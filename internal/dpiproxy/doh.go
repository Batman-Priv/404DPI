package dpiproxy

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type DoHResolver struct {
	server   string
	servers  []string
	client   *http.Client
	cache    sync.Map
	cacheLen atomic.Int64
	useCache bool

	hosts        map[string][]net.IP
	queryEnabled bool

	healthyIdx atomic.Int32
}

type dohCacheEntry struct {
	ips      []net.IP
	expires  time.Time
	negative bool
}

const maxDoHCacheEntries = 10000

func NewDoHResolver(server string, useCache, queryEnabled bool) *DoHResolver {
	var servers []string
	for _, part := range strings.Split(server, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			servers = append(servers, part)
		}
	}
	first := server
	if len(servers) > 0 {
		first = servers[0]
	}
	return &DoHResolver{
		server:       first,
		servers:      servers,
		client:       &http.Client{Timeout: 5 * time.Second},
		useCache:     useCache,
		queryEnabled: queryEnabled,
	}
}

func (d *DoHResolver) SetStaticHosts(hosts map[string][]net.IP) {
	d.hosts = hosts
}

func (d *DoHResolver) Resolve(domain string) ([]net.IP, error) {
	domain = strings.TrimSuffix(domain, ".")
	if ip := net.ParseIP(domain); ip != nil {
		return []net.IP{ip}, nil
	}

	key := strings.ToLower(domain)

	if d.hosts != nil {
		if ips, ok := d.hosts[key]; ok {
			return ips, nil
		}
	}

	if !d.queryEnabled {
		return nil, fmt.Errorf("doh: no static hosts entry for %s (live DoH queries disabled)", domain)
	}

	if d.useCache {
		if v, ok := d.cache.Load(key); ok {
			entry := v.(dohCacheEntry)
			if time.Now().Before(entry.expires) {
				if entry.negative {
					return nil, fmt.Errorf("doh: %s (cached failure)", domain)
				}
				return entry.ips, nil
			}
		}
	}

	ips, ttl, err := d.query(domain, 1)
	if err != nil || len(ips) == 0 {
		if ips6, ttl6, err6 := d.query(domain, 28); err6 == nil && len(ips6) > 0 {
			ips, ttl, err = ips6, ttl6, nil
		}
	}

	if d.useCache {
		d.storeCache(key, ips, ttl, err != nil || len(ips) == 0)
	}

	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("doh: no records for %s", domain)
	}
	return ips, nil
}

func (d *DoHResolver) storeCache(key string, ips []net.IP, ttl int, negative bool) {
	if d.cacheLen.Load() >= maxDoHCacheEntries {
		d.cache.Range(func(k, _ interface{}) bool {
			d.cache.Delete(k)
			return true
		})
		d.cacheLen.Store(0)
	}

	expiry := time.Duration(ttl) * time.Second
	if negative {
		expiry = 10 * time.Second
	} else if ttl < 30 {
		expiry = 30 * time.Second
	}

	if _, existed := d.cache.Load(key); !existed {
		d.cacheLen.Add(1)
	}
	d.cache.Store(key, dohCacheEntry{ips: ips, expires: time.Now().Add(expiry), negative: negative})
}

func (d *DoHResolver) query(domain string, qtype uint16) ([]net.IP, int, error) {
	servers := d.servers
	if len(servers) == 0 {
		servers = []string{d.server}
	}

	start := int(d.healthyIdx.Load())
	if start < 0 || start >= len(servers) {
		start = 0
	}

	var lastErr error
	for i := 0; i < len(servers); i++ {
		idx := (start + i) % len(servers)
		ips, ttl, err := d.queryOne(servers[idx], domain, qtype)
		if err == nil {
			d.healthyIdx.Store(int32(idx))
			return ips, ttl, nil
		}
		lastErr = err
	}
	return nil, 0, lastErr
}

func (d *DoHResolver) queryOne(server, domain string, qtype uint16) ([]net.IP, int, error) {
	msg := buildDNSQuery(domain, qtype)
	b64 := base64.RawURLEncoding.EncodeToString(msg)

	url := server
	if strings.Contains(url, "?") {
		url += "&dns=" + b64
	} else {
		url += "?dns=" + b64
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("doh: %s: %w", server, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, 0, fmt.Errorf("doh: HTTP %d from %s", resp.StatusCode, server)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, 0, err
	}

	return parseDNSResponse(body)
}

func buildDNSQuery(domain string, qtype uint16) []byte {
	id := uint16(randIntN(65536))
	buf := make([]byte, 0, 32+len(domain))
	buf = append(buf, byte(id>>8), byte(id))
	buf = append(buf, 0x01, 0x00)
	buf = append(buf, 0x00, 0x01)
	buf = append(buf, 0x00, 0x00)
	buf = append(buf, 0x00, 0x00)
	buf = append(buf, 0x00, 0x00)

	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			continue
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00)
	buf = append(buf, byte(qtype>>8), byte(qtype))
	buf = append(buf, 0x00, 0x01)
	return buf
}

func skipDNSName(data []byte, pos int) (int, error) {
	if pos >= len(data) {
		return 0, fmt.Errorf("dns: truncated name")
	}
	for {
		if pos >= len(data) {
			return 0, fmt.Errorf("dns: truncated name")
		}
		l := int(data[pos])
		if l == 0 {
			return pos + 1, nil
		}
		if l&0xc0 == 0xc0 {
			return pos + 2, nil
		}
		pos += 1 + l
	}
}

func parseDNSResponse(data []byte) ([]net.IP, int, error) {
	if len(data) < 12 {
		return nil, 0, fmt.Errorf("dns: short response")
	}
	qdcount := int(binary.BigEndian.Uint16(data[4:6]))
	ancount := int(binary.BigEndian.Uint16(data[6:8]))

	pos := 12
	for i := 0; i < qdcount; i++ {
		var err error
		pos, err = skipDNSName(data, pos)
		if err != nil {
			return nil, 0, err
		}
		pos += 4
	}

	var ips []net.IP
	minTTL := -1

	for i := 0; i < ancount; i++ {
		var err error
		pos, err = skipDNSName(data, pos)
		if err != nil {
			return nil, 0, err
		}
		if pos+10 > len(data) {
			return nil, 0, fmt.Errorf("dns: truncated record")
		}
		rtype := binary.BigEndian.Uint16(data[pos : pos+2])
		ttl := int(binary.BigEndian.Uint32(data[pos+4 : pos+8]))
		rdlen := int(binary.BigEndian.Uint16(data[pos+8 : pos+10]))
		pos += 10
		if pos+rdlen > len(data) {
			return nil, 0, fmt.Errorf("dns: truncated rdata")
		}
		rdata := data[pos : pos+rdlen]
		pos += rdlen

		if minTTL == -1 || ttl < minTTL {
			minTTL = ttl
		}

		switch rtype {
		case 1:
			if len(rdata) == 4 {
				ips = append(ips, net.IP(append([]byte{}, rdata...)))
			}
		case 28:
			if len(rdata) == 16 {
				ips = append(ips, net.IP(append([]byte{}, rdata...)))
			}
		}
	}
	if minTTL < 0 {
		minTTL = 60
	}
	return ips, minTTL, nil
}

func parseDNSQuestion(data []byte) (domain string, qtype uint16, end int, err error) {
	pos := 12
	var labels []string
	for {
		if pos >= len(data) {
			return "", 0, 0, fmt.Errorf("dns: truncated question")
		}
		l := int(data[pos])
		if l == 0 {
			pos++
			break
		}
		if l&0xc0 == 0xc0 {
			return "", 0, 0, fmt.Errorf("dns: compressed question not supported")
		}
		if pos+1+l > len(data) {
			return "", 0, 0, fmt.Errorf("dns: bad label")
		}
		labels = append(labels, string(data[pos+1:pos+1+l]))
		pos += 1 + l
	}
	if pos+4 > len(data) {
		return "", 0, 0, fmt.Errorf("dns: truncated qtype/qclass")
	}
	qtype = binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 4
	return strings.Join(labels, "."), qtype, pos, nil
}

func buildDNSAnswerResponse(id []byte, question []byte, qtype uint16, ips []net.IP) []byte {
	resp := make([]byte, 0, 32+len(question)+len(ips)*16)
	resp = append(resp, id...)
	resp = append(resp, 0x81, 0x80)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, byte(len(ips)>>8), byte(len(ips)))
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, question...)

	for _, ip := range ips {
		resp = append(resp, 0xc0, 0x0c)
		resp = append(resp, byte(qtype>>8), byte(qtype))
		resp = append(resp, 0x00, 0x01)
		resp = append(resp, 0x00, 0x00, 0x00, 0x3c)
		if qtype == 28 {
			ip16 := ip.To16()
			resp = append(resp, 0x00, 0x10)
			resp = append(resp, ip16...)
		} else {
			ip4 := ip.To4()
			resp = append(resp, 0x00, 0x04)
			resp = append(resp, ip4...)
		}
	}
	return resp
}

func buildDNSErrorResponse(id []byte, question []byte, rcode byte) []byte {
	resp := make([]byte, 0, 16+len(question))
	resp = append(resp, id...)
	resp = append(resp, 0x81, 0x80|rcode)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, 0x00, 0x00)
	resp = append(resp, question...)
	return resp
}

func loadHostsFile(path string) (map[string][]net.IP, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	hosts := map[string][]net.IP{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := net.ParseIP(fields[0])
		if ip == nil {
			continue
		}
		for _, domain := range fields[1:] {
			key := strings.ToLower(domain)
			hosts[key] = append(hosts[key], ip)
		}
	}
	return hosts, nil
}
