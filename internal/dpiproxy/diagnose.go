package dpiproxy

import (
	crand "crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

var defaultScanDomains = []string{
	"www.google.com",
	"www.youtube.com",
	"www.instagram.com",
	"www.wikipedia.org",
	"x.com",
}

type ProbeResult struct {
	OK      bool
	Elapsed time.Duration
	Detail  string
}

type DomainDiagnosis struct {
	Domain           string
	SystemDNS        []net.IP
	DoHDNS           []net.IP
	DNSMismatch      bool
	TCPDirect        ProbeResult
	TLSDirect        ProbeResult
	TLSFragmentedSNI ProbeResult
	TLSFakeSNI       ProbeResult
	LikelyDPI        bool
	Unreachable      bool
	Method           string
	Suggestion       string
}

func runDiagnostics(config *Config) {
	domains := config.ScanDomains
	if len(domains) == 0 {
		domains = defaultScanDomains
	}

	doh := NewDoHResolver(config.DoHServer, false, true)

	fmt.Println("=== DPI / network filtering diagnosis ===")
	fmt.Printf("DoH server used for comparison: %s\n\n", config.DoHServer)

	var anyDPI, anyDNSIssue, anyUnreachable bool
	for _, domain := range domains {
		fmt.Printf("--- %s ---\n", domain)
		d := scanDomain(domain, doh)
		printDomainDiagnosis(d)
		if d.LikelyDPI {
			anyDPI = true
		}
		if d.DNSMismatch {
			anyDNSIssue = true
		}
		if d.Unreachable {
			anyUnreachable = true
		}
		fmt.Println()
	}

	fmt.Println("=== Summary ===")
	switch {
	case anyDPI && anyDNSIssue:
		fmt.Println("Signs of both DPI (SNI-based blocking) and a mismatch between local DNS and DoH were detected.")
		fmt.Println("Suggestion: use -doh together with -adaptive (enabled by default).")
	case anyDPI:
		fmt.Println("Signs of SNI/DPI-based blocking were detected on at least one domain.")
		fmt.Println("Suggestion: -adaptive (enabled by default); if that does not help, try -fragment-method natural or -race-strategies and measure with -benchmark.")
	case anyUnreachable:
		fmt.Println("A TCP connection could not be established to some domains at all (IP/port-level block or network outage).")
		fmt.Println("Splitting the SNI alone will not help here; you need an upstream proxy/tunnel (-out-host).")
	case anyDNSIssue:
		fmt.Println("The local DNS answer differed from DoH (possible DNS hijack/poisoning), but the TLS connection itself worked fine.")
		fmt.Println("Suggestion: -doh alone is enough; there is no need for heavy fragmentation.")
	default:
		fmt.Println("No clear sign of active filtering was found on these specific domains.")
		fmt.Println("(The current network may be unrestricted, or these domains may not be filtered - try other domains with -scan-domains.)")
	}
}

func scanDomain(domain string, doh *DoHResolver) DomainDiagnosis {
	d := DomainDiagnosis{Domain: domain}
	const timeout = 5 * time.Second

	sysIPs, _ := net.LookupIP(domain)
	var dohIPs []net.IP
	if doh != nil {
		dohIPs, _ = doh.Resolve(domain)
	}
	d.SystemDNS, d.DoHDNS = sysIPs, dohIPs
	if len(sysIPs) > 0 && len(dohIPs) > 0 {
		d.DNSMismatch = !ipSetsOverlap(sysIPs, dohIPs)
	}

	ip := domain
	if len(sysIPs) > 0 {
		ip = sysIPs[0].String()
	} else if len(dohIPs) > 0 {
		ip = dohIPs[0].String()
	}

	d.TCPDirect = probeTCP(net.JoinHostPort(ip, "443"), timeout)
	if !d.TCPDirect.OK {
		d.Unreachable = true
		d.Method = "TCP could not connect to the destination at all (IP/port-level block or network outage)"
		if d.DNSMismatch {
			d.Method += " + local DNS answer differs from DoH"
			d.Suggestion = "Use -doh so the correct IP is resolved."
		} else {
			d.Suggestion = "If the IP is correct, you need an upstream proxy/tunnel (-out-host)."
		}
		return d
	}

	d.TLSDirect = probeTLSStdlib(ip, domain, timeout)
	if d.TLSDirect.OK {
		d.Method = "This domain does not appear to be blocked in this test"
		if d.DNSMismatch {
			d.Method += ", but the local DNS answer differs from DoH (possibly a harmless hijack or CDN routing)"
			d.Suggestion = "If you see odd behavior, try -doh."
		}
		return d
	}

	d.TLSFragmentedSNI = probeFragmentedTLS(ip, domain, timeout, false, 0, nil)
	if d.TLSFragmentedSNI.OK {
		d.LikelyDPI = true
		d.Method = "SNI-based DPI (splitting the ClientHello fixed it)"
		d.Suggestion = "fragment-method=sni is enough (the default; adaptive is also on by default)."
		return d
	}

	d.TLSFakeSNI = probeTLSStdlib(ip, "www.example.com", timeout)
	if d.TLSFakeSNI.OK {
		d.LikelyDPI = true
		d.Method = "DPI with stronger detection (only fully replacing the SNI worked)"
		d.Suggestion = "Splitting the ClientHello did not work; swapping the SNI inside the proxy would also break the application's handshake. You need an upstream proxy/tunnel (-out-host) or ECH."
		return d
	}

	d.LikelyDPI = true
	d.Method = "Strong blocking: neither simple fragmentation nor SNI replacement alone worked"
	d.Suggestion = "Likely an IP block or DPI with full stream reassembly. Try -fragment-method natural and -race-strategies; if that does not help, you need an upstream proxy/tunnel (-out-host)."
	return d
}

func printDomainDiagnosis(d DomainDiagnosis) {
	if len(d.SystemDNS) > 0 {
		fmt.Printf("  Local DNS: %s\n", formatIPs(d.SystemDNS))
	}
	if len(d.DoHDNS) > 0 {
		fmt.Printf("  DNS via DoH: %s%s\n", formatIPs(d.DoHDNS), map[bool]string{true: "  ⚠ differs from local DNS", false: ""}[d.DNSMismatch])
	}
	fmt.Printf("  Direct TCP:443 connection: %s\n", formatProbe(d.TCPDirect))
	if d.TCPDirect.OK {
		fmt.Printf("  Direct TLS handshake (real SNI): %s\n", formatProbe(d.TLSDirect))
	}
	if !d.TLSDirect.OK && d.TCPDirect.OK {
		fmt.Printf("  TLS with fragmented SNI: %s\n", formatProbe(d.TLSFragmentedSNI))
	}
	if !d.TLSFragmentedSNI.OK && d.TCPDirect.OK && !d.TLSDirect.OK {
		fmt.Printf("  TLS with fake SNI: %s\n", formatProbe(d.TLSFakeSNI))
	}
	if d.Method != "" {
		fmt.Printf("  Result: %s\n", d.Method)
	}
	if d.Suggestion != "" {
		fmt.Printf("  Suggestion: %s\n", d.Suggestion)
	}
}

func formatProbe(p ProbeResult) string {
	status := "failed"
	if p.OK {
		status = "succeeded"
	}
	if p.Detail != "" {
		return fmt.Sprintf("%s (%s, %v)", status, p.Detail, p.Elapsed.Round(time.Millisecond))
	}
	return fmt.Sprintf("%s (%v)", status, p.Elapsed.Round(time.Millisecond))
}

func formatIPs(ips []net.IP) string {
	parts := make([]string, 0, len(ips))
	for i, ip := range ips {
		if i >= 3 {
			parts = append(parts, "...")
			break
		}
		parts = append(parts, ip.String())
	}
	return strings.Join(parts, ", ")
}

func ipSetsOverlap(a, b []net.IP) bool {
	for _, x := range a {
		for _, y := range b {
			if x.Equal(y) {
				return true
			}
		}
	}
	return false
}

func probeTCP(addr string, timeout time.Duration) ProbeResult {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	elapsed := time.Since(start)
	if err != nil {
		return ProbeResult{OK: false, Elapsed: elapsed, Detail: classifyDialError(err, elapsed, timeout)}
	}
	conn.Close()
	return ProbeResult{OK: true, Elapsed: elapsed}
}

func probeTLSStdlib(ip, sni string, timeout time.Duration) ProbeResult {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), timeout)
	if err != nil {
		return ProbeResult{OK: false, Elapsed: time.Since(start), Detail: classifyDialError(err, time.Since(start), timeout)}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	tc := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	err = tc.Handshake()
	elapsed := time.Since(start)
	if err != nil {
		return ProbeResult{OK: false, Elapsed: elapsed, Detail: classifyDialError(err, elapsed, timeout)}
	}
	return ProbeResult{OK: true, Elapsed: elapsed}
}

func probeFragmentedTLS(ip, sni string, timeout time.Duration, useFakePacket bool, fakeTTL int, pool []string) ProbeResult {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), timeout)
	if err != nil {
		return ProbeResult{OK: false, Elapsed: time.Since(start), Detail: classifyDialError(err, time.Since(start), timeout)}
	}
	defer conn.Close()
	setNoDelay(conn)

	version := [2]byte{0x03, 0x03}
	chRaw := buildProbeClientHello(sni)

	if useFakePacket {
		sendFakeClientHellos(conn, version, &Config{FakePacketTTL: fakeTTL, FakePacketCount: 1, FakeSNIPool: pool, FakeMethod: "ttl"})
	}

	ch, err := parseClientHello(chRaw)
	if err != nil {
		return ProbeResult{OK: false, Detail: "internal: could not build probe ClientHello"}
	}
	full, sniOffset, sniLen, _ := serializeClientHello(ch)
	chunks := splitForProbe(full, sniOffset, sniLen)

	for _, chunk := range chunks {
		record := buildTLSRecord(version, chunk)
		conn.SetWriteDeadline(time.Now().Add(timeout))
		if _, err := conn.Write(record); err != nil {
			return ProbeResult{OK: false, Elapsed: time.Since(start), Detail: classifyDialError(err, time.Since(start), timeout)}
		}
		time.Sleep(3 * time.Millisecond)
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, rerr := conn.Read(buf)
	elapsed := time.Since(start)
	if rerr != nil || n == 0 || !looksLikeHandshake(buf[:n]) {
		return ProbeResult{OK: false, Elapsed: elapsed, Detail: classifyDialError(rerr, elapsed, timeout)}
	}
	return ProbeResult{OK: true, Elapsed: elapsed}
}

func classifyDialError(err error, elapsed, timeout time.Duration) string {
	if err == nil {
		return "no response"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "refused"):
		return "connection refused - immediate rejection, likely an active IP block"
	case strings.Contains(msg, "reset"):
		return "connection reset - RST, likely active blocking (DPI/firewall)"
	case elapsed >= timeout-100*time.Millisecond:
		return "timeout - black hole, packets are silently dropped"
	default:
		return msg
	}
}

func buildTLSRecord(version [2]byte, data []byte) []byte {
	record := make([]byte, 5+len(data))
	record[0] = 0x16
	record[1] = version[0]
	record[2] = version[1]
	record[3] = byte(len(data) >> 8)
	record[4] = byte(len(data))
	copy(record[5:], data)
	return record
}

func splitForProbe(data []byte, sniOffset, sniLen int) [][]byte {
	if sniOffset <= 0 || sniLen <= 0 || sniOffset+sniLen > len(data) {
		return [][]byte{data}
	}
	chunks := [][]byte{data[:sniOffset]}
	rest := data[sniOffset:]
	for len(rest) > 0 {
		n := 8 + randIntN(8)
		if n > len(rest) {
			n = len(rest)
		}
		chunks = append(chunks, rest[:n])
		rest = rest[n:]
	}
	return chunks
}

func buildProbeClientHello(sni string) []byte {
	var random [32]byte
	if _, err := crand.Read(random[:]); err != nil {
		for i := range random {
			random[i] = byte(randIntN(256))
		}
	}

	ch := &clientHelloMsg{
		Version: [2]byte{0x03, 0x03},
		Random:  random,
		CipherSuites: []byte{
			0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
			0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30,
			0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35,
		},
		CompressionMethods: []byte{0x00},
		Extensions: []tlsExtension{
			{Type: 0, Data: buildServerNameExtensionData(sni)},
			{Type: 10, Data: []byte{0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19}},
			{Type: 11, Data: []byte{0x01, 0x00}},
			{Type: 13, Data: []byte{0x00, 0x0a, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03, 0x08, 0x04}},
			{Type: 43, Data: []byte{0x04, 0x03, 0x04, 0x03, 0x03}},
		},
	}

	full, _, _, _ := serializeClientHello(ch)
	return full
}
