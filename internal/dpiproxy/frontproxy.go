package dpiproxy

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type frontCA struct {
	cert      *x509.Certificate
	key       *ecdsa.PrivateKey
	certPEM   []byte
	permitted []string

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func randSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return n
}

func loadOrCreateFrontCA(dir string, domains []string) (*frontCA, string, error) {
	permitted := sortedUnique(domains)
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	if cb, err := os.ReadFile(certPath); err == nil {
		if kb, err := os.ReadFile(keyPath); err == nil {
			if ca, err := parseFrontCA(cb, kb); err == nil &&
				sameStrings(sortedUnique(ca.cert.PermittedDNSDomains), permitted) &&
				time.Until(ca.cert.NotAfter) > 30*24*time.Hour {
				return ca, certPath, nil
			}
			log.Printf("[INFO] domain fronting: the CA in %s doesn't match the current -front-map (or is about to expire); creating a new one - import it again", dir)
		}
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:                randSerial(),
		Subject:                     pkix.Name{CommonName: "404DPI local domain-fronting CA", Organization: []string{"404DPI"}},
		NotBefore:                   time.Now().Add(-time.Hour),
		NotAfter:                    time.Now().AddDate(5, 0, 0),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         permitted,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, "", err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, "", err
	}
	cb := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	if err := writeFileAtomic(keyPath, kb, 0600); err != nil {
		return nil, "", err
	}
	if err := writeFileAtomic(certPath, cb, 0644); err != nil {
		return nil, "", err
	}
	ca, err := parseFrontCA(cb, kb)
	return ca, certPath, err
}

func parseFrontCA(certPEM, keyPEM []byte) (*frontCA, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, fmt.Errorf("invalid PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &frontCA{cert: cert, key: key, certPEM: certPEM, permitted: sortedUnique(cert.PermittedDNSDomains), leaves: map[string]*tls.Certificate{}}, nil
}

func (ca *frontCA) allows(host string) bool {
	host = strings.ToLower(host)
	for _, p := range ca.permitted {
		if host == p || strings.HasSuffix(host, "."+p) {
			return true
		}
	}
	return false
}

func (ca *frontCA) leafFor(host string) (*tls.Certificate, error) {
	host = strings.ToLower(host)
	if !ca.allows(host) {
		return nil, fmt.Errorf("%q is not covered by the domain-fronting CA", host)
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c, ok := ca.leaves[host]; ok && time.Until(c.Leaf.NotAfter) > time.Hour {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(7 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key, Leaf: leaf}
	ca.leaves[host] = c
	return c, nil
}

func (s *ProxyServer) initFront() error {
	if len(s.config.FrontMap) == 0 {
		return nil
	}
	s.frontOnce.Do(func() {
		var domains []string
		for real := range s.config.FrontMap {
			domains = append(domains, real)
		}
		var path string
		s.frontCA, path, s.frontErr = loadOrCreateFrontCA(s.config.FrontCADir, domains)
		if s.frontErr != nil {
			return
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if f := s.config.FrontUpstreamCA; f != "" {
			pemData, err := os.ReadFile(f)
			if err != nil {
				s.frontErr = fmt.Errorf("-front-upstream-ca: %w", err)
				return
			}
			if !pool.AppendCertsFromPEM(pemData) {
				s.frontErr = fmt.Errorf("-front-upstream-ca: no certificates found in %s", f)
				return
			}
		}
		s.frontRoots = pool
		log.Printf("[INFO] domain fronting for %d domain(s). Import this local CA into your browser/OS trust store: %s "+
			"(name-constrained to: %s)", len(s.config.FrontMap), path, strings.Join(s.frontCA.permitted, ", "))
	})
	return s.frontErr
}

type readerConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }

type fragConn struct {
	net.Conn
	s    *ProxyServer
	host string
	done bool
}

func (f *fragConn) Write(p []byte) (int, error) {
	if f.done || len(p) <= 5 || p[0] != 0x16 {
		return f.Conn.Write(p)
	}
	f.done = true
	if recLen := int(p[3])<<8 | int(p[4]); recLen+5 != len(p) || p[5] != 0x01 {
		return f.Conn.Write(p)
	}
	version := [2]byte{p[1], p[2]}
	if f.s.config.FakePacket {
		sendFakeClientHellos(f.Conn, version, f.s.config)
	}
	method, _, _, _, _, splitAfter := f.s.config.resolvedFragmentSettings(f.host)
	if method == "" || method == "none" {
		return f.Conn.Write(p)
	}
	f.s.sendFragmented(f.Conn, chParseResult{clientHello: p[5:], version: version},
		FragmentStrategy{Name: method, Method: method, SplitAfterSNI: splitAfter, Raw: true})
	return len(p), nil
}

func (s *ProxyServer) serveFronted(client net.Conn, reader *bufio.Reader, host string, port int, front string) {
	if err := s.initFront(); err != nil {
		s.stats.IncrementError()
		if s.errorLog != nil {
			s.errorLog.Printf("domain fronting unavailable: %v", err)
		}
		return
	}
	timeout := time.Duration(s.config.Timeout) * time.Second

	srv := tls.Server(&readerConn{Conn: client, r: reader}, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := chi.ServerName
			if name == "" {
				name = host
			}
			return s.frontCA.leafFor(name)
		},
	})
	if timeout > 0 {
		client.SetDeadline(time.Now().Add(timeout))
	}
	if err := srv.Handshake(); err != nil {
		s.stats.IncrementError()
		if s.errorLog != nil {
			s.errorLog.Printf("fronting: client handshake for %s failed (is the local CA imported?): %v", domainToken(s.config, host), err)
		}
		return
	}
	client.SetDeadline(time.Time{})
	defer srv.Close()

	raw, err := s.dialTarget(front, port)
	if err != nil {
		s.stats.IncrementError()
		if s.errorLog != nil {
			s.errorLog.Printf("fronting: dial %s failed: %v", domainToken(s.config, front), err)
		}
		return
	}
	setNoDelay(raw)
	up := tls.Client(&fragConn{Conn: raw, s: s, host: host}, &tls.Config{
		ServerName: front,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		RootCAs:    s.frontRoots,
	})
	if timeout > 0 {
		raw.SetDeadline(time.Now().Add(timeout))
	}
	if err := up.Handshake(); err != nil {
		raw.Close()
		s.stats.IncrementError()
		if s.errorLog != nil {
			s.errorLog.Printf("fronting: handshake with front %s failed: %v", domainToken(s.config, front), err)
		}
		return
	}
	raw.SetDeadline(time.Time{})
	defer up.Close()

	done := make(chan struct{}, 2)
	pump := func(dst, src *tls.Conn, add func(uint64)) {
		var r io.Reader = src
		var w io.Writer = dst
		if timeout > 0 {
			r = &deadlineReader{r: src, conn: src, timeout: timeout}
			w = &deadlineWriter{w: dst, conn: dst, timeout: timeout}
		}
		io.Copy(&countWriter{w: w, add: add}, r)
		dst.CloseWrite()
		done <- struct{}{}
	}
	go pump(up, srv, func(n uint64) { s.stats.UpdateTraffic(0, n) })
	go pump(srv, up, func(n uint64) { s.stats.UpdateTraffic(n, 0) })
	<-done
	<-done
}
