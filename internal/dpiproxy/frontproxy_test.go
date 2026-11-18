package dpiproxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestFrontCAConstraintsAndLeaf(t *testing.T) {
	dir := t.TempDir()
	ca, _, err := loadOrCreateFrontCA(dir, []string{"real.test", "Other.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.leafFor("evil.test"); err == nil {
		t.Fatal("leaf issued outside constraints")
	}
	leaf, err := ca.leafFor("www.real.test")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "www.real.test"}); err != nil {
		t.Fatalf("leaf does not verify: %v", err)
	}

	ca2, _, _ := loadOrCreateFrontCA(dir, []string{"other.test", "real.test"})
	if ca2.cert.SerialNumber.Cmp(ca.cert.SerialNumber) != 0 {
		t.Fatal("CA should have been reused")
	}
	ca3, _, _ := loadOrCreateFrontCA(dir, []string{"real.test"})
	if ca3.cert.SerialNumber.Cmp(ca.cert.SerialNumber) == 0 {
		t.Fatal("CA should have been regenerated")
	}
}

func TestDomainFrontingEndToEnd(t *testing.T) {
	var mu sync.Mutex
	var sni, host string
	bca, bcaPath, err := loadOrCreateFrontCA(t.TempDir(), []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	bleaf, err := bca.leafFor("localhost")
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		host = r.Host
		mu.Unlock()
		fmt.Fprint(w, "fronted-ok")
	}))
	backend.TLS = &tls.Config{
		Certificates: []tls.Certificate{*bleaf},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			sni = chi.ServerName
			mu.Unlock()
			return nil, nil
		}}
	backend.StartTLS()
	defer backend.Close()
	_, port, _ := net.SplitHostPort(backend.Listener.Addr().String())
	up := bcaPath

	caDir := t.TempDir()
	ps, cfg, _ := startProxy(t, func(c *Config) {
		c.FrontMapRaw = "real.test=localhost"
		c.FrontMap = parseFrontMap(c.FrontMapRaw)
		c.FrontCADir = caDir
		c.FrontUpstreamCA = up
	}, nil)
	_ = ps

	caPEM := func() []byte {
		b, _ := os.ReadFile(filepath.Join(caDir, "ca.pem"))
		return b
	}
	if err := ps.initFront(); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM()) {
		t.Fatal("no CA written")
	}
	c := clientVia(cfg, "", "")
	c.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: pool}
	resp, err := c.Get("https://real.test:" + port + "/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "fronted-ok" {
		t.Fatalf("body %q", body)
	}
	mu.Lock()
	defer mu.Unlock()
	if sni != "localhost" || !strings.HasPrefix(host, "real.test") {
		t.Fatalf("front saw SNI=%q Host=%q", sni, host)
	}
}
