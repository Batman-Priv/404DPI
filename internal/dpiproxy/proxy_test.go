package dpiproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startProxy(t *testing.T, mod func(*Config), bl BlacklistManager) (*ProxyServer, *Config, *Statistics) {
	t.Helper()
	cfg := defaultConfig()
	cfg.Port = freePort(t)
	cfg.Quiet = true
	cfg.StrategyCacheFile = ""
	cfg.Timeout = 5
	if mod != nil {
		mod(cfg)
	}
	if bl == nil {
		bl = &NoBlacklist{}
	}
	stats := &Statistics{}
	ps := NewProxyServer(cfg, stats, bl)
	go ps.Start()
	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Port)
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Cleanup(ps.Stop)
	return ps, cfg, stats
}

func clientVia(cfg *Config, user, pass string) *http.Client {
	pu := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", cfg.Port)}
	if user != "" {
		pu.User = url.UserPassword(user, pass)
	}
	return &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{
		Proxy:             http.ProxyURL(pu),
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}}
}

func tlsBackend(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("hello ", 2000))
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return srv, port
}

func TestFragmentationKeepsTLSWorking(t *testing.T) {
	_, port := tlsBackend(t)
	for _, method := range []string{"sni", "natural", "random", "multi", "none"} {
		for _, adaptive := range []bool{false, true} {
			method, adaptive := method, adaptive
			t.Run(fmt.Sprintf("%s/adaptive=%v", method, adaptive), func(t *testing.T) {
				_, cfg, _ := startProxy(t, func(c *Config) { c.FragmentMethod = method; c.Adaptive = adaptive }, nil)

				resp, err := clientVia(cfg, "", "").Get("https://localhost:" + port + "/")
				if err != nil {
					t.Fatalf("request failed: %v", err)
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != 200 || len(body) != len("hello ")*2000 {
					t.Fatalf("unexpected response: %d, %d bytes", resp.StatusCode, len(body))
				}
			})
		}
	}
}

func TestFragmentsReassembleToOriginalClientHello(t *testing.T) {
	raw := buildProbeClientHello("www.example.com")
	for _, method := range []string{"sni", "natural", "random", "multi", "none"} {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/after=%v", method, after), func(t *testing.T) {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				got := make(chan []byte, 1)
				go func() {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					defer c.Close()
					data, _ := io.ReadAll(c)
					got <- data
				}()

				cfg := defaultConfig()
				cfg.Quiet = true
				cfg.FragmentDelay = 0
				s := NewProxyServer(cfg, &Statistics{}, &NoBlacklist{})
				conn, err := net.Dial("tcp", ln.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				s.sendFragmented(conn, chParseResult{clientHello: raw, version: [2]byte{3, 1}},
					FragmentStrategy{Name: method, Method: method, SplitAfterSNI: after})
				conn.Close()

				var payload []byte
				data := <-got
				for len(data) >= 5 {
					if data[0] != 0x16 {
						t.Fatalf("unexpected record type %#x", data[0])
					}
					n := int(data[3])<<8 | int(data[4])
					if len(data) < 5+n {
						t.Fatal("truncated record")
					}
					payload = append(payload, data[5:5+n]...)
					data = data[5+n:]
				}
				if !bytes.Equal(payload, raw) {
					t.Fatal("reassembled fragments differ from the original ClientHello")
				}
			})
		}
	}
}

func TestBlacklistListsDestinationsThatNeedBypass(t *testing.T) {
	_, port := tlsBackend(t)
	list := filepath.Join(t.TempDir(), "blacklist.txt")
	if err := os.WriteFile(list, []byte("# needs bypass\nlocalhost\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg0 := defaultConfig()
	cfg0.BlacklistFile = list
	bl, err := NewFileBlacklist(cfg0)
	if err != nil {
		t.Fatal(err)
	}
	_, cfg, stats := startProxy(t, nil, bl)
	cl := clientVia(cfg, "", "")

	for _, host := range []string{"localhost", "127.0.0.1"} {
		resp, err := cl.Get("https://" + host + ":" + port + "/")
		if err != nil {
			t.Fatalf("%s: listed or not, the request must go through (no 403): %v", host, err)
		}
		resp.Body.Close()
	}
	if b, d := stats.bypassedConns.Load(), stats.directConns.Load(); b != 1 || d != 1 {
		t.Fatalf("bypassed=%d direct=%d, want 1 and 1", b, d)
	}
}

func TestPlainHTTPProxy(t *testing.T) {
	var sawProxyAuth, sawProxyConn string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawProxyAuth = r.Header.Get("Proxy-Authorization")
		sawProxyConn = r.Header.Get("Proxy-Connection")
		switch r.URL.Path {
		case "/204":
			w.WriteHeader(http.StatusNoContent)
		case "/304":
			w.WriteHeader(http.StatusNotModified)
		default:
			fmt.Fprint(w, "plain body")
		}
	}))
	defer backend.Close()

	_, cfg, stats := startProxy(t, func(c *Config) { c.Username = "u"; c.Password = "p" }, nil)
	cl := clientVia(cfg, "u", "p")

	resp, err := cl.Get(backend.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "plain body" {
		t.Fatalf("body = %q", body)
	}
	if sawProxyAuth != "" || sawProxyConn != "" {
		t.Fatalf("proxy-only headers leaked to the origin: Proxy-Authorization=%q Proxy-Connection=%q", sawProxyAuth, sawProxyConn)
	}

	ka := clientVia(cfg, "u", "p")
	ka.Transport.(*http.Transport).DisableKeepAlives = false
	for path, want := range map[string]int{"/204": 204, "/304": 304} {
		start := time.Now()
		resp, err := ka.Get(backend.URL + path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("%s: status %d", path, resp.StatusCode)
		}
		resp, err = ka.Get(backend.URL + "/")
		if err != nil {
			t.Fatalf("request after %s: %v", path, err)
		}
		resp.Body.Close()
		if time.Since(start) > 2*time.Second {
			t.Fatalf("%s: proxy stalled for %v", path, time.Since(start))
		}
	}
	if stats.trafficIn.Load() == 0 {
		t.Fatal("download counter stayed at zero for plain HTTP")
	}

	if resp, err := clientVia(cfg, "u", "wrong").Get(backend.URL + "/"); err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("wrong password: status %d, want 407", resp.StatusCode)
		}
	}
}

func TestTrafficCountersBothDirections(t *testing.T) {
	_, port := tlsBackend(t)
	_, cfg, stats := startProxy(t, nil, nil)
	resp, err := clientVia(cfg, "", "").Get("https://localhost:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	deadline := time.Now().Add(2 * time.Second)
	for stats.trafficIn.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if stats.trafficIn.Load() < 12000 {
		t.Fatalf("download counter = %d, want >= the 12000-byte body", stats.trafficIn.Load())
	}
	if stats.trafficOut.Load() == 0 {
		t.Fatal("upload counter stayed at zero")
	}
}

func TestStopDoesNotHangOnOpenTunnels(t *testing.T) {
	_, port := tlsBackend(t)
	ps, cfg, _ := startProxy(t, func(c *Config) { c.Timeout = 60 }, nil)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.Port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT 127.0.0.1:%s HTTP/1.1\r\nHost: x\r\n\r\n", port)
	br := bufio.NewReader(conn)
	if line, err := br.ReadString('\n'); err != nil || !strings.Contains(line, "200") {
		t.Fatalf("CONNECT failed: %q %v", line, err)
	}

	done := make(chan struct{})
	go func() { ps.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("Stop() hung on an idle tunnel")
	}
}

func TestStrategyRecordSemantics(t *testing.T) {
	sni := FragmentStrategy{Name: "sni"}
	nat := FragmentStrategy{Name: "natural"}
	r := newStrategyRecord(sni)

	r.record(sni, false)
	r.record(nat, false)
	if got := r.snapshot(); got.Attempts != 1 || got.Successes != 0 {
		t.Fatalf("after failures: %+v", got)
	}
	r.record(nat, true)
	got := r.snapshot()
	if got.Strategy.Name != "natural" || got.Attempts != 1 || got.Successes != 1 {
		t.Fatalf("after switching: %+v", got)
	}
	if r.Confidence() != 1 {
		t.Fatalf("confidence = %v", r.Confidence())
	}
}

func TestParseHTTPRequestStripsProxyHeaders(t *testing.T) {
	s := NewProxyServer(defaultConfig(), &Statistics{}, &NoBlacklist{})
	raw := "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic eDp5\r\nProxy-Connection: keep-alive\r\nAccept: */*\r\n\r\n"
	req, err := s.parseHTTPRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if req.Headers["proxy-authorization"] == "" {
		t.Fatal("the proxy still needs to see Proxy-Authorization to check it")
	}
	out := string(req.Raw)
	if strings.Contains(strings.ToLower(out), "proxy-") || !strings.Contains(out, "Accept: */*") || !strings.HasSuffix(out, "\r\n\r\n") {
		t.Fatalf("forwarded request is wrong:\n%q", out)
	}
}

func TestQUICCryptoFrameBounds(t *testing.T) {
	frame := []byte{0x06, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00}
	if sni := extractSNIFromQUICFrames(frame); sni != "" {
		t.Fatalf("got %q", sni)
	}
}

func TestStatsLabels(t *testing.T) {
	var s Statistics
	s.IncrementBypassed()
	s.IncrementDirect()
	s.UpdateTraffic(2048, 10)
	out := s.GetStats()
	for _, want := range []string{"Bypassed: 1", "Direct: 1", "DL: 2.0 KB", "UL: 10 B"} {
		if !strings.Contains(out, want) {
			t.Fatalf("%q missing from %q", want, out)
		}
	}
}

func TestEscalationKeepsExplicitNone(t *testing.T) {
	cfg := defaultConfig()
	cfg.FragmentMethod = "none"
	s := NewProxyServer(cfg, &Statistics{}, &NoBlacklist{})
	if l := s.defaultEscalation("example.com"); l[0].Method != "none" {
		t.Fatalf("first strategy = %q, want none", l[0].Method)
	}
}
