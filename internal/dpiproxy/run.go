package dpiproxy

import (
	"bufio"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Statistics struct {
	totalConns    atomic.Uint64
	directConns   atomic.Uint64
	bypassedConns atomic.Uint64
	errorConns    atomic.Uint64
	trafficIn     atomic.Uint64
	trafficOut    atomic.Uint64
	activeConns   atomic.Int64
}

func (s *Statistics) TryAcquireConn(max int) bool {
	if max <= 0 {
		s.activeConns.Add(1)
		return true
	}
	for {
		cur := s.activeConns.Load()
		if cur >= int64(max) {
			return false
		}
		if s.activeConns.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

func (s *Statistics) ReleaseConn() {
	s.activeConns.Add(-1)
}

func (s *Statistics) UpdateTraffic(in, out uint64) {
	s.trafficIn.Add(in)
	s.trafficOut.Add(out)
}

func (s *Statistics) IncrementTotal()    { s.totalConns.Add(1) }
func (s *Statistics) IncrementDirect()   { s.directConns.Add(1) }
func (s *Statistics) IncrementBypassed() { s.bypassedConns.Add(1) }
func (s *Statistics) IncrementError()    { s.errorConns.Add(1) }

func (s *Statistics) GetStats() string {
	return fmt.Sprintf(
		"Total: %d | Bypassed: %d | Direct: %d | Errors: %d | DL: %s | UL: %s",
		s.totalConns.Load(), s.bypassedConns.Load(), s.directConns.Load(),
		s.errorConns.Load(), formatBytes(s.trafficIn.Load()), formatBytes(s.trafficOut.Load()),
	)
}

type countWriter struct {
	w   io.Writer
	add func(uint64)
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		c.add(uint64(n))
	}
	return n, err
}

func waitTimeout(wg *sync.WaitGroup, d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

type BlacklistManager interface {
	IsBlocked(domain string) bool
	CheckDomain(domain string)
}

type FileBlacklist struct {
	blocked map[string]bool
	mu      sync.RWMutex
	config  *Config
}

func NewFileBlacklist(config *Config) (*FileBlacklist, error) {
	b := &FileBlacklist{
		blocked: make(map[string]bool),
		config:  config,
	}
	if err := b.load(); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *FileBlacklist) load() error {
	data, err := os.ReadFile(b.config.BlacklistFile)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if len(line) < 2 || strings.HasPrefix(line, "#") {
			continue
		}
		domain := strings.ToLower(strings.TrimPrefix(line, "www."))
		b.blocked[domain] = true
	}
	return nil
}

func (b *FileBlacklist) IsBlocked(domain string) bool {
	domain = strings.ToLower(strings.TrimPrefix(domain, "www."))
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.config.DomainMatching == "loose" {
		for blocked := range b.blocked {
			if strings.Contains(domain, blocked) {
				return true
			}
		}
		return false
	}

	if b.blocked[domain] {
		return true
	}

	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if b.blocked[parent] {
			return true
		}
	}
	return false
}

func (b *FileBlacklist) CheckDomain(domain string) {}

type AutoBlacklist struct {
	blocked    map[string]bool
	whitelist  map[string]bool
	failCount  map[string]int
	failTime   map[string]time.Time
	probing    map[string]bool
	mu         sync.RWMutex
	config     *Config
	threshold  int
	failWindow time.Duration
}

func NewAutoBlacklist(config *Config) *AutoBlacklist {
	b := &AutoBlacklist{
		blocked:    make(map[string]bool),
		whitelist:  make(map[string]bool),
		failCount:  make(map[string]int),
		failTime:   make(map[string]time.Time),
		probing:    make(map[string]bool),
		config:     config,
		threshold:  3,
		failWindow: 5 * time.Minute,
	}

	if config.BlacklistFile != "" {
		if data, err := os.ReadFile(config.BlacklistFile); err == nil {
			loaded := 0
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				b.blocked[loadNormalizedDomain(config, line)] = true
				loaded++
			}
			if loaded > 0 {
				log.Printf("[INFO] auto-blacklist: loaded %d previously-learned domain(s) from %s", loaded, config.BlacklistFile)
			}
		}
	}

	return b
}

func (b *AutoBlacklist) IsBlocked(domain string) bool {
	domain = domainToken(b.config, strings.ToLower(strings.TrimPrefix(domain, "www.")))
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.blocked[domain]
}

func (b *AutoBlacklist) CheckDomain(domain string) {
	realDomain := strings.ToLower(strings.TrimPrefix(domain, "www."))
	if realDomain == "" || net.ParseIP(realDomain) != nil {
		return
	}
	token := domainToken(b.config, realDomain)

	b.mu.Lock()
	if b.blocked[token] || b.whitelist[token] || b.probing[token] {
		b.mu.Unlock()
		return
	}
	b.probing[token] = true
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.probing, token)
		b.mu.Unlock()
	}()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(realDomain, "443"), 3*time.Second)
	if err != nil {
		b.recordFailure(token)
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         realDomain,
	})

	if err := tlsConn.Handshake(); err != nil {
		b.recordFailure(token)
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.whitelist[token] = true
	delete(b.failCount, token)
	delete(b.failTime, token)
}

func (b *AutoBlacklist) recordFailure(domain string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if lastFail, ok := b.failTime[domain]; ok {
		if time.Since(lastFail) > b.failWindow {
			b.failCount[domain] = 0
		}
	}

	b.failCount[domain]++
	b.failTime[domain] = time.Now()

	if b.failCount[domain] >= b.threshold {
		b.blocked[domain] = true
		if f, err := os.OpenFile(b.config.BlacklistFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
			f.WriteString(domain + "\n")
			f.Close()
		}
	}
}

type NoBlacklist struct{}

func (n *NoBlacklist) IsBlocked(domain string) bool { return false }
func (n *NoBlacklist) CheckDomain(domain string)    {}

type HTTPRequest struct {
	Method    string
	URL       string
	Headers   map[string]string
	Raw       []byte
	IsConnect bool
	Host      string
	Port      int
	Body      io.Reader
	Chunked   bool
}

type ProxyServer struct {
	config     *Config
	stats      *Statistics
	blacklist  BlacklistManager
	ln         net.Listener
	stopCh     chan struct{}
	wg         sync.WaitGroup
	bufPool    sync.Pool
	accessLog  *log.Logger
	accessF    *os.File
	errorLog   *log.Logger
	errorF     *os.File
	doh        *DoHResolver
	stratCache sync.Map
	stopOnce   sync.Once

	frontOnce  sync.Once
	frontCA    *frontCA
	frontRoots *x509.CertPool
	frontErr   error
}

func NewProxyServer(config *Config, stats *Statistics, blacklist BlacklistManager) *ProxyServer {
	s := &ProxyServer{
		config:    config,
		stats:     stats,
		blacklist: blacklist,
		stopCh:    make(chan struct{}),
		bufPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, config.BufferSize)
			},
		},
	}

	if config.EnableDoH {
		s.doh = NewDoHResolver(config.DoHServer, config.DoHCache, true)
	} else if config.HostsFile != "" {
		s.doh = NewDoHResolver("", false, false)
	}
	if s.doh != nil && config.HostsFile != "" {
		if hosts, err := loadHostsFile(config.HostsFile); err != nil {
			log.Printf("[WARN] could not load hosts file %s: %v", config.HostsFile, err)
		} else {
			s.doh.SetStaticHosts(hosts)
			log.Printf("[INFO] loaded %d static host entry(ies) from %s", len(hosts), config.HostsFile)
		}
	}

	s.loadStrategyCache()

	if config.LogAccess != "" {
		f, err := os.OpenFile(config.LogAccess, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			s.accessLog = log.New(f, "", log.LstdFlags)
			s.accessF = f
		}
	}
	if config.LogError != "" {
		f, err := os.OpenFile(config.LogError, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			s.errorLog = log.New(f, "", log.LstdFlags)
			s.errorF = f
		}
	}

	return s
}

func (s *ProxyServer) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.ln = ln
	if err := s.initFront(); err != nil {
		log.Printf("[WARN] domain fronting disabled: %v", err)
	}

	log.Printf("Proxy running on %s", addr)
	log.Printf("Fragment method: %s", s.config.FragmentMethod)
	log.Printf("Fragment delay: %dms", s.config.FragmentDelay)
	log.Printf("Blacklist: %s", s.getBlacklistType())
	s.config.warnUnsafeOptions()

	go s.statsDisplay()
	go s.periodicStrategySave()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return nil
			default:
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					time.Sleep(50 * time.Millisecond)
					continue
				}
				time.Sleep(200 * time.Millisecond)
				continue
			}
		}
		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *ProxyServer) getBlacklistType() string {
	switch s.blacklist.(type) {
	case *NoBlacklist:
		return "disabled"
	case *AutoBlacklist:
		return "auto"
	default:
		return "file-based"
	}
}

func (s *ProxyServer) statsDisplay() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			if !s.config.Quiet {
				fmt.Printf("\033[2J\033[H")
				fmt.Println(s.stats.GetStats())
				fmt.Printf("\n[INFO] Press Ctrl+C to stop | Method: %s | Delay: %dms\n",
					s.config.FragmentMethod, s.config.FragmentDelay)
			}
		}
	}
}

func (s *ProxyServer) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
	if s.ln != nil {
		s.ln.Close()
	}
	if !waitTimeout(&s.wg, 3*time.Second) {
		log.Printf("[INFO] %d connection(s) still open at shutdown - closing anyway", s.stats.activeConns.Load())
	}

	s.saveStrategyCache()

	if s.accessF != nil {
		s.accessF.Close()
	}
	if s.errorF != nil {
		s.errorF.Close()
	}
}

func (s *ProxyServer) needsBypass(host string) bool {
	if _, all := s.blacklist.(*NoBlacklist); all {
		return true
	}
	return s.blacklist.IsBlocked(host)
}

func shouldFragmentPort(port int) bool {
	return port == 443 || port == 8443
}

func (s *ProxyServer) handleConnection(client net.Conn) {
	defer s.wg.Done()
	defer client.Close()
	defer func() {
		if r := recover(); r != nil {
			if s.errorLog != nil {
				s.errorLog.Printf("recovered panic in connection handler: %v", r)
			}
		}
	}()

	if !s.stats.TryAcquireConn(s.config.MaxConnections) {
		s.stats.IncrementError()
		return
	}
	defer s.stats.ReleaseConn()

	reader := bufio.NewReader(client)

	for {
		if s.config.Timeout > 0 {
			client.SetReadDeadline(time.Now().Add(time.Duration(s.config.Timeout) * time.Second))
		}

		req, err := s.parseHTTPRequest(reader)
		if err != nil {
			if err != io.EOF && s.errorLog != nil {
				s.errorLog.Printf("Parse error: %v", err)
			}
			return
		}

		if !s.checkAuth(req, client) {
			return
		}

		s.stats.IncrementTotal()
		go s.blacklist.CheckDomain(req.Host)

		bypass := s.needsBypass(req.Host)
		mode := "DIRECT"
		if bypass {
			s.stats.IncrementBypassed()
			mode = "BYPASS"
		} else {
			s.stats.IncrementDirect()
		}
		if s.accessLog != nil {
			s.accessLog.Printf("%s %s %s %s", mode, client.RemoteAddr(), domainToken(s.config, req.Host), req.Method)
		}

		if req.IsConnect {
			s.handleHTTPS(client, req, reader, bypass)
			return
		}

		if !s.handlePlainHTTP(client, req, reader, bypass) {
			return
		}
	}
}

func (s *ProxyServer) parseHTTPRequest(reader *bufio.Reader) (*HTTPRequest, error) {
	firstLine, err := readLimitedLine(reader, maxRequestLineLen)
	if err != nil {
		return nil, err
	}

	parts := strings.Fields(firstLine)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid request")
	}

	req := &HTTPRequest{
		Method:  parts[0],
		URL:     parts[1],
		Headers: make(map[string]string),
		Raw:     []byte(firstLine),
	}

	headerCount := 0
	totalHeaderBytes := len(firstLine)
	for {
		line, err := readLimitedLine(reader, maxHeaderLineLen)
		if err != nil {
			return nil, err
		}
		totalHeaderBytes += len(line)
		if totalHeaderBytes > maxTotalHeaderSize {
			return nil, fmt.Errorf("total header size exceeds %d bytes", maxTotalHeaderSize)
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			req.Raw = append(req.Raw, line...)
			break
		}

		headerCount++
		if headerCount > maxHeaderCount {
			return nil, fmt.Errorf("too many headers (limit %d)", maxHeaderCount)
		}

		forward := true
		if idx := strings.Index(trimmed, ":"); idx > 0 {
			key := strings.ToLower(strings.TrimSpace(trimmed[:idx]))
			value := strings.TrimSpace(trimmed[idx+1:])
			req.Headers[key] = value

			if key == "proxy-authorization" || key == "proxy-connection" {
				forward = false
			}
		}
		if forward {
			req.Raw = append(req.Raw, line...)
		}
	}

	req.IsConnect = req.Method == "CONNECT"

	if req.IsConnect {
		host, port, err := net.SplitHostPort(req.URL)
		if err != nil {
			host = req.URL
			port = "443"
		}
		req.Host = host
		p, _ := strconv.Atoi(port)
		req.Port = p
		if req.Port == 0 {
			req.Port = 443
		}
	} else {
		hostHeader := req.Headers["host"]
		if hostHeader == "" {
			return nil, fmt.Errorf("no host header")
		}
		host, port, err := net.SplitHostPort(hostHeader)
		if err != nil {
			host = hostHeader
			port = "80"
		}
		req.Host = host
		p, _ := strconv.Atoi(port)
		req.Port = p
		if req.Port == 0 {
			req.Port = 80
		}
	}

	if te, ok := req.Headers["transfer-encoding"]; ok && strings.Contains(strings.ToLower(te), "chunked") {
		req.Chunked = true
	} else if cl, ok := req.Headers["content-length"]; ok {
		length, err := strconv.ParseInt(cl, 10, 64)
		if err == nil && length > 0 {
			req.Body = io.LimitReader(reader, length)
		}
	}

	return req, nil
}

func (s *ProxyServer) checkAuth(req *HTTPRequest, client net.Conn) bool {
	if s.config.Username == "" && s.config.Password == "" {
		return true
	}

	auth := req.Headers["proxy-authorization"]
	if auth == "" {
		s.send407(client)
		return false
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		s.send407(client)
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		s.send407(client)
		return false
	}

	creds := strings.SplitN(string(decoded), ":", 2)
	if len(creds) != 2 || !secureEqual(creds[0], s.config.Username) || !secureEqual(creds[1], s.config.Password) {
		s.send407(client)
		return false
	}

	return true
}

func secureEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *ProxyServer) send407(client net.Conn) {
	resp := "HTTP/1.1 407 Proxy Authentication Required\r\n" +
		"Proxy-Authenticate: Basic realm=\"NoDPI\"\r\n" +
		"Content-Length: 0\r\n" +
		"Connection: close\r\n\r\n"
	client.Write([]byte(resp))
}

func (s *ProxyServer) dialTarget(host string, port int) (net.Conn, error) {
	var conn net.Conn
	var err error

	if s.config.OutHost != "" {
		if s.config.OutType == "http" {
			return s.dialHTTPProxy(host, port)
		} else if s.config.OutType == "socks5" {
			return s.dialSOCKS5(host, port)
		}
		addr := fmt.Sprintf("%s:%d", s.config.OutHost, s.config.OutPort)
		conn, err = net.DialTimeout("tcp", addr, time.Duration(s.config.Timeout)*time.Second)
	} else {
		target := host
		if s.doh != nil {
			if ips, derr := s.doh.Resolve(host); derr == nil && len(ips) > 0 {
				target = ips[randIntN(len(ips))].String()
			} else if s.errorLog != nil {
				s.errorLog.Printf("DoH resolve failed for %s, falling back to local resolver: %v", domainToken(s.config, host), derr)
			}
		}
		addr := net.JoinHostPort(target, strconv.Itoa(port))
		conn, err = buildDialer(s.config, time.Duration(s.config.Timeout)*time.Second).Dial("tcp", addr)
	}

	if err != nil {
		return nil, err
	}

	s.setSocketOptions(conn)
	return conn, nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (s *ProxyServer) dialHTTPProxy(host string, port int) (net.Conn, error) {
	timeout := time.Duration(s.config.Timeout) * time.Second
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(s.config.OutHost, strconv.Itoa(s.config.OutPort)), timeout)
	if err != nil {
		return nil, err
	}
	if timeout > 0 {
		conn.SetDeadline(time.Now().Add(timeout))
	}

	target := net.JoinHostPort(host, strconv.Itoa(port))
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)

	if s.config.OutUsername != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(s.config.OutUsername + ":" + s.config.OutPassword))
		req += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}

	req += "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}

	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, err
	}

	if fields := strings.Fields(resp); len(fields) < 2 || fields[1] != "200" {
		conn.Close()
		return nil, fmt.Errorf("proxy connection failed: %s", strings.TrimSpace(resp))
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	conn.SetDeadline(time.Time{})

	s.setSocketOptions(conn)
	if reader.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: reader}, nil
	}
	return conn, nil
}

func (s *ProxyServer) dialSOCKS5(host string, port int) (net.Conn, error) {
	timeout := time.Duration(s.config.Timeout) * time.Second
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(s.config.OutHost, strconv.Itoa(s.config.OutPort)), timeout)
	if err != nil {
		return nil, err
	}
	if timeout > 0 {
		conn.SetDeadline(time.Now().Add(timeout))
	}
	fail := func(err error) (net.Conn, error) {
		conn.Close()
		return nil, err
	}

	authMethods := []byte{0x00}
	if s.config.OutUsername != "" {
		authMethods = []byte{0x00, 0x02}
	}

	if _, err := conn.Write(append([]byte{0x05, byte(len(authMethods))}, authMethods...)); err != nil {
		return fail(err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil || resp[0] != 0x05 {
		return fail(fmt.Errorf("socks5 handshake failed"))
	}
	if resp[1] == 0xFF {
		return fail(fmt.Errorf("socks5: no acceptable authentication method"))
	}

	if resp[1] == 0x02 {
		if len(s.config.OutUsername) > 255 || len(s.config.OutPassword) > 255 {
			return fail(fmt.Errorf("socks5: username/password too long"))
		}
		auth := []byte{0x01}
		auth = append(auth, byte(len(s.config.OutUsername)))
		auth = append(auth, []byte(s.config.OutUsername)...)
		auth = append(auth, byte(len(s.config.OutPassword)))
		auth = append(auth, []byte(s.config.OutPassword)...)
		if _, err := conn.Write(auth); err != nil {
			return fail(err)
		}

		resp = make([]byte, 2)
		if _, err := io.ReadFull(conn, resp); err != nil || resp[1] != 0x00 {
			return fail(fmt.Errorf("socks5 auth failed"))
		}
	}

	var req []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append([]byte{0x05, 0x01, 0x00, 0x01}, v4...)
		} else {
			req = append([]byte{0x05, 0x01, 0x00, 0x04}, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fail(fmt.Errorf("socks5: hostname too long"))
		}
		req = append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, host...)
	}
	req = append(req, byte(port>>8), byte(port&0xFF))

	if _, err := conn.Write(req); err != nil {
		return fail(err)
	}

	reader := bufio.NewReader(conn)
	reply := make([]byte, 4)
	if _, err := io.ReadFull(reader, reply); err != nil {
		return fail(err)
	}

	if reply[1] != 0x00 {
		return fail(fmt.Errorf("socks5 connection failed: %d", reply[1]))
	}

	var addrLen int
	switch reply[3] {
	case 0x01:
		addrLen = 4
	case 0x03:
		lenByte, err := reader.ReadByte()
		if err != nil {
			return fail(err)
		}
		addrLen = int(lenByte)
	case 0x04:
		addrLen = 16
	default:
		return fail(fmt.Errorf("unknown address type: %d", reply[3]))
	}

	if _, err := io.CopyN(io.Discard, reader, int64(addrLen+2)); err != nil {
		return fail(err)
	}
	conn.SetDeadline(time.Time{})

	s.setSocketOptions(conn)
	if reader.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: reader}, nil
	}
	return conn, nil
}

func copyChunked(dst io.Writer, src *bufio.Reader) error {
	for {
		line, err := src.ReadString('\n')
		if err != nil {
			return err
		}
		if _, err := dst.Write([]byte(line)); err != nil {
			return err
		}

		trimmed := strings.TrimRight(line, "\r\n")
		sizeStr := trimmed
		if semi := strings.IndexByte(trimmed, ';'); semi >= 0 {
			sizeStr = trimmed[:semi]
		}
		sizeStr = strings.TrimSpace(sizeStr)
		size, err := strconv.ParseInt(sizeStr, 16, 64)
		if err != nil {
			return err
		}

		if size == 0 {
			for {
				l, err := src.ReadString('\n')
				if err != nil {
					return err
				}
				dst.Write([]byte(l))
				if strings.TrimSpace(l) == "" {
					break
				}
			}
			return nil
		}

		if _, err := io.CopyN(dst, src, size); err != nil {
			return err
		}
		crlf := make([]byte, 2)
		if _, err := io.ReadFull(src, crlf); err != nil {
			return err
		}
		dst.Write(crlf)
	}
}

func parseStatusCode(statusLine string) int {
	fields := strings.Fields(statusLine)
	if len(fields) < 2 {
		return 0
	}
	code, _ := strconv.Atoi(fields[1])
	return code
}

func (s *ProxyServer) handlePlainHTTP(client net.Conn, req *HTTPRequest, reader *bufio.Reader, bypass bool) bool {
	remote, err := s.dialTarget(req.Host, req.Port)
	if err != nil {
		s.stats.IncrementError()
		if s.errorLog != nil {
			s.errorLog.Printf("Dial error: %v", err)
		}
		client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return false
	}
	defer remote.Close()

	timeout := time.Duration(s.config.Timeout) * time.Second
	if timeout > 0 {
		remote.SetWriteDeadline(time.Now().Add(timeout))
	}

	var writeErr error
	if bypass && s.config.HTTPObfuscate {
		writeErr = s.obfuscateAndSendHTTP(remote, req.Raw)
	} else {
		_, writeErr = remote.Write(req.Raw)
	}
	if writeErr != nil {
		s.stats.IncrementError()
		return false
	}
	s.stats.UpdateTraffic(0, uint64(len(req.Raw)))

	if req.Chunked {
		up := &countWriter{w: remote, add: func(n uint64) { s.stats.UpdateTraffic(0, n) }}
		if err := copyChunked(up, reader); err != nil {
			return false
		}
	} else if req.Body != nil {
		buf := s.bufPool.Get().([]byte)
		n, err := io.CopyBuffer(remote, req.Body, buf)
		s.bufPool.Put(buf)
		s.stats.UpdateTraffic(0, uint64(n))
		if err != nil {
			return false
		}
	}

	down := &countWriter{w: client, add: func(n uint64) { s.stats.UpdateTraffic(n, 0) }}
	respReader := bufio.NewReader(remote)

	var code int
	var respHeaders map[string]string
	for {
		if timeout > 0 {
			remote.SetReadDeadline(time.Now().Add(timeout))
		}
		statusLine, err := respReader.ReadString('\n')
		if err != nil {
			s.stats.IncrementError()
			return false
		}
		if _, err := down.Write([]byte(statusLine)); err != nil {
			return false
		}
		code = parseStatusCode(statusLine)

		respHeaders = make(map[string]string)
		for {
			if timeout > 0 {
				remote.SetReadDeadline(time.Now().Add(timeout))
			}
			line, err := respReader.ReadString('\n')
			if err != nil {
				return false
			}
			if _, err := down.Write([]byte(line)); err != nil {
				return false
			}
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				break
			}
			if idx := strings.Index(trimmed, ":"); idx > 0 {
				key := strings.ToLower(strings.TrimSpace(trimmed[:idx]))
				value := strings.TrimSpace(trimmed[idx+1:])
				respHeaders[key] = value
			}
		}
		if code >= 100 && code < 200 && code != 101 {
			continue
		}
		break
	}

	if code == 101 {
		if n := respReader.Buffered(); n > 0 {
			io.CopyN(down, respReader, int64(n))
		}
		remote.SetReadDeadline(time.Time{})
		s.pipeWithReader(client, remote, reader)
		return false
	}

	contentLength := int64(-1)
	if cl, ok := respHeaders["content-length"]; ok {
		if v, err := strconv.ParseInt(cl, 10, 64); err == nil {
			contentLength = v
		}
	}
	chunkedResp := false
	if te, ok := respHeaders["transfer-encoding"]; ok && strings.Contains(strings.ToLower(te), "chunked") {
		chunkedResp = true
	}

	closeAfter := false
	if v, ok := respHeaders["connection"]; ok && strings.EqualFold(v, "close") {
		closeAfter = true
	}
	if v, ok := req.Headers["connection"]; ok && strings.EqualFold(v, "close") {
		closeAfter = true
	}

	if req.Method == "HEAD" || code == 204 || code == 304 {
		contentLength = 0
		chunkedResp = false
	}

	if chunkedResp {
		if err := copyChunked(down, respReader); err != nil {
			return false
		}
	} else if contentLength >= 0 {
		if timeout > 0 {
			remote.SetReadDeadline(time.Now().Add(timeout))
		}
		if _, err := io.CopyN(down, respReader, contentLength); err != nil {
			return false
		}
	} else {
		io.Copy(down, respReader)
		closeAfter = true
	}

	return !closeAfter
}

func (s *ProxyServer) handleHTTPS(client net.Conn, req *HTTPRequest, reader *bufio.Reader, bypass bool) {
	if front := s.config.frontFor(req.Host); front != "" {
		if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}
		s.serveFronted(client, reader, req.Host, req.Port, front)
		return
	}
	fragment := bypass && shouldFragmentPort(req.Port) &&
		!(s.config.FragmentMethod == "none" && !s.config.Adaptive && !s.config.FakePacket)

	firstConn, err := s.dialTarget(req.Host, req.Port)
	if err != nil {
		s.stats.IncrementError()
		if s.errorLog != nil {
			s.errorLog.Printf("Dial error: %v", err)
		}
		client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return
	}
	setNoDelay(firstConn)

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		firstConn.Close()
		return
	}
	setNoDelay(client)

	if !fragment {
		defer firstConn.Close()
		s.pipeWithReader(client, firstConn, reader)
		return
	}

	remote, buffered, err := s.connectAndFragment(client, req.Host, req.Port, reader, firstConn)
	if err != nil {
		firstConn.Close()
		if s.errorLog != nil {
			s.errorLog.Printf("fragment error for %s: %v", domainToken(s.config, req.Host), err)
		}

		return
	}
	defer remote.Close()

	if len(buffered) > 0 {
		if _, err := client.Write(buffered); err != nil {
			return
		}
		s.stats.UpdateTraffic(uint64(len(buffered)), 0)
	}
	s.pipeWithReader(client, remote, reader)
}

func (s *ProxyServer) wrapAndSend(remote net.Conn, version [2]byte, data []byte) {
	record := make([]byte, 5+len(data))
	record[0] = 0x16
	record[1] = version[0]
	record[2] = version[1]
	record[3] = byte(len(data) >> 8)
	record[4] = byte(len(data))
	copy(record[5:], data)
	remote.Write(record)
}

func chunkData(data []byte, minSize, maxSize int) [][]byte {
	var chunks [][]byte
	for len(data) > 0 {
		size := minSize
		if maxSize > minSize {
			size = minSize + rand.IntN(maxSize-minSize+1)
		}
		if size > len(data) {
			size = len(data)
		}
		if size < 1 {
			size = 1
		}
		chunks = append(chunks, data[:size])
		data = data[size:]
	}
	return chunks
}

func chunkDataFib(data []byte) [][]byte {
	fib := []int{1, 2, 3, 5, 8, 13, 21, 34, 55, 89}
	var chunks [][]byte
	i := 0
	for len(data) > 0 {
		size := fib[i%len(fib)]
		if size > len(data) {
			size = len(data)
		}
		chunks = append(chunks, data[:size])
		data = data[size:]
		i++
	}
	return chunks
}

func setNoDelay(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
}

func closeWriteSide(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
}

func (s *ProxyServer) setSocketOptions(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		if s.config.KeepAlive {
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(30 * time.Second)
		}
		if s.config.TTL > 0 {
			setTTL(tc, s.config.TTL)
		}
	}
}

type deadlineReader struct {
	r       io.Reader
	conn    net.Conn
	timeout time.Duration
}

func (d *deadlineReader) Read(p []byte) (int, error) {
	if d.timeout > 0 {
		d.conn.SetReadDeadline(time.Now().Add(d.timeout))
	}
	return d.r.Read(p)
}

type deadlineWriter struct {
	w       io.Writer
	conn    net.Conn
	timeout time.Duration
}

func (d *deadlineWriter) Write(p []byte) (int, error) {
	if d.timeout > 0 {
		d.conn.SetWriteDeadline(time.Now().Add(d.timeout))
	}
	return d.w.Write(p)
}

func (s *ProxyServer) pipeWithReader(client net.Conn, remote net.Conn, reader *bufio.Reader) {
	buf1 := s.bufPool.Get().([]byte)
	buf2 := s.bufPool.Get().([]byte)
	defer s.bufPool.Put(buf1)
	defer s.bufPool.Put(buf2)

	timeout := time.Duration(s.config.Timeout) * time.Second
	done := make(chan struct{}, 2)

	go func() {
		var r io.Reader = reader
		var w io.Writer = remote
		if timeout > 0 {
			r = &deadlineReader{r: reader, conn: client, timeout: timeout}
			w = &deadlineWriter{w: remote, conn: remote, timeout: timeout}
		}
		w = &countWriter{w: w, add: func(n uint64) { s.stats.UpdateTraffic(0, n) }}
		io.CopyBuffer(w, r, buf1)
		closeWriteSide(remote)
		done <- struct{}{}
	}()

	go func() {
		var r io.Reader = remote
		var w io.Writer = client
		if timeout > 0 {
			r = &deadlineReader{r: remote, conn: remote, timeout: timeout}
			w = &deadlineWriter{w: client, conn: client, timeout: timeout}
		}
		w = &countWriter{w: w, add: func(n uint64) { s.stats.UpdateTraffic(n, 0) }}
		io.CopyBuffer(w, r, buf2)
		closeWriteSide(client)
		done <- struct{}{}
	}()

	<-done
	<-done
}

func Run() {
	config := parseFlags()
	if err := config.validate(); err != nil {
		log.Fatalf("[ERROR] invalid configuration: %v", err)
	}

	if config.Scan {
		runDiagnostics(config)
		return
	}
	if config.Benchmark {
		runBenchmark(config)
		return
	}
	if config.Selftest {
		os.Exit(runSelftest(config))
	}

	stats := &Statistics{}
	var blacklist BlacklistManager

	switch {
	case config.NoBlacklist:
		blacklist = &NoBlacklist{}
	case config.AutoBlacklist:
		blacklist = NewAutoBlacklist(config)
	default:
		var err error
		blacklist, err = NewFileBlacklist(config)
		if err != nil {
			log.Printf("[WARN] could not load blacklist (%v) - continuing with blacklist disabled", err)
			blacklist = &NoBlacklist{}
		}
	}

	server := NewProxyServer(config, stats, blacklist)

	var socksServer *Socks5Server
	if config.EnableSocks5 {
		socksServer = NewSocks5Server(config, stats, blacklist, server)
	}

	var transparentServer *TransparentServer
	if config.EnableTransparent {
		if !isTransparentSupported() {
			log.Printf("[WARN] -transparent was requested but whole-system transparent redirect isn't implemented on this OS (Linux-only, needs SO_ORIGINAL_DST). Every connection through it will fail. Use -socks5 instead and point your browser/OS proxy settings at it - see transparent_other.go for why and what the Windows equivalent would take.")
		}
		transparentServer = NewTransparentServer(config, stats, blacklist, server)
	}

	startStatsHTTP(config, stats, server)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		var shuttingDown atomic.Bool
		for sig := range sigCh {
			if sig == syscall.SIGHUP {
				n, err := config.ReloadProfiles()
				if err != nil {
					log.Printf("[WARN] SIGHUP: could not reload profiles: %v", err)
				} else {
					log.Printf("[INFO] SIGHUP: reloaded %d domain profile(s) from %s (other settings need a restart)", n, config.ConfigFile)
				}
				continue
			}
			if !shuttingDown.CompareAndSwap(false, true) {
				log.Println("[INFO] second signal received - exiting immediately")
				os.Exit(1)
			}
			log.Println("[INFO] shutting down... (press Ctrl+C again to force)")
			go func() {
				if transparentServer != nil {
					transparentServer.Stop()
				}
				if socksServer != nil {
					socksServer.Stop()
				}
				server.Stop()
				os.Exit(0)
			}()
		}
	}()

	if socksServer != nil {
		go func() {
			if err := socksServer.Start(); err != nil {
				log.Printf("[ERROR] SOCKS5 server error: %v", err)
			}
		}()
	}

	if transparentServer != nil {
		go func() {
			if err := transparentServer.Start(); err != nil {
				log.Printf("[ERROR] transparent server error: %v", err)
			}
		}()
	}

	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
