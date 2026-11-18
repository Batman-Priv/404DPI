package dpiproxy

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

type TransparentServer struct {
	config    *Config
	stats     *Statistics
	blacklist BlacklistManager
	proxy     *ProxyServer

	ln       net.Listener
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

func NewTransparentServer(config *Config, stats *Statistics, blacklist BlacklistManager, proxy *ProxyServer) *TransparentServer {
	return &TransparentServer{
		config:    config,
		stats:     stats,
		blacklist: blacklist,
		proxy:     proxy,
		stopCh:    make(chan struct{}),
	}
}

func (s *TransparentServer) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.TransparentHost, s.config.TransparentPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.ln = ln
	log.Printf("Transparent listener on %s (needs a matching iptables REDIRECT rule - see README.md)", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return nil
			default:
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

func (s *TransparentServer) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
	if s.ln != nil {
		s.ln.Close()
	}
	waitTimeout(&s.wg, 3*time.Second)
}

func (s *TransparentServer) handleConn(client net.Conn) {
	defer s.wg.Done()
	defer client.Close()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[ERROR] recovered panic in transparent handler: %v", r)
		}
	}()

	tc, ok := client.(*net.TCPConn)
	if !ok {
		return
	}

	if !s.stats.TryAcquireConn(s.config.MaxConnections) {
		return
	}
	defer s.stats.ReleaseConn()

	ip, port, err := getOriginalDst(tc)
	if err != nil {
		log.Printf("[ERROR] SO_ORIGINAL_DST lookup failed (is the iptables REDIRECT rule set up? see README.md): %v", err)
		return
	}

	if port == s.config.TransparentPort {
		return
	}

	host := ip.String()
	go s.blacklist.CheckDomain(host)
	s.stats.IncrementTotal()

	reader := bufio.NewReader(client)

	if shouldFragmentPort(port) {
		s.handleTLS(client, reader, host, port)
		return
	}

	remote, err := s.proxy.dialTarget(host, port)
	if err != nil {
		s.stats.IncrementError()
		return
	}
	defer remote.Close()
	setNoDelay(remote)
	s.stats.IncrementDirect()
	s.proxy.pipeWithReader(client, remote, reader)
}

func (s *TransparentServer) handleTLS(client net.Conn, reader *bufio.Reader, host string, port int) {
	firstConn, err := s.proxy.dialTarget(host, port)
	if err != nil {
		s.stats.IncrementError()
		return
	}
	setNoDelay(firstConn)

	remote, buffered, err := s.proxy.connectAndFragment(client, host, port, reader, firstConn)
	if err != nil {
		firstConn.Close()
		return
	}
	defer remote.Close()

	if len(buffered) > 0 {
		if _, err := client.Write(buffered); err != nil {
			return
		}
		s.stats.UpdateTraffic(uint64(len(buffered)), 0)
	}
	s.stats.IncrementBypassed()
	s.proxy.pipeWithReader(client, remote, reader)
}
