package dpiproxy

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type Socks5Server struct {
	config    *Config
	stats     *Statistics
	blacklist BlacklistManager
	proxy     *ProxyServer
	ln        net.Listener
	stopCh    chan struct{}
	stopOnce  sync.Once
	wg        sync.WaitGroup
}

func NewSocks5Server(config *Config, stats *Statistics, blacklist BlacklistManager, proxy *ProxyServer) *Socks5Server {
	return &Socks5Server{
		config:    config,
		stats:     stats,
		blacklist: blacklist,
		proxy:     proxy,
		stopCh:    make(chan struct{}),
	}
}

func (s *Socks5Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Socks5Host, s.config.Socks5Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.ln = ln
	log.Printf("SOCKS5 proxy running on %s", addr)

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

func (s *Socks5Server) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
	if s.ln != nil {
		s.ln.Close()
	}
	waitTimeout(&s.wg, 3*time.Second)
}

func (s *Socks5Server) handleConn(client net.Conn) {
	defer s.wg.Done()
	defer client.Close()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[ERROR] recovered panic in socks5 handler: %v", r)
		}
	}()

	if !s.stats.TryAcquireConn(s.config.MaxConnections) {
		return
	}
	defer s.stats.ReleaseConn()

	client.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(client)

	verNMethods := make([]byte, 2)
	if _, err := io.ReadFull(reader, verNMethods); err != nil || verNMethods[0] != 0x05 {
		return
	}
	methods := make([]byte, int(verNMethods[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return
	}

	needAuth := s.config.Username != "" || s.config.Password != ""
	chosen := byte(0xFF)
	for _, m := range methods {
		if needAuth && m == 0x02 {
			chosen = 0x02
			break
		}
		if !needAuth && m == 0x00 {
			chosen = 0x00
		}
	}
	if chosen == 0xFF {
		client.Write([]byte{0x05, 0xFF})
		return
	}
	client.Write([]byte{0x05, chosen})

	if chosen == 0x02 {
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(reader, hdr); err != nil {
			return
		}
		uname := make([]byte, int(hdr[1]))
		if _, err := io.ReadFull(reader, uname); err != nil {
			return
		}
		plenB := make([]byte, 1)
		if _, err := io.ReadFull(reader, plenB); err != nil {
			return
		}
		passwd := make([]byte, int(plenB[0]))
		if _, err := io.ReadFull(reader, passwd); err != nil {
			return
		}
		if !secureEqual(string(uname), s.config.Username) || !secureEqual(string(passwd), s.config.Password) {
			client.Write([]byte{0x01, 0x01})
			return
		}
		client.Write([]byte{0x01, 0x00})
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(reader, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	cmd := hdr[1]
	atyp := hdr[3]

	host, err := readSocks5Addr(reader, atyp)
	if err != nil {
		s.replySocks5(client, 0x08, nil, 0)
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBuf); err != nil {
		return
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])

	client.SetDeadline(time.Time{})

	switch cmd {
	case 0x01:
		s.handleConnect(client, reader, host, port)
	case 0x03:
		s.handleUDPAssociate(client)
	default:
		s.replySocks5(client, 0x07, nil, 0)
	}
}

func readSocks5Addr(reader *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case 0x03:
		lenB, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		buf := make([]byte, int(lenB))
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	default:
		return "", fmt.Errorf("unsupported address type %d", atyp)
	}
}

func (s *Socks5Server) replySocks5(client net.Conn, rep byte, bindIP net.IP, bindPort int) {
	ip4 := net.IPv4(0, 0, 0, 0).To4()
	if bindIP != nil {
		if v4 := bindIP.To4(); v4 != nil {
			ip4 = v4
		}
	}
	resp := []byte{0x05, rep, 0x00, 0x01}
	resp = append(resp, ip4...)
	resp = append(resp, byte(bindPort>>8), byte(bindPort&0xFF))
	client.Write(resp)
}

func (s *Socks5Server) handleConnect(client net.Conn, reader *bufio.Reader, host string, port int) {
	go s.blacklist.CheckDomain(host)
	s.stats.IncrementTotal()

	bypass := s.proxy.needsBypass(host)
	fragment := bypass && shouldFragmentPort(port) &&
		!(s.config.FragmentMethod == "none" && !s.config.Adaptive && !s.config.FakePacket)
	if bypass {
		s.stats.IncrementBypassed()
	} else {
		s.stats.IncrementDirect()
	}

	if front := s.config.frontFor(host); front != "" {
		s.replySocks5(client, 0x00, net.IPv4(127, 0, 0, 1), s.config.Socks5Port)
		s.proxy.serveFronted(client, reader, host, port, front)
		return
	}

	firstConn, err := s.proxy.dialTarget(host, port)
	if err != nil {
		s.stats.IncrementError()
		s.replySocks5(client, 0x05, nil, 0)
		return
	}
	setNoDelay(firstConn)
	s.replySocks5(client, 0x00, net.IPv4(127, 0, 0, 1), s.config.Socks5Port)
	setNoDelay(client)

	if !fragment {
		defer firstConn.Close()
		s.proxy.pipeWithReader(client, firstConn, reader)
		return
	}

	remote, buffered, err := s.proxy.connectAndFragment(client, host, port, reader, firstConn)
	if err != nil {
		firstConn.Close()
		if s.proxy.errorLog != nil {
			s.proxy.errorLog.Printf("socks5 fragment error for %s: %v", domainToken(s.config, host), err)
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
	s.proxy.pipeWithReader(client, remote, reader)
}

func (s *Socks5Server) handleUDPAssociate(client net.Conn) {
	bindHost := s.config.Socks5Host
	if bindHost == "" || bindHost == "0.0.0.0" {
		bindHost = "127.0.0.1"
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(bindHost), Port: 0})
	if err != nil {
		s.replySocks5(client, 0x01, nil, 0)
		return
	}
	defer udpConn.Close()

	local := udpConn.LocalAddr().(*net.UDPAddr)
	replyIP := net.ParseIP(bindHost)
	s.replySocks5(client, 0x00, replyIP, local.Port)

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		client.Read(buf)
		close(done)
		udpConn.Close()
	}()

	var clientAddr *net.UDPAddr
	var clientMu sync.Mutex

	buf := make([]byte, 65535)
	for {
		udpConn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-done:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-done:
					return
				default:
					continue
				}
			}
			return
		}

		clientMu.Lock()
		if clientAddr == nil {
			clientAddr = addr
		}
		isFromClient := addr.IP.Equal(clientAddr.IP) && addr.Port == clientAddr.Port
		curClient := clientAddr
		clientMu.Unlock()

		data := append([]byte{}, buf[:n]...)
		if isFromClient {
			s.relayUDPFromClient(udpConn, data, curClient)
		} else {
			relayUDPToClient(udpConn, data, addr, curClient)
		}
	}
}

func (s *Socks5Server) relayUDPFromClient(udpConn *net.UDPConn, packet []byte, clientAddr *net.UDPAddr) {
	if len(packet) < 4 || packet[2] != 0x00 {
		return
	}
	atyp := packet[3]

	var host string
	var pos int
	switch atyp {
	case 0x01:
		if len(packet) < 4+4+2 {
			return
		}
		host = net.IP(packet[4:8]).String()
		pos = 8
	case 0x03:
		if len(packet) < 5 {
			return
		}
		l := int(packet[4])
		if len(packet) < 5+l+2 {
			return
		}
		host = string(packet[5 : 5+l])
		pos = 5 + l
	case 0x04:
		if len(packet) < 4+16+2 {
			return
		}
		host = net.IP(packet[4:20]).String()
		pos = 20
	default:
		return
	}
	port := int(packet[pos])<<8 | int(packet[pos+1])
	data := packet[pos+2:]

	if port == 443 {
		switch s.config.resolvedQUICMode() {
		case "inspect":

			if len(data) > 0 && data[0]&0x80 != 0 {
				go inspectQUICInitial(s.config, host, append([]byte(nil), data...))
			}
		case "drop":

			return
		case "delay":

			dataCopy := append([]byte(nil), data...)
			go func() {
				delay := s.config.QUICDelay
				if delay <= 0 {
					delay = 80
				}
				time.Sleep(time.Duration(delay+randIntN(delay)) * time.Millisecond)
				s.forwardUDPPacket(udpConn, atyp, host, port, dataCopy, clientAddr)
			}()
			return
		}
	}

	s.forwardUDPPacket(udpConn, atyp, host, port, data, clientAddr)
}

func (s *Socks5Server) forwardUDPPacket(udpConn *net.UDPConn, atyp byte, host string, port int, data []byte, clientAddr *net.UDPAddr) {
	if s.config.EnableDoH && port == 53 && s.proxy.doh != nil {
		if resp := s.answerDNSViaDoH(data); resp != nil {
			reply := buildSocks5UDPHeader(atyp, host, port)
			reply = append(reply, resp...)
			udpConn.WriteToUDP(reply, clientAddr)
		}
		return
	}

	target := &net.UDPAddr{Port: port}
	if ip := net.ParseIP(host); ip != nil {
		target.IP = ip
	} else if s.proxy.doh != nil {
		ips, err := s.proxy.doh.Resolve(host)
		if err != nil || len(ips) == 0 {
			return
		}
		target.IP = ips[0]
	} else {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return
		}
		target.IP = ips[0]
	}
	udpConn.WriteToUDP(data, target)
}

func relayUDPToClient(udpConn *net.UDPConn, data []byte, from *net.UDPAddr, clientAddr *net.UDPAddr) {
	atyp := byte(0x01)
	ipBytes := from.IP.To4()
	if ipBytes == nil {
		atyp = 0x04
		ipBytes = from.IP.To16()
	}
	header := make([]byte, 0, 10+len(data))
	header = append(header, 0x00, 0x00, 0x00, atyp)
	header = append(header, ipBytes...)
	header = append(header, byte(from.Port>>8), byte(from.Port&0xFF))
	header = append(header, data...)
	udpConn.WriteToUDP(header, clientAddr)
}

func buildSocks5UDPHeader(atyp byte, host string, port int) []byte {
	header := []byte{0x00, 0x00, 0x00}
	switch atyp {
	case 0x01, 0x04:
		ip := net.ParseIP(host)
		if atyp == 0x01 && ip.To4() != nil {
			header = append(header, 0x01)
			header = append(header, ip.To4()...)
		} else {
			header = append(header, 0x04)
			header = append(header, ip.To16()...)
		}
	default:
		header = append(header, 0x03, byte(len(host)))
		header = append(header, []byte(host)...)
	}
	header = append(header, byte(port>>8), byte(port&0xFF))
	return header
}

func (s *Socks5Server) answerDNSViaDoH(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	id := query[0:2]
	domain, qtype, qend, err := parseDNSQuestion(query)
	if err != nil || qend > len(query) {
		return nil
	}

	ips, err := s.proxy.doh.Resolve(domain)
	if err != nil || len(ips) == 0 {
		return buildDNSErrorResponse(id, query[:qend], 3)
	}

	var answers []net.IP
	for _, ip := range ips {
		if qtype == 1 && ip.To4() != nil {
			answers = append(answers, ip)
		} else if qtype == 28 && ip.To4() == nil {
			answers = append(answers, ip)
		}
	}
	if len(answers) == 0 {
		return buildDNSErrorResponse(id, query[:qend], 0)
	}
	return buildDNSAnswerResponse(id, query[:qend], qtype, answers)
}
