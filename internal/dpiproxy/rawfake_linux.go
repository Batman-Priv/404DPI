//go:build linux

package dpiproxy

import (
	"fmt"
	"net"
	"syscall"
)

const (
	tcpRepair        = 19
	tcpRepairQueue   = 20
	tcpQueueSeq      = 21
	tcpRepairOn      = 1
	tcpRepairOff     = 0
	tcpRepairOffNoWP = -1
	tcpRecvQueue     = 1
	tcpSendQueue     = 2
)

func connSeqs(tc *net.TCPConn) (snd, rcv uint32, err error) {
	rc, err := tc.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	cerr := rc.Control(func(fd uintptr) {
		f := int(fd)
		if e := syscall.SetsockoptInt(f, syscall.IPPROTO_TCP, tcpRepair, tcpRepairOn); e != nil {
			err = fmt.Errorf("TCP_REPAIR: %w", e)
			return
		}
		defer func() {
			if e := syscall.SetsockoptInt(f, syscall.IPPROTO_TCP, tcpRepair, tcpRepairOffNoWP); e != nil {
				_ = syscall.SetsockoptInt(f, syscall.IPPROTO_TCP, tcpRepair, tcpRepairOff)
			}
		}()
		read := func(queue int) (uint32, error) {
			if e := syscall.SetsockoptInt(f, syscall.IPPROTO_TCP, tcpRepairQueue, queue); e != nil {
				return 0, e
			}
			v, e := syscall.GetsockoptInt(f, syscall.IPPROTO_TCP, tcpQueueSeq)
			return uint32(v), e
		}
		if snd, err = read(tcpSendQueue); err != nil {
			return
		}
		rcv, err = read(tcpRecvQueue)
	})
	if cerr != nil {
		return 0, 0, cerr
	}
	return snd, rcv, err
}

func injectFakeSegment(tc *net.TCPConn, payload []byte, f fakeFooling, ttl int) error {
	la, ok1 := tc.LocalAddr().(*net.TCPAddr)
	ra, ok2 := tc.RemoteAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return fmt.Errorf("not a TCP connection")
	}
	snd, rcv, err := connSeqs(tc)
	if err != nil {
		return err
	}
	if ttl <= 0 || ttl > 255 {
		ttl = 64
	}
	pkt := buildFakeTCPPacket(la.IP, ra.IP, uint16(la.Port), uint16(ra.Port), snd, rcv, payload, uint8(ttl), f)

	if ra4 := ra.IP.To4(); ra4 != nil && la.IP.To4() != nil {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			return fmt.Errorf("raw socket: %w", err)
		}
		defer syscall.Close(fd)
		sa := &syscall.SockaddrInet4{}
		copy(sa.Addr[:], ra4)
		return syscall.Sendto(fd, pkt, 0, sa)
	}
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("raw socket: %w", err)
	}
	defer syscall.Close(fd)
	sa := &syscall.SockaddrInet6{}
	copy(sa.Addr[:], ra.IP.To16())
	return syscall.Sendto(fd, pkt, 0, sa)
}

func rawFakeAvailable() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			defer c.Close()
			buf := make([]byte, 1)
			c.Read(buf)
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return err
	}
	defer c.Close()
	tc := c.(*net.TCPConn)
	if _, _, err := connSeqs(tc); err != nil {
		return fmt.Errorf("%w (needs root or CAP_NET_ADMIN)", err)
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("raw socket: %w (needs root or CAP_NET_RAW)", err)
	}
	syscall.Close(fd)
	return nil
}
