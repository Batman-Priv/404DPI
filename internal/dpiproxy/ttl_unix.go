//go:build unix

package dpiproxy

import (
	"net"
	"syscall"
)

func ttlSockopt(tc *net.TCPConn) (level, opt int) {
	if isIPv6Conn(tc) {
		return syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS
	}
	return syscall.IPPROTO_IP, syscall.IP_TTL
}

func getConnTTL(tc *net.TCPConn) (int, error) {
	rc, err := tc.SyscallConn()
	if err != nil {
		return 0, err
	}
	level, opt := ttlSockopt(tc)
	var v int
	var serr error
	if err := rc.Control(func(fd uintptr) {
		v, serr = syscall.GetsockoptInt(int(fd), level, opt)
	}); err != nil {
		return 0, err
	}
	return v, serr
}

func setConnTTL(tc *net.TCPConn, ttl int) error {
	rc, err := tc.SyscallConn()
	if err != nil {
		return err
	}
	level, opt := ttlSockopt(tc)
	var serr error
	if err := rc.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), level, opt, ttl)
	}); err != nil {
		return err
	}
	return serr
}
