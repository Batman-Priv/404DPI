//go:build linux

package dpiproxy

import (
	"encoding/binary"
	"net"
	"syscall"
)

const soOriginalDst = 80

func getOriginalDst(conn *net.TCPConn) (net.IP, int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, 0, err
	}

	var mreq *syscall.IPv6Mreq
	var sockErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		mreq, sockErr = syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, soOriginalDst)
	})
	if ctrlErr != nil {
		return nil, 0, ctrlErr
	}
	if sockErr != nil {
		return nil, 0, sockErr
	}

	addr := mreq.Multiaddr
	port := int(binary.BigEndian.Uint16(addr[2:4]))
	ip := net.IPv4(addr[4], addr[5], addr[6], addr[7])
	return ip, port, nil
}

func isTransparentSupported() bool { return true }
