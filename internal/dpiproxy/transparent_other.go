//go:build !linux

package dpiproxy

import (
	"fmt"
	"net"
)

func getOriginalDst(conn *net.TCPConn) (net.IP, int, error) {
	return nil, 0, fmt.Errorf("transparent proxying (SO_ORIGINAL_DST) is only implemented on Linux; on Windows/macOS, point your system proxy settings at -socks5 instead")
}

func isTransparentSupported() bool { return false }
