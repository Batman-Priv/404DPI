//go:build !unix && !windows

package dpiproxy

import (
	"errors"
	"net"
)

func getConnTTL(tc *net.TCPConn) (int, error) {
	return 0, errors.New("TTL control is not supported on this platform")
}

func setConnTTL(tc *net.TCPConn, ttl int) error {
	return errors.New("TTL control is not supported on this platform")
}
