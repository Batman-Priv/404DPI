//go:build !linux

package dpiproxy

import (
	"errors"
	"net"
)

var errRawFakeUnsupported = errors.New("-fake-packet needs raw sockets with TCP_REPAIR and is only implemented on Linux")

func injectFakeSegment(tc *net.TCPConn, payload []byte, f fakeFooling, ttl int) error {
	return errRawFakeUnsupported
}

func rawFakeAvailable() error { return errRawFakeUnsupported }
