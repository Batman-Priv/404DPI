package dpiproxy

import (
	"net"
	"syscall"
	"time"
)

func buildDialer(config *Config, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if config.TCPFastOpen || config.TCPMSS > 0 {
		d.Control = func(network, address string, c syscall.RawConn) error {
			c.Control(func(fd uintptr) {
				applySocketOptions(fd, config)
			})
			return nil
		}
	}
	return d
}
