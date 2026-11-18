//go:build linux

package dpiproxy

import "syscall"

const tcpFastOpenConnect = 30

func applySocketOptions(fd uintptr, config *Config) {
	if config.TCPFastOpen {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpFastOpenConnect, 1)
	}
	if config.TCPMSS > 0 {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, config.TCPMSS)
	}
}
