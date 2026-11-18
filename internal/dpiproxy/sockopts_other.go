//go:build !linux

package dpiproxy

func applySocketOptions(fd uintptr, config *Config) {}
