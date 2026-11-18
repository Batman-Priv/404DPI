package dpiproxy

import (
	"bytes"
	"net"
	"time"
)

func (s *ProxyServer) obfuscateAndSendHTTP(remote net.Conn, raw []byte) error {
	mangled := mangleHostHeaderCase(raw)

	splitAt := findHostHeaderValueStart(mangled)
	if splitAt <= 0 {
		_, err := remote.Write(mangled)
		return err
	}

	if s.config.Timeout > 0 {
		remote.SetWriteDeadline(time.Now().Add(time.Duration(s.config.Timeout) * time.Second))
	}
	if _, err := remote.Write(mangled[:splitAt]); err != nil {
		return err
	}
	time.Sleep(time.Duration(1+randIntN(3)) * time.Millisecond)
	_, err := remote.Write(mangled[splitAt:])
	return err
}

func mangleHostHeaderCase(raw []byte) []byte {
	lower := bytes.ToLower(raw)
	idx := bytes.Index(lower, []byte("\r\nhost:"))
	if idx < 0 {
		return raw
	}
	start := idx + 2
	end := start + len("host:") - 1

	out := append([]byte{}, raw...)
	for i := start; i < end; i++ {
		if randIntN(2) == 0 {
			c := out[i]
			if c >= 'a' && c <= 'z' {
				out[i] = c - 32
			}
		}
	}
	return out
}

func findHostHeaderValueStart(raw []byte) int {
	lower := bytes.ToLower(raw)
	idx := bytes.Index(lower, []byte("\r\nhost:"))
	if idx < 0 {
		return -1
	}
	return idx + 2 + len("host:")
}
