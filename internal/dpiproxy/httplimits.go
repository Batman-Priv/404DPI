package dpiproxy

import (
	"bufio"
	"fmt"
)

const (
	maxRequestLineLen  = 8192
	maxHeaderLineLen   = 8192
	maxHeaderCount     = 100
	maxTotalHeaderSize = 65536
)

func readLimitedLine(r *bufio.Reader, maxLen int) (string, error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > maxLen {
			return "", fmt.Errorf("line exceeds %d byte limit", maxLen)
		}
		if err == nil {
			return string(buf), nil
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return "", err
	}
}
