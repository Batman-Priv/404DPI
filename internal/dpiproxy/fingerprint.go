package dpiproxy

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"
)

func isGrease(v uint16) bool {
	return v&0x0f0f == 0x0a0a && (v>>8)&0xf == v&0xf
}

func uint16ListToString(vals []uint16, filterGrease bool) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		if filterGrease && isGrease(v) {
			continue
		}
		parts = append(parts, strconv.Itoa(int(v)))
	}
	return strings.Join(parts, "-")
}

func cipherSuitesToUint16(suites []byte) []uint16 {
	out := make([]uint16, 0, len(suites)/2)
	for i := 0; i+1 < len(suites); i += 2 {
		out = append(out, uint16(suites[i])<<8|uint16(suites[i+1]))
	}
	return out
}

func extList16(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(data[0])<<8 | int(data[1])
	body := data[2:]
	if listLen > len(body) {
		listLen = len(body)
	}
	body = body[:listLen]
	out := make([]uint16, 0, len(body)/2)
	for i := 0; i+1 < len(body); i += 2 {
		out = append(out, uint16(body[i])<<8|uint16(body[i+1]))
	}
	return out
}

func extList8(data []byte) []uint16 {
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	body := data[1:]
	if listLen > len(body) {
		listLen = len(body)
	}
	body = body[:listLen]
	out := make([]uint16, 0, len(body))
	for _, b := range body {
		out = append(out, uint16(b))
	}
	return out
}

func findExt(ch *clientHelloMsg, typ uint16) []byte {
	for _, e := range ch.Extensions {
		if e.Type == typ {
			return e.Data
		}
	}
	return nil
}

func ja3String(ch *clientHelloMsg) string {
	version := int(ch.Version[0])<<8 | int(ch.Version[1])
	ciphers := uint16ListToString(cipherSuitesToUint16(ch.CipherSuites), true)

	extTypes := make([]uint16, 0, len(ch.Extensions))
	for _, e := range ch.Extensions {
		extTypes = append(extTypes, e.Type)
	}
	extensions := uint16ListToString(extTypes, true)

	curves := uint16ListToString(extList16(findExt(ch, 10)), true)
	points := uint16ListToString(extList8(findExt(ch, 11)), false)

	return strings.Join([]string{
		strconv.Itoa(version), ciphers, extensions, curves, points,
	}, ",")
}

func ja3Hash(ch *clientHelloMsg) string {
	sum := md5.Sum([]byte(ja3String(ch)))
	return hex.EncodeToString(sum[:])
}
