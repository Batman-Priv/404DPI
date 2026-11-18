package dpiproxy

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

type fakeFooling struct {
	TTL, BadSum, BadSeq, MD5 bool
}

func parseFakeFooling(spec string) (fakeFooling, error) {
	var f fakeFooling
	if strings.TrimSpace(spec) == "" {
		spec = "ttl"
	}
	for _, m := range strings.Split(spec, ",") {
		switch strings.ToLower(strings.TrimSpace(m)) {
		case "ttl":
			f.TTL = true
		case "badsum":
			f.BadSum = true
		case "badseq":
			f.BadSeq = true
		case "md5", "md5sig":
			f.MD5 = true
		case "":
		default:
			return f, fmt.Errorf("unknown fake method %q (use ttl, badsum, badseq, md5; comma-separated to combine)", m)
		}
	}
	if !f.TTL && !f.BadSum && !f.BadSeq && !f.MD5 {
		return f, fmt.Errorf("no fake method given")
	}
	return f, nil
}

func inetChecksum(parts ...[]byte) uint16 {
	var sum uint32
	var odd bool
	var carry byte
	for _, p := range parts {
		if odd && len(p) > 0 {
			sum += uint32(carry)<<8 | uint32(p[0])
			p = p[1:]
			odd = false
		}
		for len(p) >= 2 {
			sum += uint32(p[0])<<8 | uint32(p[1])
			p = p[2:]
		}
		if len(p) == 1 {
			carry, odd = p[0], true
		}
	}
	if odd {
		sum += uint32(carry) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func buildFakeTCPPacket(src, dst net.IP, sport, dport uint16, seq, ack uint32, payload []byte, ttl uint8, f fakeFooling) []byte {
	if f.BadSeq {
		seq -= 10000
	}

	var opts []byte
	if f.MD5 {
		opts = make([]byte, 20)
		opts[0], opts[1] = 19, 18
		rand.Read(opts[2:18])
		opts[18], opts[19] = 1, 1
	}
	tcp := make([]byte, 20+len(opts)+len(payload))
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = byte((20+len(opts))/4) << 4
	tcp[13] = 0x18
	binary.BigEndian.PutUint16(tcp[14:], 0xffff)
	copy(tcp[20:], opts)
	copy(tcp[20+len(opts):], payload)

	var pseudo []byte
	src4, dst4 := src.To4(), dst.To4()
	v4 := src4 != nil && dst4 != nil
	if v4 {
		pseudo = make([]byte, 12)
		copy(pseudo[0:], src4)
		copy(pseudo[4:], dst4)
		pseudo[9] = 6
		binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcp)))
	} else {
		pseudo = make([]byte, 40)
		copy(pseudo[0:], src.To16())
		copy(pseudo[16:], dst.To16())
		binary.BigEndian.PutUint32(pseudo[32:], uint32(len(tcp)))
		pseudo[39] = 6
	}
	csum := inetChecksum(pseudo, tcp)
	if f.BadSum {
		csum ^= 0x5a5a
	}
	binary.BigEndian.PutUint16(tcp[16:], csum)

	if v4 {
		ip := make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)))
		var id [2]byte
		rand.Read(id[:])
		copy(ip[4:], id[:])
		binary.BigEndian.PutUint16(ip[6:], 0x4000)
		ip[8] = ttl
		ip[9] = 6
		copy(ip[12:], src4)
		copy(ip[16:], dst4)
		binary.BigEndian.PutUint16(ip[10:], inetChecksum(ip))
		return append(ip, tcp...)
	}
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(tcp)))
	ip[6] = 6
	ip[7] = ttl
	copy(ip[8:], src.To16())
	copy(ip[24:], dst.To16())
	return append(ip, tcp...)
}
