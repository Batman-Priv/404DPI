package dpiproxy

import (
	"encoding/binary"
	"net"
	"testing"
)

func tcpChecksumOK(pkt []byte) bool {
	if pkt[0]>>4 == 4 {
		ihl := int(pkt[0]&0x0f) * 4
		tcp := pkt[ihl:]
		pseudo := make([]byte, 12)
		copy(pseudo, pkt[12:20])
		pseudo[9] = 6
		binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcp)))
		return inetChecksum(pseudo, tcp) == 0 && inetChecksum(pkt[:ihl]) == 0
	}
	tcp := pkt[40:]
	pseudo := make([]byte, 40)
	copy(pseudo, pkt[8:40])
	binary.BigEndian.PutUint32(pseudo[32:], uint32(len(tcp)))
	pseudo[39] = 6
	return inetChecksum(pseudo, tcp) == 0
}

func TestBuildFakeTCPPacket(t *testing.T) {
	payload := []byte("hello decoy")
	for _, addrs := range [][2]string{{"10.0.1.2", "10.0.2.2"}, {"fd00::1", "fd00::2"}} {
		src, dst := net.ParseIP(addrs[0]), net.ParseIP(addrs[1])
		v4 := src.To4() != nil

		good := buildFakeTCPPacket(src, dst, 40000, 443, 1000, 2000, payload, 7, fakeFooling{TTL: true})
		if !tcpChecksumOK(good) {
			t.Fatalf("%s: checksum of a normal decoy must be valid", addrs[0])
		}
		ttl := good[8]
		if !v4 {
			ttl = good[7]
		}
		if ttl != 7 {
			t.Fatalf("%s: ttl = %d", addrs[0], ttl)
		}

		bad := buildFakeTCPPacket(src, dst, 40000, 443, 1000, 2000, payload, 7, fakeFooling{BadSum: true})
		if tcpChecksumOK(bad) {
			t.Fatalf("%s: badsum packet has a valid checksum", addrs[0])
		}

		md5 := buildFakeTCPPacket(src, dst, 40000, 443, 1000, 2000, payload, 7, fakeFooling{MD5: true})
		if !tcpChecksumOK(md5) {
			t.Fatalf("%s: md5 packet checksum invalid", addrs[0])
		}
		off := 0
		if v4 {
			off = 20
		} else {
			off = 40
		}
		if md5[off+12]>>4 != 10 || md5[off+20] != 19 || md5[off+21] != 18 {
			t.Fatalf("%s: md5 option missing", addrs[0])
		}
		if string(md5[len(md5)-len(payload):]) != string(payload) {
			t.Fatalf("%s: payload corrupted", addrs[0])
		}

		seq := buildFakeTCPPacket(src, dst, 40000, 443, 1000, 2000, payload, 7, fakeFooling{BadSeq: true})
		if got := binary.BigEndian.Uint32(seq[off+4:]); got == 1000 {
			t.Fatalf("%s: badseq left the sequence number alone", addrs[0])
		}
	}
}

func TestParseFakeFooling(t *testing.T) {
	f, err := parseFakeFooling("ttl, badsum,MD5")
	if err != nil || !f.TTL || !f.BadSum || !f.MD5 || f.BadSeq {
		t.Fatalf("%+v %v", f, err)
	}
	if f, _ := parseFakeFooling(""); !f.TTL {
		t.Fatal("empty must default to ttl")
	}
	if _, err := parseFakeFooling("bogus"); err == nil {
		t.Fatal("bogus method accepted")
	}
}
