package dpiproxy

import (
	"crypto/rand"
	"log"
	"net"
	"sync"
)

func isIPv6Conn(tc *net.TCPConn) bool {
	addr, ok := tc.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return false
	}
	return addr.IP.To4() == nil
}

func setTTL(tc *net.TCPConn, ttl int) {
	if ttl <= 0 {
		return
	}
	_ = setConnTTL(tc, ttl)
}

var decoySNIs = []string{
	"www.example.com",
	"www.microsoft.com",
	"www.wikipedia.org",
	"www.mozilla.org",
	"www.cloudflare.com",
}

var fakeWarnOnce sync.Once

func sendFakeClientHellos(remote net.Conn, version [2]byte, cfg *Config) bool {
	tc, ok := remote.(*net.TCPConn)
	if !ok {
		return false
	}
	f, err := parseFakeFooling(cfg.FakeMethod)
	if err != nil {
		return false
	}
	count := cfg.FakePacketCount
	if count < 1 {
		count = 1
	}
	sent := false
	for i := 0; i < count; i++ {
		ttl := 0
		if f.TTL {
			ttl = cfg.FakePacketTTL + i
			if ttl <= 0 {
				ttl = 1 + i
			}
		}
		decoy := buildDecoyClientHelloRecord(version, cfg.FakeSNIPool)
		if err := injectFakeSegment(tc, decoy, f, ttl); err != nil {
			fakeWarnOnce.Do(func() {
				log.Printf("[WARN] -fake-packet: could not inject decoy (%v); continuing without it", err)
			})
			return sent
		}
		sent = true
	}
	return sent
}

func buildDecoyClientHelloRecord(version [2]byte, pool []string) []byte {
	list := decoySNIs
	if len(pool) > 0 {
		list = pool
	}
	sni := list[randIntN(len(list))]

	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		for i := range random {
			random[i] = byte(randIntN(256))
		}
	}

	ch := &clientHelloMsg{
		Version:            version,
		Random:             random,
		SessionID:          nil,
		CipherSuites:       []byte{0xc0, 0x2f, 0xc0, 0x30, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35},
		CompressionMethods: []byte{0x00},
		Extensions: []tlsExtension{
			{Type: 0, Data: buildServerNameExtensionData(sni)},
		},
	}

	full, _, _, _ := serializeClientHello(ch)

	record := make([]byte, 5+len(full))
	record[0] = 0x16
	record[1] = version[0]
	record[2] = version[1]
	record[3] = byte(len(full) >> 8)
	record[4] = byte(len(full))
	copy(record[5:], full)
	return record
}
