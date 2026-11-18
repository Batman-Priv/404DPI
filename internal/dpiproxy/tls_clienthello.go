package dpiproxy

import (
	"fmt"
	"math/rand"
)

type tlsExtension struct {
	Type uint16
	Data []byte
}

type clientHelloMsg struct {
	Version            [2]byte
	Random             [32]byte
	SessionID          []byte
	CipherSuites       []byte
	CompressionMethods []byte
	Extensions         []tlsExtension
}

func randIntN(n int) int {
	if n <= 0 {
		return 0
	}
	return rand.Intn(n)
}

func parseClientHello(handshake []byte) (*clientHelloMsg, error) {
	if len(handshake) < 4 {
		return nil, fmt.Errorf("handshake too short")
	}
	if handshake[0] != 0x01 {
		return nil, fmt.Errorf("not a client hello")
	}
	length := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < 4+length {
		return nil, fmt.Errorf("truncated client hello")
	}
	body := handshake[4 : 4+length]

	if len(body) < 2+32+1 {
		return nil, fmt.Errorf("client hello too short")
	}

	ch := &clientHelloMsg{}
	pos := 0
	copy(ch.Version[:], body[pos:pos+2])
	pos += 2
	copy(ch.Random[:], body[pos:pos+32])
	pos += 32

	sidLen := int(body[pos])
	pos++
	if pos+sidLen > len(body) {
		return nil, fmt.Errorf("bad session id length")
	}
	ch.SessionID = append([]byte{}, body[pos:pos+sidLen]...)
	pos += sidLen

	if pos+2 > len(body) {
		return nil, fmt.Errorf("bad cipher suites")
	}
	csLen := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	if pos+csLen > len(body) {
		return nil, fmt.Errorf("bad cipher suites length")
	}
	ch.CipherSuites = append([]byte{}, body[pos:pos+csLen]...)
	pos += csLen

	if pos+1 > len(body) {
		return nil, fmt.Errorf("bad compression methods")
	}
	cmLen := int(body[pos])
	pos++
	if pos+cmLen > len(body) {
		return nil, fmt.Errorf("bad compression methods length")
	}
	ch.CompressionMethods = append([]byte{}, body[pos:pos+cmLen]...)
	pos += cmLen

	if pos+2 > len(body) {
		return ch, nil
	}
	extTotalLen := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	end := pos + extTotalLen
	if end > len(body) {
		return nil, fmt.Errorf("bad extensions length")
	}

	for pos+4 <= end {
		etype := int(body[pos])<<8 | int(body[pos+1])
		elen := int(body[pos+2])<<8 | int(body[pos+3])
		pos += 4
		if pos+elen > end {
			return nil, fmt.Errorf("bad extension entry")
		}
		edata := append([]byte{}, body[pos:pos+elen]...)
		ch.Extensions = append(ch.Extensions, tlsExtension{Type: uint16(etype), Data: edata})
		pos += elen
	}

	return ch, nil
}

func parseServerNameHost(data []byte) (int, int, bool) {
	if len(data) < 5 {
		return 0, 0, false
	}
	listLen := int(data[0])<<8 | int(data[1])
	if 2+listLen > len(data) {
		return 0, 0, false
	}
	if data[2] != 0x00 {
		return 0, 0, false
	}
	hLen := int(data[3])<<8 | int(data[4])
	if 5+hLen > len(data) {
		return 0, 0, false
	}
	return 5, hLen, true
}

var greaseValues = []uint16{
	0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
	0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}

func greaseValue() uint16 {
	return greaseValues[randIntN(len(greaseValues))]
}

func applyGrease(ch *clientHelloMsg) {
	g := greaseValue()
	ch.CipherSuites = append([]byte{byte(g >> 8), byte(g)}, ch.CipherSuites...)

	g2 := greaseValue()
	newExt := tlsExtension{Type: g2, Data: []byte{0x00}}
	insertPos := 0
	if len(ch.Extensions) > 0 {
		insertPos = randIntN(len(ch.Extensions) + 1)
	}
	ch.Extensions = append(ch.Extensions, tlsExtension{})
	copy(ch.Extensions[insertPos+1:], ch.Extensions[insertPos:])
	ch.Extensions[insertPos] = newExt
}

const echGreaseExtensionType = 0xfe0d

func hasExtension(ch *clientHelloMsg, typ uint16) bool {
	for _, e := range ch.Extensions {
		if e.Type == typ {
			return true
		}
	}
	return false
}

func applyECHGrease(ch *clientHelloMsg) {
	if hasExtension(ch, echGreaseExtensionType) {
		return
	}
	const (
		hpkeKDFHKDFSHA256  = 0x0001
		hpkeAEADAES128GCM  = 0x0001
		x25519PublicKeyLen = 32
	)

	payloadLen := 112 + randIntN(48)

	data := make([]byte, 0, 1+2+2+1+2+x25519PublicKeyLen+2+payloadLen)
	data = append(data, 0x00)
	data = append(data, 0x00, hpkeKDFHKDFSHA256)
	data = append(data, 0x00, hpkeAEADAES128GCM)
	data = append(data, byte(randIntN(256)))

	enc := make([]byte, x25519PublicKeyLen)
	fillRandom(enc)
	data = append(data, byte(x25519PublicKeyLen>>8), byte(x25519PublicKeyLen))
	data = append(data, enc...)

	payload := make([]byte, payloadLen)
	fillRandom(payload)
	data = append(data, byte(payloadLen>>8), byte(payloadLen))
	data = append(data, payload...)

	newExt := tlsExtension{Type: echGreaseExtensionType, Data: data}
	insertPos := 0
	if len(ch.Extensions) > 0 {
		insertPos = randIntN(len(ch.Extensions) + 1)
	}
	ch.Extensions = append(ch.Extensions, tlsExtension{})
	copy(ch.Extensions[insertPos+1:], ch.Extensions[insertPos:])
	ch.Extensions[insertPos] = newExt
}

func fillRandom(b []byte) {
	for i := range b {
		b[i] = byte(randIntN(256))
	}
}

func applyPadding(ch *clientHelloMsg, targetLen int) {
	if hasExtension(ch, 21) {
		return
	}
	full, _, _, _ := serializeClientHello(ch)
	current := len(full)
	if current >= targetLen {
		return
	}
	need := targetLen - current - 4
	if need < 0 {
		need = 0
	}
	ch.Extensions = append(ch.Extensions, tlsExtension{Type: 21, Data: make([]byte, need)})
}

func shuffleClientHello(ch *clientHelloMsg) {
	n := len(ch.CipherSuites) / 2
	for i := n - 1; i > 0; i-- {
		j := randIntN(i + 1)
		a, b := 2*i, 2*j
		ch.CipherSuites[a], ch.CipherSuites[b] = ch.CipherSuites[b], ch.CipherSuites[a]
		ch.CipherSuites[a+1], ch.CipherSuites[b+1] = ch.CipherSuites[b+1], ch.CipherSuites[a+1]
	}
	for i := len(ch.Extensions) - 1; i > 0; i-- {
		j := randIntN(i + 1)
		ch.Extensions[i], ch.Extensions[j] = ch.Extensions[j], ch.Extensions[i]
	}
}

func chunkByBoundaries(data []byte, boundaries []int) [][]byte {
	var chunks [][]byte
	for i := 0; i+1 < len(boundaries); i++ {
		start, end := boundaries[i], boundaries[i+1]
		if start < 0 {
			start = 0
		}
		if end > len(data) {
			end = len(data)
		}
		if end <= start {
			continue
		}
		chunks = append(chunks, data[start:end])
	}
	return chunks
}

func buildServerNameExtensionData(host string) []byte {
	h := []byte(host)
	total := 1 + 2 + len(h)
	data := make([]byte, 0, 2+total)
	data = append(data, byte(total>>8), byte(total))
	data = append(data, 0x00)
	data = append(data, byte(len(h)>>8), byte(len(h)))
	data = append(data, h...)
	return data
}

func serializeClientHello(ch *clientHelloMsg) ([]byte, int, int, []int) {
	body := make([]byte, 0, 512)
	var bodyBoundaries []int

	body = append(body, ch.Version[:]...)
	body = append(body, ch.Random[:]...)
	bodyBoundaries = append(bodyBoundaries, len(body))

	body = append(body, byte(len(ch.SessionID)))
	body = append(body, ch.SessionID...)
	bodyBoundaries = append(bodyBoundaries, len(body))

	csLen := len(ch.CipherSuites)
	body = append(body, byte(csLen>>8), byte(csLen))
	body = append(body, ch.CipherSuites...)
	bodyBoundaries = append(bodyBoundaries, len(body))

	body = append(body, byte(len(ch.CompressionMethods)))
	body = append(body, ch.CompressionMethods...)
	bodyBoundaries = append(bodyBoundaries, len(body))

	extBytes := make([]byte, 0, 256)
	var extBoundaries []int
	sniOffsetInExt := -1
	sniLen := 0

	for _, ext := range ch.Extensions {
		extBytes = append(extBytes, byte(ext.Type>>8), byte(ext.Type))
		elen := len(ext.Data)
		extBytes = append(extBytes, byte(elen>>8), byte(elen))
		dataStart := len(extBytes)
		extBytes = append(extBytes, ext.Data...)
		if ext.Type == 0 {
			if hOff, hLen, ok := parseServerNameHost(ext.Data); ok {
				sniOffsetInExt = dataStart + hOff
				sniLen = hLen
			}
		}
		extBoundaries = append(extBoundaries, len(extBytes))
	}

	prefixLen := len(body)
	body = append(body, byte(len(extBytes)>>8), byte(len(extBytes)))
	body = append(body, extBytes...)

	handshakeLen := len(body)
	full := make([]byte, 0, 4+handshakeLen)
	full = append(full, 0x01, byte(handshakeLen>>16), byte(handshakeLen>>8), byte(handshakeLen))
	full = append(full, body...)

	boundaries := []int{0}
	for _, b := range bodyBoundaries {
		boundaries = append(boundaries, 4+b)
	}
	for _, b := range extBoundaries {
		boundaries = append(boundaries, 4+prefixLen+2+b)
	}
	boundaries = append(boundaries, len(full))

	sniOffset := -1
	if sniOffsetInExt >= 0 {
		sniOffset = 4 + prefixLen + 2 + sniOffsetInExt
	}

	return full, sniOffset, sniLen, boundaries
}
