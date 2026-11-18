package dpiproxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"log"
	"sync"
	"time"
)

var quicV1InitialSalt = mustHex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

func mustHex(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		hi := hexNibble(s[i*2])
		lo := hexNibble(s[i*2+1])
		b[i] = hi<<4 | lo
	}
	return b
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func hkdfExtract(salt, ikm []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	var out []byte
	var t []byte
	counter := byte(1)
	for len(out) < length {
		mac := hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		out = append(out, t...)
		counter++
	}
	return out[:length]
}

func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	fullLabel := append([]byte("tls13 "), label...)
	info := make([]byte, 0, 2+1+len(fullLabel)+1+len(context))
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	return hkdfExpand(secret, info, length)
}

type quicInitialKeys struct {
	key []byte
	iv  []byte
	hp  []byte
}

func deriveClientInitialKeys(dcid []byte) quicInitialKeys {
	initialSecret := hkdfExtract(quicV1InitialSalt, dcid)
	clientInitialSecret := hkdfExpandLabel(initialSecret, "client in", nil, 32)
	return quicInitialKeys{
		key: hkdfExpandLabel(clientInitialSecret, "quic key", nil, 16),
		iv:  hkdfExpandLabel(clientInitialSecret, "quic iv", nil, 12),
		hp:  hkdfExpandLabel(clientInitialSecret, "quic hp", nil, 16),
	}
}

func headerProtectionMask(hpKey, sample []byte) ([]byte, error) {
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return nil, err
	}
	if len(sample) != block.BlockSize() {
		return nil, fmt.Errorf("quic: bad hp sample length %d", len(sample))
	}
	mask := make([]byte, block.BlockSize())
	block.Encrypt(mask, sample)
	return mask, nil
}

func buildNonce(iv []byte, packetNumber uint64) []byte {
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for i := 0; i < 8 && i < len(nonce); i++ {
		nonce[len(nonce)-1-i] ^= byte(packetNumber >> (8 * i))
	}
	return nonce
}

func readVarint(buf []byte, pos int) (uint64, int, bool) {
	if pos >= len(buf) {
		return 0, pos, false
	}
	first := buf[pos]
	length := 1 << (first >> 6)
	if pos+length > len(buf) {
		return 0, pos, false
	}
	v := uint64(first & 0x3f)
	for i := 1; i < length; i++ {
		v = v<<8 | uint64(buf[pos+i])
	}
	return v, pos + length, true
}

type quicClientInitial struct {
	dcid          []byte
	pnOffset      int
	packetEnd     int
	firstByteMask byte
}

func parseQUICLongHeaderInitial(packet []byte) (*quicClientInitial, error) {
	if len(packet) < 7 {
		return nil, fmt.Errorf("quic: packet too short")
	}
	if packet[0]&0x80 == 0 {
		return nil, fmt.Errorf("quic: not a long header packet")
	}

	if (packet[0]>>4)&0x03 != 0x00 {
		return nil, fmt.Errorf("quic: not an Initial packet")
	}
	version := uint32(packet[1])<<24 | uint32(packet[2])<<16 | uint32(packet[3])<<8 | uint32(packet[4])
	if version != 1 {
		return nil, fmt.Errorf("quic: unsupported version 0x%08x", version)
	}

	pos := 5
	dcidLen := int(packet[pos])
	pos++
	if dcidLen > 20 || pos+dcidLen > len(packet) {
		return nil, fmt.Errorf("quic: bad DCID length")
	}
	dcid := append([]byte(nil), packet[pos:pos+dcidLen]...)
	pos += dcidLen

	if pos >= len(packet) {
		return nil, fmt.Errorf("quic: truncated after DCID")
	}
	scidLen := int(packet[pos])
	pos++
	if scidLen > 20 || pos+scidLen > len(packet) {
		return nil, fmt.Errorf("quic: bad SCID length")
	}
	pos += scidLen

	tokenLen, newPos, ok := readVarint(packet, pos)
	if !ok || tokenLen > uint64(len(packet)) || newPos+int(tokenLen) > len(packet) {
		return nil, fmt.Errorf("quic: bad token length")
	}
	pos = newPos + int(tokenLen)

	lengthVal, newPos, ok := readVarint(packet, pos)
	if !ok {
		return nil, fmt.Errorf("quic: bad length varint")
	}
	pos = newPos

	pnOffset := pos
	if lengthVal > uint64(len(packet)) {
		return nil, fmt.Errorf("quic: declared length exceeds datagram")
	}
	packetEnd := pnOffset + int(lengthVal)
	if packetEnd > len(packet) {
		return nil, fmt.Errorf("quic: declared length exceeds datagram")
	}

	if pnOffset+4+16 > packetEnd {
		return nil, fmt.Errorf("quic: packet too short for header protection sample")
	}

	return &quicClientInitial{dcid: dcid, pnOffset: pnOffset, packetEnd: packetEnd}, nil
}

func decryptQUICClientInitial(packet []byte) (plaintext []byte, sni string, err error) {
	hdr, err := parseQUICLongHeaderInitial(packet)
	if err != nil {
		return nil, "", err
	}
	keys := deriveClientInitialKeys(hdr.dcid)

	buf := append([]byte(nil), packet[:hdr.packetEnd]...)

	sampleOffset := hdr.pnOffset + 4
	sample := buf[sampleOffset : sampleOffset+16]
	mask, err := headerProtectionMask(keys.hp, sample)
	if err != nil {
		return nil, "", err
	}

	buf[0] ^= mask[0] & 0x0f
	pnLen := int(buf[0]&0x03) + 1

	packetNumber := uint64(0)
	for i := 0; i < pnLen; i++ {
		buf[hdr.pnOffset+i] ^= mask[1+i]
		packetNumber = packetNumber<<8 | uint64(buf[hdr.pnOffset+i])
	}

	if hdr.pnOffset+pnLen > hdr.packetEnd {
		return nil, "", fmt.Errorf("quic: packet number runs past the packet")
	}
	aad := buf[:hdr.pnOffset+pnLen]
	ciphertext := buf[hdr.pnOffset+pnLen : hdr.packetEnd]
	if len(ciphertext) < 16 {
		return nil, "", fmt.Errorf("quic: ciphertext shorter than AEAD tag")
	}

	block, err := aes.NewCipher(keys.key)
	if err != nil {
		return nil, "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", err
	}
	nonce := buildNonce(keys.iv, packetNumber)

	plaintext, err = aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, "", fmt.Errorf("quic: AEAD open failed: %w", err)
	}

	sni = extractSNIFromQUICFrames(plaintext)
	return plaintext, sni, nil
}

const maxQUICCryptoSpan = 1 << 16

func extractSNIFromQUICFrames(plaintext []byte) string {
	type chunk struct {
		offset int
		data   []byte
	}
	var chunks []chunk

	pos := 0
	for pos < len(plaintext) {
		frameType := plaintext[pos]
		switch frameType {
		case 0x00:
			pos++
		case 0x01:
			pos++
		case 0x06:
			pos++
			off, newPos, ok := readVarint(plaintext, pos)
			if !ok {
				return ""
			}
			pos = newPos
			length, newPos, ok := readVarint(plaintext, pos)
			if !ok {
				return ""
			}
			pos = newPos

			if off > maxQUICCryptoSpan || length > maxQUICCryptoSpan || off+length > maxQUICCryptoSpan {
				return ""
			}
			if pos+int(length) > len(plaintext) {
				return ""
			}
			chunks = append(chunks, chunk{offset: int(off), data: plaintext[pos : pos+int(length)]})
			pos += int(length)
		case 0x02, 0x03:

			return ""
		default:

			return ""
		}
	}

	if len(chunks) == 0 {
		return ""
	}

	total := 0
	for _, c := range chunks {
		if end := c.offset + len(c.data); end > total {
			total = end
		}
	}
	reassembled := make([]byte, total)
	covered := make([]bool, total)
	for _, c := range chunks {
		copy(reassembled[c.offset:], c.data)
		for i := c.offset; i < c.offset+len(c.data); i++ {
			covered[i] = true
		}
	}

	if total < 4 || !covered[0] {
		return ""
	}
	claimedLen := int(reassembled[1])<<16 | int(reassembled[2])<<8 | int(reassembled[3])
	need := 4 + claimedLen
	if need > total {
		return ""
	}
	for i := 0; i < need; i++ {
		if !covered[i] {
			return ""
		}
	}
	return extractSNI(reassembled[:need])
}

type quicSNIEntry struct {
	When time.Time
	Host string
	SNI  string
}

var (
	recentQUICSNIMu  sync.Mutex
	recentQUICSNIBuf [50]quicSNIEntry
	recentQUICSNIPos int
	recentQUICSNILen int
)

func recordRecentQUICSNI(host, sni string) {
	recentQUICSNIMu.Lock()
	defer recentQUICSNIMu.Unlock()
	recentQUICSNIBuf[recentQUICSNIPos] = quicSNIEntry{When: time.Now(), Host: host, SNI: sni}
	recentQUICSNIPos = (recentQUICSNIPos + 1) % len(recentQUICSNIBuf)
	if recentQUICSNILen < len(recentQUICSNIBuf) {
		recentQUICSNILen++
	}
}

func recentQUICSNISnapshot() []quicSNIEntry {
	recentQUICSNIMu.Lock()
	defer recentQUICSNIMu.Unlock()
	out := make([]quicSNIEntry, 0, recentQUICSNILen)
	for i := 0; i < recentQUICSNILen; i++ {
		idx := (recentQUICSNIPos - 1 - i + len(recentQUICSNIBuf)) % len(recentQUICSNIBuf)
		out = append(out, recentQUICSNIBuf[idx])
	}
	return out
}

func inspectQUICInitial(config *Config, remoteHost string, packet []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[WARN] recovered panic while inspecting QUIC Initial toward %s: %v", domainToken(config, remoteHost), r)
		}
	}()
	_, sni, err := decryptQUICClientInitial(packet)
	if err != nil || sni == "" {
		return
	}
	hostTok := domainToken(config, remoteHost)
	sniTok := domainToken(config, sni)
	recordRecentQUICSNI(hostTok, sniTok)
	if remoteHost != "" && sni != remoteHost {
		log.Printf("quic: %s -> Initial ClientHello SNI=%q (SOCKS5 target was %q)", hostTok, sniTok, hostTok)
	} else {
		log.Printf("quic: Initial ClientHello SNI=%q", sniTok)
	}
}
