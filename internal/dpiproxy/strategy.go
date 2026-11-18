package dpiproxy

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"
)

type FragmentStrategy struct {
	Name          string
	Method        string
	FakeSNI       string
	SplitAfterSNI bool
	FakePacket    bool
	Raw           bool
}

type chParseResult struct {
	ok                bool
	clientHello       []byte
	version           [2]byte
	leftoverHandshake []byte
	extraRecords      []byte
	nonTLS            bool
	tooLarge          bool
	raw               []byte
	err               error
}

func (s *ProxyServer) readClientHelloFromClient(client net.Conn, reader *bufio.Reader) chParseResult {
	var recordBuf []byte
	var handshakeBuf []byte
	var version [2]byte
	haveVersion := false
	var extraRecords []byte
	readBuf := make([]byte, 8192)

	for {
		if s.config.Timeout > 0 {
			client.SetReadDeadline(time.Now().Add(time.Duration(s.config.Timeout) * time.Second))
		}
		n, err := reader.Read(readBuf)
		if err != nil {
			return chParseResult{err: err, raw: recordBuf}
		}
		recordBuf = append(recordBuf, readBuf[:n]...)

		if len(recordBuf)+len(handshakeBuf) > 262144 {
			raw := append([]byte{}, handshakeBuf...)
			raw = append(raw, recordBuf...)
			return chParseResult{tooLarge: true, raw: raw}
		}

		for len(recordBuf) >= 5 {
			recordType := recordBuf[0]
			recordLen := int(recordBuf[3])<<8 | int(recordBuf[4])
			total := 5 + recordLen
			if len(recordBuf) < total {
				break
			}
			record := recordBuf[:total]
			recordBuf = recordBuf[total:]

			if recordType != 0x16 || record[1] != 0x03 {
				if !haveVersion {
					raw := append([]byte{}, record...)
					raw = append(raw, recordBuf...)
					return chParseResult{nonTLS: true, raw: raw}
				}
				extraRecords = append(extraRecords, record...)
				continue
			}

			if !haveVersion {
				version[0] = record[1]
				version[1] = record[2]
				haveVersion = true
			}
			handshakeBuf = append(handshakeBuf, record[5:]...)
		}

		if len(handshakeBuf) >= 4 {
			hlen := int(handshakeBuf[1])<<16 | int(handshakeBuf[2])<<8 | int(handshakeBuf[3])
			need := 4 + hlen
			if len(handshakeBuf) >= need {
				return chParseResult{
					ok:                true,
					clientHello:       append([]byte{}, handshakeBuf[:need]...),
					version:           version,
					leftoverHandshake: append([]byte{}, handshakeBuf[need:]...),
					extraRecords:      append(extraRecords, recordBuf...),
				}
			}
		}
	}
}

func (s *ProxyServer) defaultEscalation(domain string) []FragmentStrategy {
	method, _, _, _, fakeSNI, splitAfter := s.config.resolvedFragmentSettings(domain)
	if method == "" {
		method = "sni"
	}

	decoy := s.config.FakePacket

	list := []FragmentStrategy{
		{Name: method, Method: method, FakeSNI: fakeSNI, SplitAfterSNI: splitAfter, FakePacket: decoy},
	}

	for _, alt := range []string{"sni", "natural", "random", "multi"} {
		if alt == method {
			continue
		}
		list = append(list, FragmentStrategy{Name: alt, Method: alt, FakeSNI: fakeSNI, SplitAfterSNI: splitAfter, FakePacket: decoy})
	}

	list = append(list, FragmentStrategy{
		Name: "last-resort", Method: "multi", SplitAfterSNI: splitAfter, FakePacket: decoy,
	})

	list = append(list, FragmentStrategy{Name: "plain", Method: "none"})

	return list
}

func (s *ProxyServer) connectAndFragment(client net.Conn, host string, port int, reader *bufio.Reader, firstConn net.Conn) (net.Conn, []byte, error) {
	res := s.readClientHelloFromClient(client, reader)
	if res.err != nil {
		return nil, nil, res.err
	}
	if !res.ok {
		if len(res.raw) > 0 {
			if _, err := firstConn.Write(res.raw); err != nil {
				return nil, nil, err
			}
		}
		return firstConn, nil, nil
	}

	cacheKey := host
	if sni := extractSNI(res.clientHello); sni != "" {
		cacheKey = sni
	}
	cacheKeyLower := strings.ToLower(cacheKey)

	var cached *StrategyRecord
	if v, ok := s.stratCache.Load(domainToken(s.config, cacheKeyLower)); ok {
		cached = v.(*StrategyRecord)
	}

	var strategies []FragmentStrategy
	if s.config.Adaptive {
		if cached != nil {
			strategies = append(strategies, cached.current())
		}
		strategies = append(strategies, s.defaultEscalation(cacheKey)...)
	} else {
		method, _, _, _, fakeSNI, splitAfter := s.config.resolvedFragmentSettings(cacheKey)
		strategies = append(strategies, FragmentStrategy{Name: method, Method: method, FakeSNI: fakeSNI, SplitAfterSNI: splitAfter, FakePacket: s.config.FakePacket})
	}

	if s.config.Adaptive && s.config.RaceStrategies && len(strategies) > 1 {
		conf := 0.0
		if cached != nil {
			conf = cached.Confidence()
		}
		if conf < confidenceHigh {
			maxRacers := 3
			if cached != nil && conf >= confidenceLow {
				maxRacers = 2
			}
			return s.connectAndFragmentRace(host, cacheKey, port, res, firstConn, strategies, maxRacers)
		}
	}

	var lastErr error
	for i, strat := range strategies {
		var remote net.Conn
		var err error
		if i == 0 {
			remote = firstConn
		} else {
			remote, err = s.dialTarget(host, port)
			if err != nil {
				lastErr = err
				continue
			}
		}

		setNoDelay(remote)

		if strat.FakePacket {
			sendFakeClientHellos(remote, res.version, s.config)
		}

		s.sendFragmented(remote, res, strat)

		if len(res.leftoverHandshake) > 0 {
			s.wrapAndSend(remote, res.version, res.leftoverHandshake)
		}
		if len(res.extraRecords) > 0 {
			if _, werr := remote.Write(res.extraRecords); werr != nil {
				lastErr = werr
				remote.Close()
				s.recordStrategyResult(cacheKeyLower, strat, false)
				continue
			}
		}

		if !s.config.Adaptive {
			return remote, nil, nil
		}

		remote.SetReadDeadline(time.Now().Add(4 * time.Second))
		peek := make([]byte, 512)
		n, rerr := remote.Read(peek)
		remote.SetReadDeadline(time.Time{})
		success := rerr == nil && n > 0 && looksLikeHandshake(peek[:n])
		s.recordStrategyResult(cacheKeyLower, strat, success)
		if success {
			return remote, peek[:n], nil
		}

		if rerr == nil && n > 0 {
			lastErr = fmt.Errorf("got a response but it wasn't a TLS handshake (likely an Alert - something rejected the attempt)")
		} else {
			lastErr = rerr
		}
		remote.Close()
		if s.errorLog != nil {
			s.errorLog.Printf("strategy %q failed for %s (attempt %d/%d): %v", strat.Name, domainToken(s.config, host), i+1, len(strategies), lastErr)
		}
	}

	return nil, nil, fmt.Errorf("all fragmentation strategies failed for %s: %v", host, lastErr)
}

func (s *ProxyServer) recordStrategyResult(cacheKeyLower string, strat FragmentStrategy, success bool) {
	key := domainToken(s.config, cacheKeyLower)
	v, _ := s.stratCache.LoadOrStore(key, newStrategyRecord(strat))
	v.(*StrategyRecord).record(strat, success)
}

func locateSNI(raw []byte) (offset, length int) {
	ch, err := parseClientHello(raw)
	if err != nil {
		return -1, 0
	}
	if re, off, l, _ := serializeClientHello(ch); off >= 0 && bytes.Equal(re, raw) {
		return off, l
	}

	if sni := extractSNI(raw); sni != "" {
		if i := bytes.Index(raw, []byte(sni)); i >= 0 {
			return i, len(sni)
		}
	}
	return -1, 0
}

func (s *ProxyServer) sendFragmented(remote net.Conn, res chParseResult, strat FragmentStrategy) {
	raw := res.clientHello
	if len(raw) < 4 || raw[0] != 0x01 {
		s.wrapAndSend(remote, res.version, raw)
		return
	}

	full := raw
	var sniOffset, sniLen int
	fakeSNI := s.config.pickFakeSNI(strat.FakeSNI)
	if strat.Method != "none" && !strat.Raw && (s.config.mutatesClientHello() || fakeSNI != "") {
		ch, err := parseClientHello(raw)
		if err != nil {
			s.wrapAndSend(remote, res.version, raw)
			return
		}
		if fakeSNI != "" {
			for i := range ch.Extensions {
				if ch.Extensions[i].Type == 0 {
					ch.Extensions[i].Data = buildServerNameExtensionData(fakeSNI)
				}
			}
		}
		if s.config.TLSGrease {
			applyGrease(ch)
		}
		if s.config.ECHGrease {
			applyECHGrease(ch)
		}
		if s.config.TLSPadding > 0 {
			applyPadding(ch, s.config.TLSPadding)
		}
		if s.config.TLSProfile != "" {
			applyTLSProfile(ch, s.config.TLSProfile)
		} else if s.config.TLSShuffle {
			shuffleClientHello(ch)
		}
		full, sniOffset, sniLen, _ = serializeClientHello(ch)
	} else {
		sniOffset, sniLen = locateSNI(raw)
	}

	var chunks [][]byte
	switch strat.Method {
	case "random":
		chunks = chunkData(full, s.config.FragmentMin, s.config.FragmentMax)
	case "multi":
		chunks = chunkDataFib(full)
	case "natural":
		chunks = chunkDataNatural(full, newNaturalProfile())
	case "none":
		chunks = [][]byte{full}
	default:
		if sniOffset > 0 && sniLen > 0 && sniOffset+sniLen <= len(full) {
			splitPoint := sniOffset
			if strat.SplitAfterSNI {
				splitPoint = sniOffset + sniLen
			}
			var c [][]byte
			if splitPoint > 0 {
				c = append(c, full[:splitPoint])
			}
			c = append(c, chunkData(full[splitPoint:], s.config.FragmentMin, s.config.FragmentMax)...)
			chunks = c
		} else {
			chunks = chunkData(full, s.config.FragmentMin, s.config.FragmentMax)
		}
	}

	for i, chunk := range chunks {
		if len(chunk) == 0 {
			continue
		}
		if s.config.Timeout > 0 {
			remote.SetWriteDeadline(time.Now().Add(time.Duration(s.config.Timeout) * time.Second))
		}
		record := make([]byte, 5+len(chunk))
		record[0] = 0x16
		record[1] = res.version[0]
		record[2] = res.version[1]
		record[3] = byte(len(chunk) >> 8)
		record[4] = byte(len(chunk))
		copy(record[5:], chunk)

		if _, err := remote.Write(record); err != nil {
			return
		}
		if i < len(chunks)-1 {
			if strat.Method == "natural" {
				maxMS := s.config.FragmentDelay + s.config.FragmentJitter
				if maxMS <= 0 {
					maxMS = 12
				}
				if d := naturalDelay(maxMS); d > 0 {
					time.Sleep(d)
				}
			} else if s.config.FragmentDelay > 0 || s.config.FragmentJitter > 0 {
				delay := s.config.FragmentDelay
				if s.config.FragmentJitter > 0 {
					delay += randIntN(s.config.FragmentJitter)
				}
				if delay > 0 {
					time.Sleep(time.Duration(delay) * time.Millisecond)
				}
			}
		}
	}
}

type raceResult struct {
	remote net.Conn
	peek   []byte
	strat  FragmentStrategy
	err    error
}

func (s *ProxyServer) connectAndFragmentRace(host, cacheKey string, port int, res chParseResult, firstConn net.Conn, strategies []FragmentStrategy, maxRacers int) (net.Conn, []byte, error) {
	n := len(strategies)
	if n > maxRacers {
		n = maxRacers
	}

	resultCh := make(chan raceResult, n)

	for i := 0; i < n; i++ {
		strat := strategies[i]
		var seed net.Conn
		if i == 0 {
			seed = firstConn
		}
		go func(strat FragmentStrategy, remote net.Conn) {
			if remote == nil {
				dialed, err := s.dialTarget(host, port)
				if err != nil {
					resultCh <- raceResult{err: err}
					return
				}
				remote = dialed
			}

			setNoDelay(remote)
			resultCh <- s.tryStrategy(remote, host, cacheKey, strat, res)
		}(strat, seed)
	}

	var lastErr error
	for i := 0; i < n; i++ {
		r := <-resultCh
		if r.err == nil {
			remaining := n - i - 1
			if remaining > 0 {
				go func(count int) {
					for j := 0; j < count; j++ {
						rr := <-resultCh
						if rr.remote != nil {
							rr.remote.Close()
						}
					}
				}(remaining)
			}

			return r.remote, r.peek, nil
		}
		lastErr = r.err
	}

	return nil, nil, fmt.Errorf("all raced strategies failed for %s: %v", host, lastErr)
}

func (s *ProxyServer) tryStrategy(remote net.Conn, host, cacheKey string, strat FragmentStrategy, res chParseResult) raceResult {
	if remote == nil {
		return raceResult{err: fmt.Errorf("no connection")}
	}

	if strat.FakePacket {
		sendFakeClientHellos(remote, res.version, s.config)
	}
	s.sendFragmented(remote, res, strat)
	if len(res.leftoverHandshake) > 0 {
		s.wrapAndSend(remote, res.version, res.leftoverHandshake)
	}
	if len(res.extraRecords) > 0 {
		if _, werr := remote.Write(res.extraRecords); werr != nil {
			remote.Close()
			s.recordStrategyResult(strings.ToLower(cacheKey), strat, false)
			return raceResult{err: werr}
		}
	}

	remote.SetReadDeadline(time.Now().Add(4 * time.Second))
	peek := make([]byte, 512)
	n, rerr := remote.Read(peek)
	remote.SetReadDeadline(time.Time{})
	success := rerr == nil && n > 0 && looksLikeHandshake(peek[:n])
	s.recordStrategyResult(strings.ToLower(cacheKey), strat, success)
	if !success {
		remote.Close()
		if rerr == nil {
			rerr = fmt.Errorf("response wasn't a TLS handshake")
		}
		return raceResult{err: rerr}
	}
	return raceResult{remote: remote, peek: peek[:n], strat: strat}
}
