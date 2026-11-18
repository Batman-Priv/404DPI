package dpiproxy

import (
	"fmt"
	"net"
	"sort"
	"time"
)

type benchMethod struct {
	name       string
	method     string
	fakePacket bool
}

var benchMethods = []benchMethod{
	{name: "direct", method: ""},
	{name: "sni", method: "sni"},
	{name: "natural", method: "natural"},
	{name: "random", method: "random"},
	{name: "multi", method: "multi"},
	{name: "sni+fake-packet", method: "sni", fakePacket: true},
}

const benchTrialsPerMethod = 3

func runBenchmark(config *Config) {
	domains := config.ScanDomains
	if len(domains) == 0 {
		domains = defaultScanDomains
	}

	for _, domain := range domains {
		fmt.Printf("=== %s ===\n", domain)
		ips, err := net.LookupIP(domain)
		if err != nil || len(ips) == 0 {
			fmt.Printf("  DNS lookup failed: %v\n\n", err)
			continue
		}
		ip := ips[0].String()

		fmt.Printf("%-18s %-9s %-9s %-9s %-34s %-s\n", "Strategy", "Success", "Median", "Max", "JA3", "Shape")
		fmt.Println("--------------------------------------------------------------------------------------------")
		for _, m := range benchMethods {
			successes := 0
			var latencies []time.Duration
			var ja3 string
			shapeSignatures := map[string]bool{}
			for i := 0; i < benchTrialsPerMethod; i++ {
				start := time.Now()
				var r benchProbeResult
				if m.method == "" {
					ok := probeTLSStdlib(ip, domain, 5*time.Second).OK
					r = benchProbeResult{ok: ok}
				} else {
					r = probeFragmentedTLSMethod(ip, domain, 5*time.Second, m.method, config, m.fakePacket)
				}
				latencies = append(latencies, time.Since(start))
				if r.ok {
					successes++
				}
				if r.ja3 != "" {
					ja3 = r.ja3
				}
				if r.shapeSig != "" {
					shapeSignatures[r.shapeSig] = true
				}
			}
			sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
			median := latencies[len(latencies)/2]
			max := latencies[len(latencies)-1]
			successRate := 100 * successes / benchTrialsPerMethod

			shape := "-"
			if len(shapeSignatures) == 1 {
				shape = "constant (fingerprintable)"
			} else if len(shapeSignatures) > 1 {
				shape = fmt.Sprintf("varied (%d/%d unique)", len(shapeSignatures), benchTrialsPerMethod)
			}
			if ja3 == "" {
				ja3 = "-"
			}

			fmt.Printf("%-18s %-9s %-9s %-9s %-34s %-s\n", m.name, fmt.Sprintf("%d%%", successRate),
				median.Round(time.Millisecond), max.Round(time.Millisecond), ja3, shape)
		}
		fmt.Println()
	}
}

type benchProbeResult struct {
	ok       bool
	ja3      string
	shapeSig string
}

func probeFragmentedTLSMethod(ip, sni string, timeout time.Duration, method string, config *Config, useFakePacket bool) benchProbeResult {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), timeout)
	if err != nil {
		return benchProbeResult{ok: false}
	}
	defer conn.Close()
	setNoDelay(conn)

	version := [2]byte{0x03, 0x03}
	chRaw := buildProbeClientHello(sni)

	if useFakePacket {
		sendFakeClientHellos(conn, version, config)
	}

	ch, err := parseClientHello(chRaw)
	if err != nil {
		return benchProbeResult{ok: false}
	}

	if config.TLSGrease {
		applyGrease(ch)
	}
	if config.ECHGrease {
		applyECHGrease(ch)
	}
	if config.TLSPadding > 0 {
		applyPadding(ch, config.TLSPadding)
	}
	if config.TLSProfile != "" {
		applyTLSProfile(ch, config.TLSProfile)
	} else if config.TLSShuffle {
		shuffleClientHello(ch)
	}

	ja3 := ja3Hash(ch)
	full, sniOffset, sniLen, _ := serializeClientHello(ch)

	var chunks [][]byte
	switch method {
	case "random":
		chunks = chunkData(full, 8, 24)
	case "natural":
		chunks = chunkDataNatural(full, newNaturalProfile())
	case "multi":
		chunks = chunkDataFib(full)
	default:
		chunks = splitForProbe(full, sniOffset, sniLen)
	}
	shapeSig := chunkShapeSignature(chunks)

	for _, chunk := range chunks {
		record := buildTLSRecord(version, chunk)
		conn.SetWriteDeadline(time.Now().Add(timeout))
		if _, err := conn.Write(record); err != nil {
			return benchProbeResult{ok: false, ja3: ja3, shapeSig: shapeSig}
		}
		time.Sleep(3 * time.Millisecond)
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, rerr := conn.Read(buf)
	_ = time.Since(start)
	ok := rerr == nil && n > 0 && looksLikeHandshake(buf[:n])
	return benchProbeResult{ok: ok, ja3: ja3, shapeSig: shapeSig}
}

func chunkShapeSignature(chunks [][]byte) string {
	sig := ""
	for i, c := range chunks {
		if i > 0 {
			sig += "-"
		}
		sig += fmt.Sprintf("%d", len(c))
	}
	return sig
}
