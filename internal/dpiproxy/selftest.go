package dpiproxy

import (
	"fmt"
	"net"
	"time"
)

type selftestCheck struct {
	name string
	ok   bool
	note string
}

func runSelftest(config *Config) int {
	var checks []selftestCheck

	checks = append(checks, checkTCPListen(config))
	checks = append(checks, checkDNS())
	checks = append(checks, checkIPv6())
	if config.EnableDoH || config.DoHServer != "" {
		checks = append(checks, checkDoH(config.DoHServer))
	}
	checks = append(checks, checkTTLSockopt())
	checks = append(checks, checkRawFake())
	checks = append(checks, checkClientHelloParse())
	checks = append(checks, checkTransparentSupport())

	fmt.Println("=== Runtime environment self-test ===")
	allOK := true
	for _, c := range checks {
		mark := "✓"
		if !c.ok {
			mark = "✗"
			allOK = false
		}
		if c.note != "" {
			fmt.Printf("%s %-22s %s\n", mark, c.name, c.note)
		} else {
			fmt.Printf("%s %-22s\n", mark, c.name)
		}
	}

	if allOK {
		fmt.Println("\nEverything is ready.")
		return 0
	}
	fmt.Println("\nSome features are unavailable (see above) - the program will still run, but those specific features are limited.")
	return 1
}

func checkTCPListen(config *Config) selftestCheck {
	addr := fmt.Sprintf("%s:0", config.Host)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return selftestCheck{name: "TCP listen", ok: false, note: err.Error()}
	}
	ln.Close()
	return selftestCheck{name: "TCP listen", ok: true}
}

func checkDNS() selftestCheck {
	_, err := net.LookupHost("www.google.com")
	if err != nil {
		return selftestCheck{name: "System DNS", ok: false, note: err.Error()}
	}
	return selftestCheck{name: "System DNS", ok: true}
}

func checkIPv6() selftestCheck {
	conn, err := net.DialTimeout("tcp6", "[2606:4700:4700::1111]:443", 3*time.Second)
	if err != nil {
		return selftestCheck{name: "IPv6 connectivity", ok: false, note: "no IPv6 route (fake-packet/TTL trick over IPv6 won't be usable)"}
	}
	conn.Close()
	return selftestCheck{name: "IPv6 connectivity", ok: true}
}

func checkDoH(server string) selftestCheck {
	d := NewDoHResolver(server, false, true)
	_, err := d.Resolve("www.google.com")
	if err != nil {
		return selftestCheck{name: "DoH (" + server + ")", ok: false, note: err.Error()}
	}
	return selftestCheck{name: "DoH (" + server + ")", ok: true}
}

func checkTTLSockopt() selftestCheck {
	conn, err := net.DialTimeout("tcp", "1.1.1.1:443", 3*time.Second)
	if err != nil {
		return selftestCheck{name: "TTL/HopLimit sockopt", ok: false, note: "couldn't test - no connectivity"}
	}
	defer conn.Close()
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return selftestCheck{name: "TTL/HopLimit sockopt", ok: false}
	}
	if err := setConnTTL(tc, 32); err != nil {
		return selftestCheck{name: "TTL/HopLimit sockopt", ok: false, note: err.Error()}
	}
	return selftestCheck{name: "TTL/HopLimit sockopt", ok: true}
}

func checkRawFake() selftestCheck {
	if err := rawFakeAvailable(); err != nil {
		return selftestCheck{name: "Fake packets (raw)", ok: false, note: err.Error()}
	}
	return selftestCheck{name: "Fake packets (raw)", ok: true}
}

func checkClientHelloParse() selftestCheck {
	raw := buildProbeClientHello("example.com")
	if _, err := parseClientHello(raw); err != nil {
		return selftestCheck{name: "ClientHello parser", ok: false, note: err.Error()}
	}
	if sni := extractSNI(raw); sni != "example.com" {
		return selftestCheck{name: "ClientHello parser", ok: false, note: "SNI round-trip mismatch"}
	}
	return selftestCheck{name: "ClientHello parser", ok: true}
}

func checkTransparentSupport() selftestCheck {
	if isTransparentSupported() {
		return selftestCheck{name: "Transparent proxy", ok: true}
	}
	return selftestCheck{name: "Transparent proxy", ok: false, note: "not on this platform - see README for the Windows alternative"}
}
