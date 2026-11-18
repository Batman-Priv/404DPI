package dpiproxy

import "flag"

type flagAdapter struct {
	fs *flag.FlagSet
}

func (a *flagAdapter) Parse(args []string) {
	a.fs.Parse(args)
}

func registerFlags(config *Config, isWindows bool) *flagAdapter {
	fs := flag.CommandLine

	fs.StringVar(&config.ConfigFile, "config", config.ConfigFile, "Path to a config file (see README.md for format)")

	fs.StringVar(&config.Host, "host", config.Host, "Proxy host")
	fs.IntVar(&config.Port, "port", config.Port, "Proxy port")
	fs.StringVar(&config.OutHost, "out-host", config.OutHost, "Outgoing (upstream) proxy host")
	fs.IntVar(&config.OutPort, "out-port", config.OutPort, "Outgoing proxy port")
	fs.StringVar(&config.OutType, "out-type", config.OutType, "Outgoing proxy type (http/socks5; default socks5 when -out-host is set)")
	fs.StringVar(&config.OutUsername, "out-username", config.OutUsername, "Outgoing proxy username")
	fs.StringVar(&config.OutPassword, "out-password", config.OutPassword, "Outgoing proxy password")
	fs.StringVar(&config.BlacklistFile, "blacklist", config.BlacklistFile, "Blacklist file")
	fs.StringVar(&config.FragmentMethod, "fragment-method", config.FragmentMethod, "Fragment method (sni/natural/random/multi/none). natural uses a re-randomized size/timing mixture per connection instead of a fixed pattern - see fragshape.go")
	fs.StringVar(&config.DomainMatching, "domain-matching", config.DomainMatching, "Domain matching (strict/loose)")
	fs.StringVar(&config.LogAccess, "log-access", config.LogAccess, "Access log file")
	fs.StringVar(&config.LogError, "log-error", config.LogError, "Error log file")
	fs.BoolVar(&config.LogDomains, "log-domains", config.LogDomains, "Write real domain names to disk (access/error logs, the auto-blacklist file, the persisted strategy cache, and QUIC SNI logging). Default false: domains are stored as one-way tokens instead, so a copy of these files/logs on their own doesn't reveal what you visited. Turn this on only on a machine where you're fine with that history being in plaintext")
	fs.BoolVar(&config.NoBlacklist, "no-blacklist", config.NoBlacklist, "Disable the blacklist entirely (fragment everything)")
	fs.BoolVar(&config.AutoBlacklist, "autoblacklist", config.AutoBlacklist, "Learn which domains need bypassing instead of using a static list")
	fs.BoolVar(&config.Quiet, "quiet", config.Quiet, "Quiet mode (no live stats display)")
	fs.StringVar(&config.Username, "auth-username", config.Username, "Proxy username (Proxy-Authorization)")
	fs.StringVar(&config.Password, "auth-password", config.Password, "Proxy password")
	fs.IntVar(&config.FragmentDelay, "fragment-delay", config.FragmentDelay, "Delay between fragments in ms")
	fs.IntVar(&config.FragmentMin, "fragment-min", config.FragmentMin, "Minimum fragment size in bytes")
	fs.IntVar(&config.FragmentMax, "fragment-max", config.FragmentMax, "Maximum fragment size in bytes")
	fs.BoolVar(&config.SplitBeforeSNI, "split-before-sni", config.SplitBeforeSNI, "Split right before the SNI extension")
	fs.BoolVar(&config.SplitAfterSNI, "split-after-sni", config.SplitAfterSNI, "Split right after the SNI extension instead of before it")
	fs.StringVar(&config.FakeSNI, "fake-sni", config.FakeSNI, "Replace the outgoing SNI with this value")
	fs.StringVar(&config.FrontMapRaw, "front-map", config.FrontMapRaw, "Domain fronting: comma-separated real=front pairs. For a listed real domain 404DPI terminates the app's TLS locally (name-constrained local CA you must import, see -front-ca-dir) and opens its own TLS connection to the front: SNI=front, Host header unchanged. Needs a CDN that routes by Host header")
	fs.StringVar(&config.FrontCADir, "front-ca-dir", config.FrontCADir, "Directory of the local domain-fronting CA (import ca.pem into your trust store; keep ca-key.pem private)")
	fs.StringVar(&config.FrontUpstreamCA, "front-upstream-ca", config.FrontUpstreamCA, "Extra PEM CA bundle to trust when verifying the front (e.g. a private test CA)")
	fs.IntVar(&config.TTL, "ttl", config.TTL, "Set the outgoing IPv4 TTL for every packet on this connection (0 = OS default)")
	fs.BoolVar(&config.KeepAlive, "keep-alive", config.KeepAlive, "Enable TCP keep-alive")
	fs.IntVar(&config.BufferSize, "buffer-size", config.BufferSize, "Buffer size (bytes) used for piping traffic")
	fs.IntVar(&config.Timeout, "timeout", config.Timeout, "Connection timeout in seconds")

	fs.BoolVar(&config.EnableSocks5, "socks5", config.EnableSocks5, "Also start a SOCKS5 listener (CONNECT + UDP ASSOCIATE)")
	fs.IntVar(&config.Socks5Port, "socks5-port", config.Socks5Port, "SOCKS5 listener port")
	fs.StringVar(&config.Socks5Host, "socks5-host", config.Socks5Host, "SOCKS5 listener host")

	fs.BoolVar(&config.EnableDoH, "doh", config.EnableDoH, "Resolve target domains via DNS-over-HTTPS instead of the local/system resolver")
	fs.StringVar(&config.DoHServer, "doh-server", config.DoHServer, "DoH server URL(s), RFC 8484 wire format. Comma-separate several for failover, e.g. https://1.1.1.1/dns-query,https://8.8.8.8/dns-query - the first one that answers becomes sticky until it fails")
	fs.BoolVar(&config.DoHCache, "doh-cache", config.DoHCache, "Cache DoH answers in memory for their TTL")

	fs.BoolVar(&config.BlockQUIC, "block-quic", config.BlockQUIC, "Drop outbound UDP/443 in the SOCKS5 UDP relay to force clients back onto plain TLS (legacy alias for -quic-mode drop)")
	fs.StringVar(&config.QUICMode, "quic-mode", config.QUICMode, "How to handle outbound UDP/443 in the SOCKS5 UDP relay: off (forward untouched) / drop (block, forces TCP fallback) / delay (forward late+jittered, keeps QUIC working but breaks up its timing fingerprint) / inspect (decrypt+log the real SNI from Initial packets, forward unchanged - read-only). Overrides -block-quic when set.")
	fs.IntVar(&config.QUICDelay, "quic-delay", config.QUICDelay, "Base delay in ms used by -quic-mode delay (actual delay is randomized between this and 2x this)")

	fs.BoolVar(&config.FakePacket, "fake-packet", config.FakePacket, "Inject a forged decoy ClientHello segment (raw socket + TCP_REPAIR, Linux, needs root/CAP_NET_RAW+CAP_NET_ADMIN) that the DPI box sees but the server ignores, right before the real ClientHello; see -fake-method")
	fs.StringVar(&config.FakeMethod, "fake-method", config.FakeMethod, "How the decoy is hidden from the server: ttl, badsum, badseq, md5 (comma-separated to combine, e.g. ttl,badsum)")
	fs.IntVar(&config.FakePacketTTL, "fake-packet-ttl", config.FakePacketTTL, "TTL of the decoy when -fake-method includes ttl (must be just enough to pass the DPI box but not reach the server)")

	fs.BoolVar(&config.HTTPObfuscate, "http-obfuscate", config.HTTPObfuscate, "Mangle/split plain-HTTP Host headers to dodge naive literal pattern matching")

	fs.BoolVar(&config.Adaptive, "adaptive", config.Adaptive, "Retry a failing domain with different fragmentation strategies and remember whichever works")

	fs.BoolVar(&config.TLSGrease, "tls-grease", config.TLSGrease, "Add a random GREASE cipher suite/extension to the outgoing ClientHello")
	fs.BoolVar(&config.ECHGrease, "ech-grease", config.ECHGrease, "Add a GREASE \"encrypted_client_hello\" extension (RFC 9849 6.2) so the ClientHello is shaped like a modern ECH-capable browser's. NOT real ECH - the real SNI is still sent in the clear in this same ClientHello, this only affects shape/fingerprint")
	fs.IntVar(&config.TLSPadding, "tls-padding", config.TLSPadding, "Pad the ClientHello to at least N bytes (0 = disabled)")
	fs.BoolVar(&config.TLSShuffle, "tls-shuffle", config.TLSShuffle, "Randomize cipher-suite and extension order per connection (evades static TLS/JA3 fingerprint matching)")
	fs.StringVar(&config.TLSProfile, "tls-profile", config.TLSProfile, "Reorder cipher suites/extensions to match a coherent browser-like pattern instead of random: chrome / firefox / safari / edge (takes priority over -tls-shuffle if both set)")

	fs.StringVar(&config.FakeSNIPoolRaw, "fake-sni-pool", config.FakeSNIPoolRaw, "Comma-separated list of decoy SNI values to rotate through randomly (instead of one fixed -fake-sni)")
	fs.IntVar(&config.FakePacketCount, "fake-packet-count", config.FakePacketCount, "Number of decoy segments to send before the real ClientHello (with the ttl method each one gets a TTL one higher than the previous: a \"TTL ladder\")")
	fs.IntVar(&config.FragmentJitter, "fragment-jitter", config.FragmentJitter, "Extra random 0..N ms added on top of -fragment-delay for each fragment, to avoid a fixed timing pattern")
	fs.BoolVar(&config.RaceStrategies, "race-strategies", config.RaceStrategies, "Try several fragmentation strategies in parallel and keep whichever responds first (faster than sequential retries, more sockets used)")

	fs.BoolVar(&config.Scan, "scan", config.Scan, "Run network diagnostics (DPI/censorship detection) against a list of domains and exit, without starting the proxy")
	fs.StringVar(&config.ScanDomainsRaw, "scan-domains", config.ScanDomainsRaw, "Comma-separated domains to test with -scan (default: a small built-in list)")

	fs.StringVar(&config.Preset, "preset", config.Preset, "Apply a bundle of settings: safe / aggressive / stealth / vpn-like (individual flags still override)")

	fs.BoolVar(&config.EnableTransparent, "transparent", config.EnableTransparent, "Start a transparent-proxy listener (Linux only) for use with an iptables REDIRECT rule - see README")
	fs.StringVar(&config.TransparentHost, "transparent-host", config.TransparentHost, "Transparent listener bind host")
	fs.IntVar(&config.TransparentPort, "transparent-port", config.TransparentPort, "Transparent listener port (must match your iptables REDIRECT rule)")

	fs.BoolVar(&config.TCPFastOpen, "tcp-fastopen", config.TCPFastOpen, "Request TCP Fast Open on outgoing connections (Linux only; needs tcp_fastopen enabled in the kernel, and has no effect on the very first connection to a given server)")
	fs.IntVar(&config.TCPMSS, "tcp-mss", config.TCPMSS, "Clamp outgoing TCP MSS to N bytes so the kernel itself fragments packets (Linux only, 0 = disabled)")

	fs.StringVar(&config.StrategyCacheFile, "strategy-cache-file", config.StrategyCacheFile, "Where to persist the learned per-domain fragmentation strategy across restarts (empty = disabled)")

	fs.BoolVar(&config.StatsHTTP, "stats-http", config.StatsHTTP, "Serve a local JSON stats page (127.0.0.1 only, regardless of -host)")
	fs.IntVar(&config.StatsPort, "stats-port", config.StatsPort, "Port for -stats-http")

	fs.StringVar(&config.HostsFile, "hosts-file", config.HostsFile, "/etc/hosts-format file (IP domain per line) checked before any DNS/DoH lookup - useful when DNS itself is blocked but you already know the real IP")
	fs.IntVar(&config.MaxConnections, "max-connections", config.MaxConnections, "Reject new connections past this many concurrent ones across all listeners (0 = unlimited) - a simple bound on worst-case resource use")

	fs.BoolVar(&config.Benchmark, "benchmark", config.Benchmark, "Measure success rate/latency of each fragmentation method against -scan-domains and exit, without starting the proxy")
	fs.BoolVar(&config.Selftest, "selftest", config.Selftest, "Run local environment capability checks and exit (exit code 0 = all OK) - useful in CI/scripts")

	if isWindows {
		fs.BoolVar(&config.Quiet, "q", config.Quiet, "Quiet mode (shorthand)")
	}

	return &flagAdapter{fs: fs}
}
