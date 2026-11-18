package dpiproxy

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

type Config struct {
	Host            string
	Port            int
	OutHost         string
	OutPort         int
	OutType         string
	OutUsername     string
	OutPassword     string
	BlacklistFile   string
	FragmentMethod  string
	DomainMatching  string
	LogAccess       string
	LogError        string
	LogDomains      bool
	NoBlacklist     bool
	AutoBlacklist   bool
	Quiet           bool
	Username        string
	Password        string
	FragmentDelay   int
	FragmentMin     int
	FragmentMax     int
	SplitBeforeSNI  bool
	SplitAfterSNI   bool
	FakeSNI         string
	FrontMapRaw     string
	FrontMap        map[string]string
	FrontCADir      string
	FrontUpstreamCA string
	TTL             int
	KeepAlive       bool
	BufferSize      int
	Timeout         int

	ConfigFile string

	EnableSocks5 bool
	Socks5Port   int
	Socks5Host   string

	EnableDoH bool
	DoHServer string
	DoHCache  bool

	BlockQUIC bool
	QUICMode  string
	QUICDelay int

	FakePacket    bool
	FakePacketTTL int
	FakeMethod    string

	HTTPObfuscate bool

	Adaptive bool

	TLSGrease  bool
	ECHGrease  bool
	TLSPadding int

	TLSShuffle bool
	TLSProfile string

	FakeSNIPoolRaw string
	FakeSNIPool    []string

	FakePacketCount int
	FragmentJitter  int

	RaceStrategies bool

	Scan           bool
	ScanDomainsRaw string
	ScanDomains    []string

	Preset string

	EnableTransparent bool
	TransparentHost   string
	TransparentPort   int

	TCPFastOpen bool
	TCPMSS      int

	StrategyCacheFile string

	StatsHTTP bool
	StatsPort int

	HostsFile string

	MaxConnections int

	Benchmark bool
	Selftest  bool

	Profiles     map[string]*DomainProfile
	profileOrder []string
	profilesMu   sync.RWMutex
}

type DomainProfile struct {
	FragmentMethod string
	FragmentMin    int
	FragmentMax    int
	FragmentDelay  int
	FakeSNI        string
	SplitAfterSNI  *bool
}

func (c *Config) GetProfile(domain string) *DomainProfile {
	c.profilesMu.RLock()
	defer c.profilesMu.RUnlock()
	if c.Profiles == nil {
		return nil
	}
	domain = strings.ToLower(strings.TrimPrefix(domain, "www."))
	for _, pattern := range c.profileOrder {
		if matchDomainPattern(domain, pattern) {
			return c.Profiles[pattern]
		}
	}
	return nil
}

func (c *Config) ReloadProfiles() (int, error) {
	if c.ConfigFile == "" {
		return 0, nil
	}
	tmp := &Config{Profiles: map[string]*DomainProfile{}}
	if err := loadConfigFile(tmp, c.ConfigFile); err != nil {
		return 0, err
	}
	c.profilesMu.Lock()
	c.Profiles = tmp.Profiles
	c.profileOrder = tmp.profileOrder
	c.profilesMu.Unlock()
	return len(tmp.profileOrder), nil
}

func (c *Config) pickFakeSNI(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if len(c.FakeSNIPool) > 0 {
		return c.FakeSNIPool[randIntN(len(c.FakeSNIPool))]
	}
	return ""
}

func matchDomainPattern(domain, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if strings.HasPrefix(pattern, "*.") {
		base := pattern[2:]
		return domain == base || strings.HasSuffix(domain, "."+base)
	}
	return domain == pattern || strings.HasSuffix(domain, "."+pattern)
}

func (c *Config) resolvedFragmentSettings(domain string) (method string, min, max, delay int, fakeSNI string, splitAfter bool) {
	method, min, max, delay = c.FragmentMethod, c.FragmentMin, c.FragmentMax, c.FragmentDelay
	fakeSNI = c.FakeSNI
	splitAfter = c.SplitAfterSNI

	p := c.GetProfile(domain)
	if p == nil {
		return
	}
	if p.FragmentMethod != "" {
		method = p.FragmentMethod
	}
	if p.FragmentMin > 0 {
		min = p.FragmentMin
	}
	if p.FragmentMax > 0 {
		max = p.FragmentMax
	}
	if p.FragmentDelay > 0 {
		delay = p.FragmentDelay
	}
	if p.FakeSNI != "" {
		fakeSNI = p.FakeSNI
	}
	if p.SplitAfterSNI != nil {
		splitAfter = *p.SplitAfterSNI
	}
	return
}

func (c *Config) resolvedQUICMode() string {
	if c.QUICMode != "" {
		return c.QUICMode
	}
	if c.BlockQUIC {
		return "drop"
	}
	return "off"
}

func preScanConfigPath(args []string) string {
	return preScanFlagValue(args, "config")
}

func preScanFlagValue(args []string, name string) string {
	short := "-" + name
	long := "--" + name
	for i, a := range args {
		if a == short || a == long {
			if i+1 < len(args) {
				return args[i+1]
			}
		}
		if strings.HasPrefix(a, short+"=") {
			return strings.TrimPrefix(a, short+"=")
		}
		if strings.HasPrefix(a, long+"=") {
			return strings.TrimPrefix(a, long+"=")
		}
	}
	return ""
}

func defaultConfig() *Config {
	return &Config{
		Host:              "127.0.0.1",
		Port:              8881,
		OutPort:           1080,
		BlacklistFile:     "blacklist.txt",
		FragmentMethod:    "sni",
		DomainMatching:    "strict",
		FragmentDelay:     2,
		FragmentMin:       10,
		FragmentMax:       60,
		SplitBeforeSNI:    true,
		KeepAlive:         true,
		BufferSize:        32768,
		Timeout:           30,
		Socks5Host:        "127.0.0.1",
		Socks5Port:        1080,
		DoHServer:         "https://1.1.1.1/dns-query",
		DoHCache:          true,
		FakePacketTTL:     4,
		FakeMethod:        "ttl",
		FrontCADir:        "front-ca",
		Adaptive:          true,
		FakePacketCount:   1,
		TransparentHost:   "127.0.0.1",
		TransparentPort:   12345,
		StrategyCacheFile: "strategy-cache.json",
		StatsPort:         9090,
		Profiles:          map[string]*DomainProfile{},
	}
}

func loadConfigFile(cfg *Config, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var curProfile *DomainProfile
	var curPattern string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inner := strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			if strings.HasPrefix(strings.ToLower(inner), "profile:") {
				pattern := strings.TrimSpace(inner[len("profile:"):])
				curPattern = strings.ToLower(pattern)
				curProfile = &DomainProfile{}
				cfg.Profiles[curPattern] = curProfile
				cfg.profileOrder = append(cfg.profileOrder, curPattern)
			} else {
				curProfile = nil
				curPattern = ""
			}
			continue
		}

		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])
		val = strings.Trim(val, "\"'")

		if curProfile != nil {
			applyProfileKV(curProfile, key, val)
		} else {
			applyGlobalKV(cfg, key, val)
		}
		_ = curPattern
	}
	return scanner.Err()
}

func parseBool(v string) bool {
	b, _ := strconv.ParseBool(v)
	return b
}

func parseIntSafe(v string) int {
	n, _ := strconv.Atoi(v)
	return n
}

func splitCSV(v string) []string {
	if v == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func applyGlobalKV(cfg *Config, key, val string) {
	switch key {
	case "host":
		cfg.Host = val
	case "port":
		cfg.Port = parseIntSafe(val)
	case "out-host":
		cfg.OutHost = val
	case "out-port":
		cfg.OutPort = parseIntSafe(val)
	case "out-type":
		cfg.OutType = val
	case "out-username":
		cfg.OutUsername = val
	case "out-password":
		cfg.OutPassword = val
	case "blacklist":
		cfg.BlacklistFile = val
	case "fragment-method":
		cfg.FragmentMethod = val
	case "domain-matching":
		cfg.DomainMatching = val
	case "log-access":
		cfg.LogAccess = val
	case "log-error":
		cfg.LogError = val
	case "log-domains":
		cfg.LogDomains = parseBool(val)
	case "no-blacklist":
		cfg.NoBlacklist = parseBool(val)
	case "autoblacklist":
		cfg.AutoBlacklist = parseBool(val)
	case "quiet":
		cfg.Quiet = parseBool(val)
	case "auth-username":
		cfg.Username = val
	case "auth-password":
		cfg.Password = val
	case "fragment-delay":
		cfg.FragmentDelay = parseIntSafe(val)
	case "fragment-min":
		cfg.FragmentMin = parseIntSafe(val)
	case "fragment-max":
		cfg.FragmentMax = parseIntSafe(val)
	case "split-before-sni":
		cfg.SplitBeforeSNI = parseBool(val)
	case "split-after-sni":
		cfg.SplitAfterSNI = parseBool(val)
	case "fake-sni":
		cfg.FakeSNI = val
	case "front-map":
		cfg.FrontMapRaw = val
	case "front-ca-dir":
		cfg.FrontCADir = val
	case "front-upstream-ca":
		cfg.FrontUpstreamCA = val
	case "ttl":
		cfg.TTL = parseIntSafe(val)
	case "keep-alive":
		cfg.KeepAlive = parseBool(val)
	case "buffer-size":
		cfg.BufferSize = parseIntSafe(val)
	case "timeout":
		cfg.Timeout = parseIntSafe(val)
	case "enable-socks5", "socks5":
		cfg.EnableSocks5 = parseBool(val)
	case "socks5-port":
		cfg.Socks5Port = parseIntSafe(val)
	case "socks5-host":
		cfg.Socks5Host = val
	case "enable-doh", "doh":
		cfg.EnableDoH = parseBool(val)
	case "doh-server":
		cfg.DoHServer = val
	case "doh-cache":
		cfg.DoHCache = parseBool(val)
	case "block-quic":
		cfg.BlockQUIC = parseBool(val)
	case "quic-mode":
		cfg.QUICMode = val
	case "quic-delay":
		cfg.QUICDelay = parseIntSafe(val)
	case "fake-packet":
		cfg.FakePacket = parseBool(val)
	case "fake-packet-ttl":
		cfg.FakePacketTTL = parseIntSafe(val)
	case "fake-method":
		cfg.FakeMethod = val
	case "http-obfuscate":
		cfg.HTTPObfuscate = parseBool(val)
	case "adaptive":
		cfg.Adaptive = parseBool(val)
	case "tls-grease":
		cfg.TLSGrease = parseBool(val)
	case "ech-grease":
		cfg.ECHGrease = parseBool(val)
	case "tls-padding":
		cfg.TLSPadding = parseIntSafe(val)
	case "tls-shuffle":
		cfg.TLSShuffle = parseBool(val)
	case "tls-profile":
		cfg.TLSProfile = val
	case "fake-sni-pool":
		cfg.FakeSNIPoolRaw = val
	case "fake-packet-count":
		cfg.FakePacketCount = parseIntSafe(val)
	case "fragment-jitter":
		cfg.FragmentJitter = parseIntSafe(val)
	case "race-strategies":
		cfg.RaceStrategies = parseBool(val)
	case "scan-domains":
		cfg.ScanDomainsRaw = val
	case "preset":
		cfg.Preset = val
	case "transparent":
		cfg.EnableTransparent = parseBool(val)
	case "transparent-host":
		cfg.TransparentHost = val
	case "transparent-port":
		cfg.TransparentPort = parseIntSafe(val)
	case "tcp-fastopen":
		cfg.TCPFastOpen = parseBool(val)
	case "tcp-mss":
		cfg.TCPMSS = parseIntSafe(val)
	case "strategy-cache-file":
		cfg.StrategyCacheFile = val
	case "stats-http":
		cfg.StatsHTTP = parseBool(val)
	case "stats-port":
		cfg.StatsPort = parseIntSafe(val)
	case "hosts-file":
		cfg.HostsFile = val
	case "max-connections":
		cfg.MaxConnections = parseIntSafe(val)
	}
}

func applyProfileKV(p *DomainProfile, key, val string) {
	switch key {
	case "fragment-method":
		p.FragmentMethod = val
	case "fragment-min":
		p.FragmentMin = parseIntSafe(val)
	case "fragment-max":
		p.FragmentMax = parseIntSafe(val)
	case "fragment-delay":
		p.FragmentDelay = parseIntSafe(val)
	case "fake-sni":
		p.FakeSNI = val
	case "split-after-sni":
		b := parseBool(val)
		p.SplitAfterSNI = &b
	}
}

func applyPreset(cfg *Config, name string) {
	switch name {
	case "safe":
		cfg.FragmentMethod = "sni"
		cfg.Adaptive = true
		cfg.FakePacket = false
		cfg.RaceStrategies = false
		cfg.TLSShuffle = false
	case "aggressive":
		cfg.FragmentMethod = "natural"
		cfg.Adaptive = true
		cfg.RaceStrategies = true
		cfg.FragmentJitter = 15
		cfg.EnableDoH = true
		cfg.BlockQUIC = true
		cfg.EnableSocks5 = true
	case "stealth":
		cfg.FragmentMethod = "natural"
		cfg.Adaptive = true
		cfg.FragmentJitter = 15
		cfg.BlockQUIC = true
	case "vpn-like":
		cfg.EnableSocks5 = true
		cfg.EnableDoH = true
		cfg.BlockQUIC = true
		cfg.Adaptive = true
	default:
		log.Printf("[WARN] unknown -preset %q - ignoring (known: safe, aggressive, stealth, vpn-like)", name)
	}
}

func (c *Config) validate() error {
	switch c.FragmentMethod {
	case "sni", "natural", "random", "multi", "none":
	default:
		return fmt.Errorf("unknown -fragment-method %q (use sni/natural/random/multi/none)", c.FragmentMethod)
	}
	switch c.DomainMatching {
	case "strict", "loose":
	default:
		return fmt.Errorf("unknown -domain-matching %q (use strict/loose)", c.DomainMatching)
	}
	switch c.QUICMode {
	case "", "off", "drop", "delay", "inspect":
	default:
		return fmt.Errorf("unknown -quic-mode %q (use off/drop/delay/inspect)", c.QUICMode)
	}
	switch c.TLSProfile {
	case "", "chrome", "firefox", "safari", "edge":
	default:
		return fmt.Errorf("unknown -tls-profile %q (use chrome/firefox/safari/edge)", c.TLSProfile)
	}
	if _, err := parseFakeFooling(c.FakeMethod); err != nil {
		return err
	}
	if c.OutHost != "" {
		if c.OutType == "" {
			c.OutType = "socks5"
		}
		if c.OutType != "http" && c.OutType != "socks5" {
			return fmt.Errorf("unknown -out-type %q (use http/socks5)", c.OutType)
		}
	}
	return nil
}

func (c *Config) mutatesClientHello() bool {
	return c.TLSGrease || c.ECHGrease || c.TLSPadding > 0 || c.TLSShuffle ||
		c.TLSProfile != "" || c.FakeSNI != "" || len(c.FakeSNIPool) > 0
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func (c *Config) warnUnsafeOptions() {
	if c.mutatesClientHello() {
		log.Printf("[WARN] A ClientHello-rewriting option is enabled (-fake-sni/-fake-sni-pool/-tls-profile/" +
			"-tls-shuffle/-tls-grease/-ech-grease/-tls-padding). 404DPI relays the application's own TLS " +
			"handshake instead of terminating it, so the client's handshake hash no longer matches what the " +
			"server saw and real TLS connections WILL FAIL (bad record MAC). These options are only useful " +
			"for -scan/-benchmark style probing. See README > Known limitations.")
	}
	if c.FakePacket {
		if err := rawFakeAvailable(); err != nil {
			log.Printf("[WARN] -fake-packet cannot work here: %v. Connections will proceed without decoys.", err)
		} else {
			log.Printf("[INFO] -fake-packet: forged decoy segments via raw socket (method: %s)", c.FakeMethod)
		}
	}
	if !isLoopbackHost(c.Host) && c.Username == "" && c.Password == "" {
		log.Printf("[WARN] the proxy listens on %s without -auth-username/-auth-password: anyone who can reach it can use it", c.Host)
	}
	if c.EnableSocks5 && !isLoopbackHost(c.Socks5Host) && c.Username == "" && c.Password == "" {
		log.Printf("[WARN] the SOCKS5 proxy listens on %s without -auth-username/-auth-password: anyone who can reach it can use it", c.Socks5Host)
	}
}

func parseFlags() *Config {
	config := defaultConfig()

	if cf := preScanConfigPath(os.Args[1:]); cf != "" {
		config.ConfigFile = cf
		if err := loadConfigFile(config, cf); err != nil {
			log.Printf("[WARN] could not load config file %s: %v", cf, err)
		}
	}
	if preset := preScanFlagValue(os.Args[1:], "preset"); preset != "" {
		config.Preset = preset
		applyPreset(config, preset)
	}

	fs := newFlagSet(config)
	fs.Parse(os.Args[1:])

	if config.AutoBlacklist && config.BlacklistFile == "blacklist.txt" {
		exePath, _ := os.Executable()
		config.BlacklistFile = filepath.Join(filepath.Dir(exePath), "blacklist.txt")
	}
	if config.FragmentMin > config.FragmentMax {
		config.FragmentMin, config.FragmentMax = config.FragmentMax, config.FragmentMin
	}
	if config.FragmentMin < 1 {
		config.FragmentMin = 1
	}
	if config.BufferSize < 4096 {
		config.BufferSize = 4096
	}
	if config.Socks5Host == "" {
		config.Socks5Host = config.Host
	}
	if config.FakePacketCount < 1 {
		config.FakePacketCount = 1
	}
	config.FakeSNIPool = splitCSV(config.FakeSNIPoolRaw)
	config.ScanDomains = splitCSV(config.ScanDomainsRaw)
	config.FrontMap = parseFrontMap(config.FrontMapRaw)

	return config
}

func newFlagSet(config *Config) *flagAdapter {
	return registerFlags(config, runtime.GOOS == "windows")
}
