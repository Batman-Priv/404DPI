package dpiproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func domainToken(config *Config, domain string) string {
	if config != nil && config.LogDomains {
		return domain
	}
	sum := sha256.Sum256([]byte(domain))
	return hex.EncodeToString(sum[:6])
}

func looksLikeDomainToken(s string) bool {
	if len(s) != 12 || strings.Contains(s, ".") {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func loadNormalizedDomain(config *Config, line string) string {
	normalized := strings.ToLower(strings.TrimPrefix(line, "www."))
	if looksLikeDomainToken(normalized) {
		return normalized
	}
	return domainToken(config, normalized)
}
