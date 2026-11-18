package dpiproxy

import "strings"

func parseFrontMap(raw string) map[string]string {
	m := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			continue
		}
		real := strings.ToLower(strings.TrimSpace(parts[0]))
		front := strings.ToLower(strings.TrimSpace(parts[1]))
		if real == "" || front == "" {
			continue
		}
		m[real] = front
	}
	return m
}

func (c *Config) frontFor(host string) string {
	if len(c.FrontMap) == 0 {
		return ""
	}
	return c.FrontMap[strings.ToLower(host)]
}
