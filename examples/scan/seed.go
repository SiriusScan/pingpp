package main

import (
	"net"
	"net/url"
	"strings"
)

// parseTarget turns a URL, host:port, or hostname into a scan host.
func parseTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	raw = strings.TrimSuffix(raw, "/")
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(raw)
}

func expandTargets(inputs []string, seed bool) []string {
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		h = parseTarget(h)
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	for _, in := range inputs {
		host := parseTarget(in)
		if host == "" {
			continue
		}
		add(host)
		if !seed {
			continue
		}
		for _, extra := range seedAliases(host) {
			add(extra)
		}
	}
	return out
}

// seedAliases returns apex/www siblings for a registrable domain only.
// n8n.example.com is left alone; example.com ↔ www.example.com.
func seedAliases(host string) []string {
	if strings.HasPrefix(host, "www.") {
		apex := strings.TrimPrefix(host, "www.")
		if isRegistrableApex(apex) {
			return []string{apex}
		}
		return nil
	}
	if isRegistrableApex(host) {
		return []string{"www." + host}
	}
	return nil
}

var multiPartTLD = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true,
	"com.au": true, "net.au": true, "org.au": true,
	"co.jp": true, "com.br": true, "co.nz": true,
}

func isRegistrableApex(host string) bool {
	if net.ParseIP(host) != nil {
		return false
	}
	labels := strings.Split(host, ".")
	switch len(labels) {
	case 2:
		return labels[0] != "" && labels[1] != ""
	case 3:
		return multiPartTLD[labels[1]+"."+labels[2]]
	default:
		return false
	}
}
