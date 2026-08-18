package runner

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// TargetKind classifies a user-supplied scan input. Runner V2 does not
// pre-resolve hostnames.
type TargetKind string

const (
	TargetIPv4     TargetKind = "ipv4"
	TargetIPv6     TargetKind = "ipv6"
	TargetHostname TargetKind = "hostname"
	TargetCIDR     TargetKind = "cidr"
)

// TargetSpec is one admitted scan input before Engine resolution.
type TargetSpec struct {
	Input  string
	Source string
	Kind   TargetKind
	File   string
	Line   int
}

// Source names.
const (
	SourceArgv  = "argv"
	SourceStdin = "stdin"
	SourceFile  = "file"
	SourceCIDR  = "cidr"
)

// ErrUnsupportedTarget is returned for URL and host:port inputs in V1.
var ErrUnsupportedTarget = errors.New("unsupported target syntax")

// ErrInvalidTarget is returned for a malformed IP, CIDR, or hostname.
var ErrInvalidTarget = errors.New("invalid target")

func parseTarget(raw, source string) (TargetSpec, error) {
	raw = strings.TrimSpace(raw)
	spec := TargetSpec{Input: raw, Source: source}
	if raw == "" {
		return spec, fmt.Errorf("%w: empty", ErrInvalidTarget)
	}
	if looksLikeURL(raw) {
		return spec, fmt.Errorf("%w: %q (pass a hostname, IP, or CIDR; URLs are not accepted in v1)", ErrUnsupportedTarget, raw)
	}
	if host, _, ok := splitHostPort(raw); ok {
		return spec, fmt.Errorf("%w: %q (host:port is not accepted in v1; scan %s and set ports on the profile)", ErrUnsupportedTarget, raw, host)
	}

	if ip := net.ParseIP(raw); ip != nil {
		if ip.To4() != nil {
			spec.Kind = TargetIPv4
		} else {
			spec.Kind = TargetIPv6
		}
		return spec, nil
	}
	if _, n, err := net.ParseCIDR(raw); err == nil {
		spec.Kind = TargetCIDR
		spec.Input = n.String()
		return spec, nil
	}
	if err := validateHostname(raw); err != nil {
		return spec, fmt.Errorf("%w: %q: %v", ErrInvalidTarget, raw, err)
	}
	spec.Kind = TargetHostname
	return spec, nil
}

func looksLikeURL(raw string) bool {
	if i := strings.Index(raw, "://"); i > 0 {
		scheme := strings.ToLower(raw[:i])
		if scheme == "http" || scheme == "https" || scheme == "ftp" || scheme == "tcp" || scheme == "udp" {
			return true
		}
		if _, err := url.Parse(raw); err == nil {
			return true
		}
	}
	return false
}

func splitHostPort(raw string) (host, port string, ok bool) {
	if _, _, err := net.SplitHostPort(raw); err != nil {
		return "", "", false
	}
	// Bare IPv6 is ParseIP, not SplitHostPort. Bracketed IPv6 without port
	// also fails SplitHostPort. A successful split with a numeric port is host:port.
	h, p, err := net.SplitHostPort(raw)
	if err != nil || h == "" || p == "" {
		return "", "", false
	}
	for _, c := range p {
		if c < '0' || c > '9' {
			return "", "", false
		}
	}
	return h, p, true
}

func validateHostname(raw string) error {
	if strings.ContainsAny(raw, " /\\") {
		return errors.New("contains whitespace or path characters")
	}
	if net.ParseIP(raw) != nil {
		return nil
	}
	// Reject obviously invalid dotted quads that ParseIP refused.
	if isDottedQuad(raw) {
		return errors.New("invalid IPv4 address")
	}
	if strings.HasPrefix(raw, ".") || strings.HasSuffix(raw, ".") {
		if raw != "." {
			// trailing-dot FQDN is OK if the rest is a hostname
			raw = strings.TrimSuffix(raw, ".")
			if raw == "" {
				return errors.New("empty hostname")
			}
		}
	}
	if len(raw) > 253 {
		return errors.New("hostname too long")
	}
	for _, label := range strings.Split(raw, ".") {
		if label == "" || len(label) > 63 {
			return errors.New("invalid DNS label")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid DNS label")
		}
		for _, c := range label {
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
			if !ok {
				return errors.New("invalid hostname character")
			}
		}
	}
	return nil
}

func isDottedQuad(raw string) bool {
	parts := strings.Split(raw, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}
