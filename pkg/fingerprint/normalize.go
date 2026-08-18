package fingerprint

import (
	"net/http"
	"strings"
	"unicode"

	"github.com/SiriusScan/ping++/pkg/model"
)

var productAliases = map[string]string{
	"microsoft-iis": "iis",
	"microsoft iis": "iis",
	"httpd":         "apache",
	"apache-httpd":  "apache",
	"apache httpd":  "apache",
}

func normalizeString(s string) string {
	s = strings.TrimSpace(s)
	return strings.Join(strings.Fields(s), " ")
}

// CanonicalVersion keeps the dotted numeric form, dropping a leading v and
// trailing product tokens. "v1.24.0 (Ubuntu)" → "1.24.0".
func CanonicalVersion(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	var out strings.Builder
	for _, r := range s {
		if unicode.IsDigit(r) || r == '.' {
			out.WriteRune(r)
			continue
		}
		if out.Len() > 0 {
			break
		}
	}
	return strings.Trim(out.String(), ".")
}

// CanonicalProduct lowercases and applies vendor aliases without inventing a
// product from generic tokens such as "server".
func CanonicalProduct(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "_", "-")
	if s == "" || s == "server" || s == "unknown" {
		return ""
	}
	if alias, ok := productAliases[s]; ok {
		return alias
	}
	if i := strings.IndexByte(s, '/'); i > 0 {
		head := strings.TrimSpace(s[:i])
		if alias, ok := productAliases[head]; ok {
			return alias
		}
		return head
	}
	return s
}

func canonicalHeaderMap(h map[string][]string) map[string][]string {
	if h == nil {
		return nil
	}
	out := http.Header{}
	for k, vals := range h {
		ck := http.CanonicalHeaderKey(k)
		for _, v := range vals {
			out.Add(ck, normalizeString(v))
		}
	}
	return map[string][]string(out)
}

// NormalizeObservation returns a copy whose payload strings are canonical for
// matching. The original record is not modified.
func NormalizeObservation(obs model.ObservationRecord) model.ObservationRecord {
	switch obs.ObservationType {
	case model.ObservationHTTP:
		var p model.HTTPObservation
		if err := obs.DecodePayload(&p); err != nil {
			return obs
		}
		p.Server = normalizeString(p.Server)
		p.PoweredBy = normalizeString(p.PoweredBy)
		p.Title = normalizeString(p.Title)
		p.MetaGenerator = normalizeString(p.MetaGenerator)
		p.Headers = canonicalHeaderMap(p.Headers)
		_ = obs.SetPayload(p)
	case model.ObservationBanner:
		var p model.BannerObservation
		if err := obs.DecodePayload(&p); err != nil {
			return obs
		}
		p.Text = normalizeString(p.Text)
		_ = obs.SetPayload(p)
	case model.ObservationSSH:
		var p model.SSHObservation
		if err := obs.DecodePayload(&p); err != nil {
			return obs
		}
		p.Banner = normalizeString(p.Banner)
		_ = obs.SetPayload(p)
	}
	return obs
}

func applyCanonicalFields(fields map[string]string) {
	if fields == nil {
		return
	}
	if v := fields["server"]; v != "" {
		fields["canonical.server"] = v
		if p := CanonicalProduct(v); p != "" {
			fields["canonical.product"] = p
		}
		if ver := CanonicalVersion(v); ver != "" {
			fields["canonical.version"] = ver
		}
	}
	if v := fields["banner"]; v != "" {
		fields["canonical.banner"] = normalizeString(v)
		if p := CanonicalProduct(v); p != "" && fields["canonical.product"] == "" {
			fields["canonical.product"] = p
		}
	}
	if v := fields["text"]; v != "" {
		fields["canonical.text"] = normalizeString(v)
	}
}
