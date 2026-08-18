package adapters

import (
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type recogXML struct {
	XMLName      xml.Name        `xml:"fingerprints"`
	Matches      string          `xml:"matches,attr"`
	Protocol     string          `xml:"protocol,attr"`
	Fingerprints []recogXMLPrint `xml:"fingerprint"`
}

type recogXMLPrint struct {
	Pattern      string          `xml:"pattern,attr"`
	PatternFlags string          `xml:"pattern_cflags,attr"`
	Description  string          `xml:"description"`
	Params       []recogXMLParam `xml:"param"`
}

type recogXMLParam struct {
	Pos   string `xml:"pos,attr"`
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
	Text  string `xml:",chardata"`
}

func (p recogXMLParam) val() string {
	if s := strings.TrimSpace(p.Value); s != "" {
		return s
	}
	return strings.TrimSpace(p.Text)
}

// LoadRecogXML loads Rapid7 Recog-format XML into NativeRecog.
func LoadRecogXML(path string) (*NativeRecog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseRecogXML(data)
}

// ParseRecogXML parses Recog XML bytes. XML syntax errors fail closed.
// Individual patterns that are not valid RE2 are skipped.
func ParseRecogXML(data []byte) (*NativeRecog, error) {
	var doc recogXML
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	protocol, field := mapRecogMatches(doc.Matches, doc.Protocol)
	var rules []RecogRule
	skipped := 0
	for i, fp := range doc.Fingerprints {
		if fp.Pattern == "" {
			continue
		}
		pat := fp.Pattern
		if strings.Contains(strings.ToUpper(fp.PatternFlags), "REG_ICASE") && !strings.HasPrefix(pat, "(?i)") && !strings.HasPrefix(pat, "(?is)") {
			pat = "(?i)" + pat
		}
		if _, err := regexp.Compile(pat); err != nil {
			skipped++
			continue
		}
		rule := RecogRule{
			ID:        fmt.Sprintf("recog-xml-%s-%d", protocol, i),
			Protocol:  protocol,
			Field:     field,
			Pattern:   pat,
			Certainty: "strong",
		}
		for _, p := range fp.Params {
			if p.Name == "" {
				continue
			}
			pos, _ := strconv.Atoi(p.Pos)
			rule.Params = append(rule.Params, RecogParam{Name: p.Name, Pos: pos, Value: p.val()})
		}
		if fp.Description != "" && !hasRecogParam(rule.Params, "service.product") && !hasRecogParam(rule.Params, "os.product") {
			rule.Params = append(rule.Params, RecogParam{Name: "service.product", Value: fp.Description})
		}
		rules = append(rules, rule)
	}
	_ = skipped
	return NewNativeRecogFromRules(rules)
}

func hasRecogParam(params []RecogParam, name string) bool {
	for _, p := range params {
		if p.Name == name {
			return true
		}
	}
	return false
}

func mapRecogMatches(matches, protocolAttr string) (protocol, field string) {
	m := matches
	if m == "" {
		m = protocolAttr
	}
	switch {
	case strings.HasPrefix(m, "http_header."):
		return "http", strings.TrimPrefix(m, "http_header.")
	case strings.HasPrefix(m, "http."):
		return "http", strings.TrimPrefix(m, "http.")
	default:
		parts := strings.SplitN(m, ".", 2)
		protocol = parts[0]
		if protocol == "" {
			protocol = "ssh"
		}
		field = "banner"
		if len(parts) == 2 && parts[1] != "" {
			field = parts[1]
		}
		return protocol, field
	}
}
