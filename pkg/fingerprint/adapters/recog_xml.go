package adapters

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
)

type recogXML struct {
	XMLName      xml.Name        `xml:"fingerprints"`
	Matches      string          `xml:"matches,attr"`
	Fingerprints []recogXMLPrint `xml:"fingerprint"`
}

type recogXMLPrint struct {
	Pattern     string          `xml:"pattern,attr"`
	Description string          `xml:"description"`
	Params      []recogXMLParam `xml:"param"`
}

type recogXMLParam struct {
	Pos  string `xml:"pos,attr"`
	Name string `xml:"name,attr"`
	Text string `xml:",chardata"`
}

// LoadRecogXML loads Rapid7 Recog-format XML into NativeRecog.
func LoadRecogXML(path string) (*NativeRecog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseRecogXML(data)
}

// ParseRecogXML parses Recog XML bytes.
func ParseRecogXML(data []byte) (*NativeRecog, error) {
	var doc recogXML
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	protocol, field := "ssh", "banner"
	if doc.Matches != "" {
		parts := strings.SplitN(doc.Matches, ".", 2)
		protocol = parts[0]
		if len(parts) == 2 {
			field = parts[1]
		}
	}
	var rules []RecogRule
	for i, fp := range doc.Fingerprints {
		if fp.Pattern == "" {
			continue
		}
		rule := RecogRule{
			ID:       fmt.Sprintf("recog-xml-%d", i),
			Protocol: protocol,
			Field:    field,
			Pattern:  fp.Pattern,
		}
		for _, p := range fp.Params {
			switch p.Name {
			case "service.product", "os.product":
				if strings.TrimSpace(p.Text) != "" {
					rule.Product = strings.TrimSpace(p.Text)
				}
			case "service.vendor", "os.vendor":
				rule.Vendor = strings.TrimSpace(p.Text)
			case "os.family":
				rule.OSFamily = strings.TrimSpace(p.Text)
			}
		}
		if rule.Product == "" && fp.Description != "" {
			rule.Product = fp.Description
		}
		rule.Certainty = "strong"
		rules = append(rules, rule)
	}
	return NewNativeRecogFromRules(rules)
}
