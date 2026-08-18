package ldap

import (
	"fmt"
)

func berTLV(tag byte, val []byte) []byte {
	return append(append([]byte{tag}, berLength(len(val))...), val...)
}

func berLength(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	if n < 256 {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

func encodeRootDSESearch() []byte {
	names := []string{
		"vendorName", "vendorVersion", "namingContexts",
		"defaultNamingContext", "rootDomainNamingContext",
		"dnsHostName", "supportedCapabilities", "supportedLDAPVersion",
		"supportedSASLMechanisms",
	}
	var attrSeq []byte
	for _, n := range names {
		attrSeq = append(attrSeq, berTLV(0x04, []byte(n))...)
	}
	search := concat(
		berTLV(0x04, nil),          // baseObject
		[]byte{0x0a, 0x01, 0x00},   // scope baseObject
		[]byte{0x0a, 0x01, 0x00},   // derefNever
		berTLV(0x02, []byte{0x00}), // sizeLimit
		berTLV(0x02, []byte{0x00}), // timeLimit
		[]byte{0x01, 0x01, 0x00},   // typesOnly false
		berTLV(0x87, []byte("objectClass")),
		berTLV(0x30, attrSeq),
	)
	return berTLV(0x30, concat(berTLV(0x02, []byte{0x01}), berTLV(0x63, search)))
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

type tlv struct {
	Tag byte
	Val []byte
}

func parseTLV(b []byte) (tlv, []byte, error) {
	if len(b) < 2 {
		return tlv{}, nil, fmt.Errorf("short ber")
	}
	tag := b[0]
	n, hdr, err := parseLen(b[1:])
	if err != nil {
		return tlv{}, nil, err
	}
	off := 1 + hdr
	if off+n > len(b) {
		return tlv{}, nil, fmt.Errorf("truncated ber")
	}
	return tlv{Tag: tag, Val: b[off : off+n]}, b[off+n:], nil
}

func parseLen(b []byte) (int, int, error) {
	if len(b) < 1 {
		return 0, 0, fmt.Errorf("short len")
	}
	if b[0] < 0x80 {
		return int(b[0]), 1, nil
	}
	c := int(b[0] & 0x7f)
	if c == 0 || c > 3 || len(b) < 1+c {
		return 0, 0, fmt.Errorf("bad ber length")
	}
	n := 0
	for i := 0; i < c; i++ {
		n = (n << 8) | int(b[1+i])
	}
	return n, 1 + c, nil
}

func decodeRootDSE(msg []byte) (Observation, bool) {
	var out Observation
	ok := walkLDAP(msg, &out)
	return out, ok
}

func walkLDAP(b []byte, out *Observation) bool {
	matched := false
	for len(b) > 0 {
		el, rest, err := parseTLV(b)
		if err != nil {
			break
		}
		b = rest
		switch el.Tag {
		case 0x64: // SearchResultEntry
			matched = true
			out.Responded = true
			parseAttributes(el.Val, out)
		case 0x65: // SearchResultDone
			matched = true
			out.Responded = true
		case 0x30, 0x31: // SEQUENCE / SET
			if walkLDAP(el.Val, out) {
				matched = true
			}
		}
	}
	return matched
}

func parseAttributes(b []byte, out *Observation) {
	// objectName OCTET STRING, then SEQUENCE OF attribute
	if len(b) == 0 {
		return
	}
	_, rest, err := parseTLV(b)
	if err != nil {
		return
	}
	for len(rest) > 0 {
		el, next, err := parseTLV(rest)
		if err != nil {
			return
		}
		rest = next
		if el.Tag == 0x30 {
			parseAttributes(el.Val, out)
			continue
		}
	}
	// attribute: SEQUENCE { type OCTET STRING, vals SET OF OCTET STRING }
	parseAttrSeq(b, out)
}

func parseAttrSeq(b []byte, out *Observation) {
	for len(b) > 0 {
		el, rest, err := parseTLV(b)
		if err != nil {
			return
		}
		b = rest
		if el.Tag != 0x30 {
			if el.Tag == 0x04 || el.Tag == 0x31 {
				continue
			}
			continue
		}
		inner := el.Val
		nameEl, innerRest, err := parseTLV(inner)
		if err != nil || nameEl.Tag != 0x04 {
			parseAttrSeq(el.Val, out)
			continue
		}
		name := string(nameEl.Val)
		var vals []string
		if len(innerRest) > 0 {
			set, _, err := parseTLV(innerRest)
			if err == nil && (set.Tag == 0x31 || set.Tag == 0x30) {
				sb := set.Val
				for len(sb) > 0 {
					v, nsb, err := parseTLV(sb)
					if err != nil {
						break
					}
					if v.Tag == 0x04 {
						vals = append(vals, string(v.Val))
					}
					sb = nsb
				}
			}
		}
		assignAttr(out, name, vals)
	}
}

func assignAttr(out *Observation, name string, vals []string) {
	if len(vals) == 0 {
		return
	}
	switch name {
	case "vendorName":
		out.VendorName = vals[0]
	case "vendorVersion":
		out.VendorVersion = vals[0]
	case "namingContexts":
		out.NamingContexts = vals
	case "defaultNamingContext":
		out.DefaultNamingContext = vals[0]
	case "rootDomainNamingContext":
		out.RootDomainNamingContext = vals[0]
	case "dnsHostName":
		out.DNSHostName = vals[0]
	case "supportedCapabilities":
		out.SupportedCapabilities = vals
	case "supportedLDAPVersion":
		out.SupportedLDAPVersion = vals
	case "supportedSASLMechanisms":
		out.SupportedSASLMechanisms = vals
	}
}

// EncodeSearchResultEntry is exported for tests.
func EncodeSearchResultEntry(attrs map[string][]string) []byte {
	var attrBody []byte
	for k, vs := range attrs {
		var set []byte
		for _, v := range vs {
			set = append(set, berTLV(0x04, []byte(v))...)
		}
		one := concat(berTLV(0x04, []byte(k)), berTLV(0x31, set))
		attrBody = append(attrBody, berTLV(0x30, one)...)
	}
	entry := concat(berTLV(0x04, nil), berTLV(0x30, attrBody))
	return berTLV(0x30, concat(berTLV(0x02, []byte{0x01}), berTLV(0x64, entry)))
}
