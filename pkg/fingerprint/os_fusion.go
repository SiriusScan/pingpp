package fingerprint

import (
	"strings"

	"github.com/SiriusScan/ping++/pkg/model"
)

// FuseOS applies OS evidence priority from the PRD:
// protocol-native metadata > SMB/NTLM > LDAP > SNMP > SSH distro banners >
// RDP > strong app/device association > TCP stack > weak HTTP > ports > TTL.
// Generic OpenSSH/nginx/TTL-64 alone must not yield confident Linux.
func FuseOS(claims []model.Claim) []model.Claim {
	var osClaims []model.Claim
	for _, c := range claims {
		if c.Kind != model.ClaimOS {
			continue
		}
		c.Score = adjustOSScore(c)
		c.Confidence = model.TierFromScore(c.Score)
		osClaims = append(osClaims, c)
	}
	return Fuse(osClaims)
}

func adjustOSScore(c model.Claim) float64 {
	score := c.Score
	src := strings.ToLower(strings.Join(c.RuleIDs, " ") + " " + c.CorrelationGroup)
	switch {
	case strings.Contains(src, "smb") || strings.Contains(src, "ntlm"):
		// keep strong
	case strings.Contains(src, "snmp"):
		// keep
	case strings.Contains(src, "ssh") && isGenericOpenSSH(c):
		score = minFloat(score, 55) // hint at most
	case strings.Contains(src, "http") && isGenericWebServer(c):
		score = minFloat(score, 50)
	case strings.Contains(src, "ttl"):
		score = minFloat(score, 45)
	case strings.Contains(src, "port"):
		score = minFloat(score, 40)
	}
	// Generic "linux" from OpenSSH/nginx alone stays hint/unknown-ish
	if strings.EqualFold(c.Family, "linux") || strings.EqualFold(c.Product, "Linux") {
		if isGenericOpenSSH(c) || isGenericWebServer(c) || strings.Contains(src, "ttl") {
			score = minFloat(score, 55)
		}
	}
	return score
}

func isGenericOpenSSH(c model.Claim) bool {
	s := strings.ToLower(strings.Join(append(c.RuleIDs, c.EvidenceIDs...), " "))
	return strings.Contains(s, "openssh") || strings.Contains(c.CorrelationGroup, "ssh")
}

func isGenericWebServer(c model.Claim) bool {
	p := strings.ToLower(c.Product + c.Value)
	return strings.Contains(p, "nginx") || strings.Contains(p, "apache")
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
