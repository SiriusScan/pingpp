package adapters

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/SiriusScan/ping++/pkg/model"
	"gopkg.in/yaml.v3"
)

// RecogRule is a simplified Recog-compatible fingerprint loaded from YAML.
// Full Rapid7 Recog XML can be converted offline into this shape.
type RecogRule struct {
	ID        string `yaml:"id"`
	Protocol  string `yaml:"protocol"`
	Field     string `yaml:"field"`
	Pattern   string `yaml:"pattern"`
	Product   string `yaml:"product"`
	Vendor    string `yaml:"vendor"`
	Version   string `yaml:"version"`
	OSFamily  string `yaml:"os_family"`
	Certainty string `yaml:"certainty"`
	CPE       string `yaml:"cpe"`
}

// NativeRecog is a Recog-format adapter that never exposes third-party types.
type NativeRecog struct {
	rules []compiledRecog
}

type compiledRecog struct {
	rule RecogRule
	re   *regexp.Regexp
}

// LoadRecogYAML loads Recog-style rules from YAML (list).
func LoadRecogYAML(path string) (*NativeRecog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []RecogRule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	n := &NativeRecog{}
	for _, r := range rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		n.rules = append(n.rules, compiledRecog{rule: r, re: re})
	}
	return n, nil
}

// NewNativeRecogFromRules constructs a matcher from in-memory rules.
func NewNativeRecogFromRules(rules []RecogRule) (*NativeRecog, error) {
	n := &NativeRecog{}
	for _, r := range rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, err
		}
		n.rules = append(n.rules, compiledRecog{rule: r, re: re})
	}
	return n, nil
}

// Name implements FingerprintAdapter.
func (n *NativeRecog) Name() string { return "native-recog" }

// MatchField implements RecogMatcher.
func (n *NativeRecog) MatchField(protocol, field, value string) ([]model.Claim, error) {
	var out []model.Claim
	for _, cr := range n.rules {
		if cr.rule.Protocol != "" && !strings.EqualFold(cr.rule.Protocol, protocol) {
			continue
		}
		if cr.rule.Field != "" && !strings.EqualFold(cr.rule.Field, field) {
			continue
		}
		if !cr.re.MatchString(value) {
			continue
		}
		score := 85.0
		tier := model.ConfidenceTier(cr.rule.Certainty)
		if tier.Valid() {
			switch tier {
			case model.ConfidenceExact:
				score = 97
			case model.ConfidenceStrong:
				score = 90
			case model.ConfidenceProbable:
				score = 78
			case model.ConfidenceHint:
				score = 55
			}
		}
		kind := model.ClaimProduct
		product := cr.rule.Product
		if cr.rule.OSFamily != "" && product == "" {
			kind = model.ClaimOS
			product = cr.rule.OSFamily
		}
		out = append(out, model.Claim{
			ID:         fmt.Sprintf("recog:%s", cr.rule.ID),
			Kind:       kind,
			Vendor:     cr.rule.Vendor,
			Product:    product,
			Version:    cr.rule.Version,
			Family:     cr.rule.OSFamily,
			CPE:        cr.rule.CPE,
			Value:      product,
			Score:      score,
			Confidence: model.TierFromScore(score),
			RuleIDs:    []string{cr.rule.ID},
		})
	}
	return out, nil
}

// Match implements FingerprintAdapter.
func (n *NativeRecog) Match(observations []model.ObservationRecord) ([]model.Claim, error) {
	var out []model.Claim
	for _, obs := range observations {
		fields := map[string]string{}
		switch obs.ObservationType {
		case model.ObservationSSH:
			var p model.SSHObservation
			_ = obs.DecodePayload(&p)
			values := []string{}
			if p.Banner != "" {
				values = append(values, p.Banner)
			}
			if ident := sshSoftwareIdent(p.Banner); ident != "" && ident != p.Banner {
				values = append(values, ident)
			}
			for _, val := range values {
				claims, err := n.MatchField("ssh", "banner", val)
				if err != nil {
					return nil, err
				}
				for i := range claims {
					annotateRecogClaim(&claims[i], obs)
				}
				out = append(out, claims...)
			}
			continue
		case model.ObservationHTTP:
			var p model.HTTPObservation
			_ = obs.DecodePayload(&p)
			fields["server"] = p.Server
			fields["title"] = p.Title
		case model.ObservationSMB:
			var p model.SMBObservation
			_ = obs.DecodePayload(&p)
			fields["os_build"] = p.OSBuild
			fields["computer_name"] = p.ComputerName
		}
		proto := strings.TrimPrefix(obs.ObservationType, "")
		for field, val := range fields {
			if val == "" {
				continue
			}
			claims, err := n.MatchField(proto, field, val)
			if err != nil {
				return nil, err
			}
			for i := range claims {
				annotateRecogClaim(&claims[i], obs)
			}
			out = append(out, claims...)
		}
	}
	return out, nil
}

func annotateRecogClaim(c *model.Claim, obs model.ObservationRecord) {
	c.EvidenceIDs = []string{obs.ID}
	c.CorrelationGroup = "recog:" + obs.ObservationType
	c.Subject = obs.AssetID
	if obs.Endpoint != nil {
		c.Subject = model.EndpointKey(obs.Endpoint.Address, obs.Endpoint.Port, obs.Endpoint.Transport)
	}
}

// RuleCount returns the number of compiled Recog rules.
func (n *NativeRecog) RuleCount() int {
	if n == nil {
		return 0
	}
	return len(n.rules)
}

func sshSoftwareIdent(banner string) string {
	banner = strings.TrimSpace(banner)
	if !strings.HasPrefix(banner, "SSH-") {
		return banner
	}
	parts := strings.SplitN(banner, "-", 3)
	if len(parts) < 3 {
		return banner
	}
	return parts[2]
}
