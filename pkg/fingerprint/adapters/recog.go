package adapters

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/SiriusScan/ping++/pkg/model"
	"gopkg.in/yaml.v3"
)

// RecogParam is one Recog fingerprint param. Pos 0 is a static Value
// (with {name} substitutions). Pos N>0 is regex capture group N.
type RecogParam struct {
	Name  string
	Pos   int
	Value string
}

// RecogRule is a Recog-compatible fingerprint. XML import keeps service,
// OS, and hardware params separate; YAML may still use the flattened fields.
type RecogRule struct {
	ID        string       `yaml:"id"`
	Protocol  string       `yaml:"protocol"`
	Field     string       `yaml:"field"`
	Pattern   string       `yaml:"pattern"`
	Product   string       `yaml:"product"`
	Vendor    string       `yaml:"vendor"`
	Version   string       `yaml:"version"`
	OSFamily  string       `yaml:"os_family"`
	Certainty string       `yaml:"certainty"`
	CPE       string       `yaml:"cpe"`
	Params    []RecogParam `yaml:"-"`
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
	return NewNativeRecogFromRules(rules)
}

// NewNativeRecogFromRules constructs a matcher from in-memory rules.
func NewNativeRecogFromRules(rules []RecogRule) (*NativeRecog, error) {
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
		sub := cr.re.FindStringSubmatch(value)
		if sub == nil {
			continue
		}
		out = append(out, claimsFromRule(cr.rule, sub)...)
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
	if obs.Endpoint != nil {
		c.Subject = model.EndpointKey(obs.Endpoint.Address, obs.Endpoint.Port, obs.Endpoint.Transport)
	}
}

func claimsFromRule(rule RecogRule, sub []string) []model.Claim {
	score, conf := recogScore(rule.Certainty)
	if len(rule.Params) == 0 {
		version := rule.Version
		if version == "" && len(sub) > 1 {
			version = sub[1]
		}
		kind := model.ClaimProduct
		product := rule.Product
		if rule.OSFamily != "" && product == "" {
			kind = model.ClaimOS
			product = rule.OSFamily
		}
		if product == "" && version == "" && rule.Vendor == "" {
			return nil
		}
		return []model.Claim{{
			ID:         fmt.Sprintf("recog:%s", rule.ID),
			Kind:       kind,
			Vendor:     rule.Vendor,
			Product:    product,
			Version:    version,
			Family:     rule.OSFamily,
			CPE:        substitute(rule.CPE, map[string]string{"service.version": version, "os.version": version}),
			Value:      product,
			Score:      score,
			Confidence: conf,
			RuleIDs:    []string{rule.ID},
		}}
	}

	vals := resolveRecogParams(rule.Params, sub)
	var out []model.Claim
	if c, ok := recogServiceClaim(rule.ID, vals, score, conf); ok {
		out = append(out, c)
	}
	if c, ok := recogOSClaim(rule.ID, vals, score, conf); ok {
		out = append(out, c)
	}
	if c, ok := recogHardwareClaim(rule.ID, vals, score, conf); ok {
		out = append(out, c)
	}
	return out
}

func resolveRecogParams(params []RecogParam, sub []string) map[string]string {
	vals := map[string]string{}
	for _, p := range params {
		if p.Pos > 0 {
			if p.Pos < len(sub) {
				vals[p.Name] = sub[p.Pos]
			}
			continue
		}
		if p.Value != "" {
			vals[p.Name] = p.Value
		}
	}
	for name, v := range vals {
		vals[name] = substitute(v, vals)
	}
	return vals
}

var recogSubst = regexp.MustCompile(`\{([^}]+)\}`)

func substitute(s string, vals map[string]string) string {
	if s == "" || !strings.Contains(s, "{") {
		return s
	}
	return recogSubst.ReplaceAllStringFunc(s, func(tok string) string {
		name := tok[1 : len(tok)-1]
		if v := vals[name]; v != "" {
			return v
		}
		return tok
	})
}

func recogServiceClaim(ruleID string, vals map[string]string, score float64, conf model.ConfidenceTier) (model.Claim, bool) {
	product := firstNonEmpty(vals["service.product"], vals["service.family"])
	if product == "" {
		return model.Claim{}, false
	}
	family := vals["service.family"]
	if strings.EqualFold(family, product) {
		family = ""
	}
	version := vals["service.version"]
	return model.Claim{
		ID:         fmt.Sprintf("recog:%s", ruleID),
		Kind:       model.ClaimProduct,
		Vendor:     vals["service.vendor"],
		Product:    product,
		Version:    version,
		Family:     family,
		CPE:        vals["service.cpe23"],
		Value:      product,
		Score:      score,
		Confidence: conf,
		RuleIDs:    []string{ruleID},
	}, true
}

func recogOSClaim(ruleID string, vals map[string]string, score float64, conf model.ConfidenceTier) (model.Claim, bool) {
	product := firstNonEmpty(vals["os.product"], vals["os.family"])
	if product == "" && vals["os.vendor"] == "" {
		return model.Claim{}, false
	}
	return model.Claim{
		ID:         fmt.Sprintf("recog:%s:os", ruleID),
		Kind:       model.ClaimOS,
		Vendor:     vals["os.vendor"],
		Product:    product,
		Version:    vals["os.version"],
		Family:     firstNonEmpty(vals["os.family"], product),
		CPE:        vals["os.cpe23"],
		Value:      product,
		Score:      score,
		Confidence: conf,
		RuleIDs:    []string{ruleID},
	}, true
}

func recogHardwareClaim(ruleID string, vals map[string]string, score float64, conf model.ConfidenceTier) (model.Claim, bool) {
	product := firstNonEmpty(vals["hw.product"], vals["hw.device"])
	if product == "" && vals["hw.vendor"] == "" {
		return model.Claim{}, false
	}
	return model.Claim{
		ID:         fmt.Sprintf("recog:%s:hw", ruleID),
		Kind:       model.ClaimDevice,
		Vendor:     vals["hw.vendor"],
		Product:    product,
		DeviceType: vals["hw.device"],
		CPE:        vals["hw.cpe23"],
		Value:      product,
		Score:      score,
		Confidence: conf,
		RuleIDs:    []string{ruleID},
	}, true
}

func recogScore(certainty string) (float64, model.ConfidenceTier) {
	score := 85.0
	switch model.ConfidenceTier(certainty) {
	case model.ConfidenceExact:
		score = 97
	case model.ConfidenceStrong:
		score = 90
	case model.ConfidenceProbable:
		score = 78
	case model.ConfidenceHint:
		score = 55
	}
	return score, model.TierFromScore(score)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
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
