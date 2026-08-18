// Package fingerprint implements data-driven matching and evidence fusion.
//
// Collectors must not call into product logic; this package turns observations
// into Claims using rules and correlation groups.
package fingerprint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/SiriusScan/ping++/pkg/artifact"
	"github.com/SiriusScan/ping++/pkg/fingerprint/adapters"
	"github.com/SiriusScan/ping++/pkg/model"
	"gopkg.in/yaml.v3"
)

// Rule is a native fingerprint definition (YAML-backed).
type Rule struct {
	ID               string           `yaml:"id" json:"id"`
	Scope            string           `yaml:"scope" json:"scope"`
	CorrelationGroup string           `yaml:"correlation_group" json:"correlation_group"`
	Inputs           RuleInputs       `yaml:"inputs" json:"inputs"`
	Matches          []MatchCondition `yaml:"matches" json:"matches"`
	Exclusions       []MatchCondition `yaml:"exclusions" json:"exclusions"`
	Claims           []RuleClaim      `yaml:"claims" json:"claims"`
}

// RuleInputs constrains which observations a rule considers.
type RuleInputs struct {
	ObservationType string `yaml:"observation_type" json:"observation_type"`
	Protocol        string `yaml:"protocol" json:"protocol"`
}

// MatchCondition is a positive or negative field check.
type MatchCondition struct {
	Field    string `yaml:"field" json:"field"`
	Regex    string `yaml:"regex,omitempty" json:"regex,omitempty"`
	Equals   string `yaml:"equals,omitempty" json:"equals,omitempty"`
	Contains string `yaml:"contains,omitempty" json:"contains,omitempty"`
}

// RuleClaim declares an inference produced when matches succeed.
type RuleClaim struct {
	Kind       model.ClaimKind      `yaml:"kind" json:"kind"`
	Vendor     string               `yaml:"vendor,omitempty" json:"vendor,omitempty"`
	Product    string               `yaml:"product,omitempty" json:"product,omitempty"`
	Version    string               `yaml:"version,omitempty" json:"version,omitempty"`
	Family     string               `yaml:"family,omitempty" json:"family,omitempty"`
	DeviceType string               `yaml:"device_type,omitempty" json:"device_type,omitempty"`
	Attribute  string               `yaml:"attribute,omitempty" json:"attribute,omitempty"`
	Value      string               `yaml:"value,omitempty" json:"value,omitempty"`
	Certainty  model.ConfidenceTier `yaml:"certainty" json:"certainty"`
	Score      float64              `yaml:"score,omitempty" json:"score,omitempty"`
}

// Engine matches rules against observations and fuses claims.
type Engine struct {
	rules    []compiledRule
	store    artifact.Store
	adapters []adapters.FingerprintAdapter
}

type compiledRule struct {
	rule     Rule
	matchers []compiledCond
	excludes []compiledCond
}

type compiledCond struct {
	cond MatchCondition
	re   *regexp.Regexp
}

// NewEngine creates an empty fingerprint engine.
func NewEngine() *Engine {
	return &Engine{}
}

// SetArtifactStore lets Match hydrate HTTP bodies from stored artifacts.
func (e *Engine) SetArtifactStore(store artifact.Store) {
	if e != nil {
		e.store = store
	}
}

// AddAdapter registers a Recog/Wappalyzer-compatible matcher.
func (e *Engine) AddAdapter(a adapters.FingerprintAdapter) {
	if e == nil || a == nil {
		return
	}
	e.adapters = append(e.adapters, a)
}

// LoadYAMLFile loads rules from a YAML file (single rule or list).
func (e *Engine) LoadYAMLFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return e.LoadYAML(data)
}

// LoadYAML parses rule(s) from YAML bytes. Unknown fields fail closed.
func (e *Engine) LoadYAML(data []byte) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var many []Rule
	if err := dec.Decode(&many); err == nil && len(many) > 0 && many[0].ID != "" {
		for _, r := range many {
			if err := e.AddRule(r); err != nil {
				return err
			}
		}
		return nil
	}
	dec = yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var one Rule
	if err := dec.Decode(&one); err != nil {
		return err
	}
	return e.AddRule(one)
}

// YAMLRules returns compiled native YAML rules (not adapter corpora).
func (e *Engine) YAMLRules() []Rule {
	if e == nil {
		return nil
	}
	out := make([]Rule, 0, len(e.rules))
	for _, cr := range e.rules {
		out = append(out, cr.rule)
	}
	return out
}

// LoadDir loads all .yaml/.yml files from a directory (non-recursive).
func (e *Engine) LoadDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		if err := e.LoadYAMLFile(filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

// AddRule compiles and registers a rule.
func (e *Engine) AddRule(r Rule) error {
	if r.ID == "" {
		return fmt.Errorf("rule id required")
	}
	cr := compiledRule{rule: r}
	for _, m := range r.Matches {
		cc, err := compileCond(m)
		if err != nil {
			return fmt.Errorf("rule %s match: %w", r.ID, err)
		}
		cr.matchers = append(cr.matchers, cc)
	}
	for _, m := range r.Exclusions {
		cc, err := compileCond(m)
		if err != nil {
			return fmt.Errorf("rule %s exclusion: %w", r.ID, err)
		}
		cr.excludes = append(cr.excludes, cc)
	}
	e.rules = append(e.rules, cr)
	return nil
}

func compileCond(m MatchCondition) (compiledCond, error) {
	cc := compiledCond{cond: m}
	if m.Regex != "" {
		re, err := regexp.Compile(m.Regex)
		if err != nil {
			return cc, err
		}
		cc.re = re
	}
	return cc, nil
}

// Match runs all rules against observations and returns fused claims.
func (e *Engine) Match(observations []model.ObservationRecord) []model.Claim {
	var raw []model.Claim
	hydrated := make([]model.ObservationRecord, 0, len(observations))
	for _, obs := range observations {
		hydrated = append(hydrated, NormalizeObservation(e.hydrate(obs)))
	}
	for _, obs := range hydrated {
		fields := flattenObservation(obs)
		applyCanonicalFields(fields)
		for _, cr := range e.rules {
			if cr.rule.Inputs.ObservationType != "" && cr.rule.Inputs.ObservationType != obs.ObservationType {
				continue
			}
			if !matchesAll(cr.matchers, fields) {
				continue
			}
			if matchesAny(cr.excludes, fields) {
				continue
			}
			for i, rc := range cr.rule.Claims {
				score := rc.Score
				if score == 0 {
					score = scoreFromTier(rc.Certainty)
				}
				cg := cr.rule.CorrelationGroup
				if cg == "" {
					cg = obs.CorrelationGroup
				}
				if cg == "" {
					cg = cr.rule.ID
				}
				c := model.Claim{
					ID:               fmt.Sprintf("%s:%d:%s", cr.rule.ID, i, obs.ID),
					Kind:             rc.Kind,
					Vendor:           rc.Vendor,
					Product:          rc.Product,
					Version:          rc.Version,
					Family:           rc.Family,
					DeviceType:       rc.DeviceType,
					Attribute:        rc.Attribute,
					Value:            firstNonEmpty(rc.Value, rc.Product),
					Score:            score,
					Confidence:       model.TierFromScore(score),
					EvidenceIDs:      []string{obs.ID},
					RuleIDs:          []string{cr.rule.ID},
					CorrelationGroup: cg,
					Subject:          obs.AssetID,
				}
				if obs.Endpoint != nil {
					c.Subject = model.EndpointKey(obs.Endpoint.Address, obs.Endpoint.Port, obs.Endpoint.Transport)
				}
				raw = append(raw, c)
			}
		}
	}
	for _, a := range e.adapters {
		claims, err := matchAdapter(a, hydrated)
		if err != nil {
			continue
		}
		raw = append(raw, claims...)
	}
	return Compose(raw)
}

func matchAdapter(a adapters.FingerprintAdapter, obs []model.ObservationRecord) (claims []model.Claim, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("adapter %s panic: %v", a.Name(), rec)
			claims = nil
		}
	}()
	return a.Match(obs)
}

func (e *Engine) hydrate(obs model.ObservationRecord) model.ObservationRecord {
	if e == nil || e.store == nil || obs.ObservationType != model.ObservationHTTP || len(obs.ArtifactIDs) == 0 {
		return obs
	}
	var p model.HTTPObservation
	_ = obs.DecodePayload(&p)
	if p.Body != "" {
		return obs
	}
	for _, id := range obs.ArtifactIDs {
		data, _, err := e.store.Get(id)
		if err != nil || len(data) == 0 {
			continue
		}
		p.Body = string(data)
		_ = obs.SetPayload(p)
		break
	}
	return obs
}

func scoreFromTier(t model.ConfidenceTier) float64 {
	switch t {
	case model.ConfidenceExact:
		return 97
	case model.ConfidenceStrong:
		return 90
	case model.ConfidenceProbable:
		return 78
	case model.ConfidenceHint:
		return 55
	default:
		return 20
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func matchesAll(conds []compiledCond, fields map[string]string) bool {
	if len(conds) == 0 {
		return false
	}
	for _, c := range conds {
		if !matchCond(c, fields) {
			return false
		}
	}
	return true
}

func matchesAny(conds []compiledCond, fields map[string]string) bool {
	for _, c := range conds {
		if matchCond(c, fields) {
			return true
		}
	}
	return false
}

func matchCond(c compiledCond, fields map[string]string) bool {
	val, ok := fields[c.cond.Field]
	if !ok {
		// also try case-insensitive header-style keys
		for k, v := range fields {
			if strings.EqualFold(k, c.cond.Field) {
				val = v
				ok = true
				break
			}
		}
	}
	if !ok {
		return false
	}
	if c.cond.Equals != "" {
		return strings.EqualFold(val, c.cond.Equals)
	}
	if c.cond.Contains != "" {
		return strings.Contains(strings.ToLower(val), strings.ToLower(c.cond.Contains))
	}
	if c.re != nil {
		return c.re.MatchString(val)
	}
	return false
}

// flattenObservation projects observation payload fields into a flat string map.
func flattenObservation(obs model.ObservationRecord) (out map[string]string) {
	out = map[string]string{
		"observation_type": obs.ObservationType,
		"probe_id":         obs.ProbeID,
	}
	defer func() { _ = recover() }()
	if len(obs.Payload) == 0 {
		return out
	}
	var generic map[string]any
	if err := json.Unmarshal(obs.Payload, &generic); err != nil {
		return out
	}
	flatten("", generic, out)
	return out
}

func flatten(prefix string, v any, out map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			flatten(key, val, out)
		}
	case []any:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			parts = append(parts, fmt.Sprint(item))
		}
		out[prefix] = strings.Join(parts, ",")
	case string:
		out[prefix] = t
	case float64:
		out[prefix] = fmt.Sprintf("%v", t)
	case bool:
		out[prefix] = fmt.Sprintf("%v", t)
	case nil:
		// skip
	default:
		out[prefix] = fmt.Sprint(t)
	}
}
