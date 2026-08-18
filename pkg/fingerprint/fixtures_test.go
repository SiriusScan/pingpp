package fingerprint_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/SiriusScan/ping++/pkg/fingerprint"
	"github.com/SiriusScan/ping++/pkg/model"
	"gopkg.in/yaml.v3"
)

type fixtureFile struct {
	ObservationType string         `yaml:"observation_type"`
	RuleIDs         []string       `yaml:"rule_ids"`
	Payload         map[string]any `yaml:"payload"`
	Expect          *fixtureExpect `yaml:"expect"`
	Reject          *fixtureReject `yaml:"reject"`
}

type fixtureExpect struct {
	Product       string `yaml:"product"`
	Vendor        string `yaml:"vendor"`
	MinConfidence string `yaml:"min_confidence"`
}

type fixtureReject struct {
	Product string `yaml:"product"`
	Vendor  string `yaml:"vendor"`
}

func TestFixtureCorpus(t *testing.T) {
	e := fingerprint.NewEngine()
	if err := e.LoadBuiltinPacks(); err != nil {
		t.Fatal(err)
	}
	root := fixtureRoot(t)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var fx fixtureFile
		if err := yaml.Unmarshal(raw, &fx); err != nil {
			t.Errorf("%s: %v", path, err)
			return nil
		}
		obs := model.ObservationRecord{ID: path, ObservationType: fx.ObservationType, CorrelationGroup: path}
		if err := obs.SetPayload(fx.Payload); err != nil {
			t.Errorf("%s payload: %v", path, err)
			return nil
		}
		claims := e.Match([]model.ObservationRecord{obs})
		rel, _ := filepath.Rel(root, path)
		if fx.Expect != nil {
			if !claimMatches(claims, fx.Expect.Product, fx.Expect.Vendor, fx.Expect.MinConfidence) {
				t.Errorf("%s: expected %s/%s >= %s, got %+v", rel, fx.Expect.Vendor, fx.Expect.Product, fx.Expect.MinConfidence, claims)
			}
		}
		if fx.Reject != nil {
			if claimMatches(claims, fx.Reject.Product, fx.Reject.Vendor, "") {
				t.Errorf("%s: rejected %s/%s still present in %+v", rel, fx.Reject.Vendor, fx.Reject.Product, claims)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestStrongExactYAMLRulesHaveNegativeFixtures(t *testing.T) {
	e := fingerprint.NewEngine()
	if err := e.LoadBuiltinPacks(); err != nil {
		t.Fatal(err)
	}
	negs := collectNegatives(t)
	for _, r := range e.YAMLRules() {
		for _, c := range r.Claims {
			if c.Certainty != model.ConfidenceStrong && c.Certainty != model.ConfidenceExact {
				continue
			}
			if !negativeCoversRule(r, c, negs) {
				t.Errorf("strong/exact rule %s claim %s/%s (obs=%s) has no rule- or product-tied negative fixture", r.ID, c.Vendor, c.Product, r.Inputs.ObservationType)
			}
		}
	}
}

type negativeFixture struct {
	obsType string
	ruleIDs []string
	reject  fixtureReject
}

func collectNegatives(t *testing.T) []negativeFixture {
	t.Helper()
	var out []negativeFixture
	root := fixtureRoot(t)
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.Contains(path, string(filepath.Separator)+"negative"+string(filepath.Separator)) {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var fx fixtureFile
		if err := yaml.Unmarshal(raw, &fx); err != nil || fx.Reject == nil {
			return nil
		}
		out = append(out, negativeFixture{obsType: fx.ObservationType, ruleIDs: fx.RuleIDs, reject: *fx.Reject})
		return nil
	})
	return out
}

func negativeCoversRule(r fingerprint.Rule, c fingerprint.RuleClaim, negs []negativeFixture) bool {
	for _, n := range negs {
		for _, id := range n.ruleIDs {
			if id == r.ID {
				return true
			}
		}
		if c.Product == "" {
			continue
		}
		if n.reject.Product != c.Product {
			continue
		}
		if r.Inputs.ObservationType != "" && n.obsType != "" && n.obsType != r.Inputs.ObservationType {
			continue
		}
		return true
	}
	return false
}

func claimMatches(claims []model.Claim, product, vendor, min string) bool {
	want := minRank(min)
	for _, c := range claims {
		if product != "" && c.Product != product {
			continue
		}
		if vendor != "" && c.Vendor != vendor {
			continue
		}
		if product == "" && vendor == "" {
			continue
		}
		if rank(c.Confidence) >= want {
			return true
		}
	}
	return false
}

func minRank(s string) int {
	if s == "" {
		return 0
	}
	return rank(model.ConfidenceTier(s))
}

func rank(t model.ConfidenceTier) int {
	switch t {
	case model.ConfidenceExact:
		return 4
	case model.ConfidenceStrong:
		return 3
	case model.ConfidenceProbable:
		return 2
	case model.ConfidenceHint:
		return 1
	default:
		return 0
	}
}

func fixtureRoot(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "testdata", "fingerprints"))
}
