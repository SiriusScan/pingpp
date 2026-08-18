package fingerprint_test

import (
	"testing"

	"github.com/SiriusScan/ping++/pkg/fingerprint"
	"github.com/SiriusScan/ping++/pkg/model"
)

func TestCanonicalProductAliases(t *testing.T) {
	if fingerprint.CanonicalProduct("Microsoft-IIS/10.0") != "iis" {
		t.Fatalf("got %q", fingerprint.CanonicalProduct("Microsoft-IIS/10.0"))
	}
	if fingerprint.CanonicalProduct("Apache-HTTPD") != "apache" {
		t.Fatalf("httpd alias=%q", fingerprint.CanonicalProduct("Apache-HTTPD"))
	}
	if fingerprint.CanonicalProduct("server") != "" {
		t.Fatal("generic server token must not become a product")
	}
}

func TestCanonicalVersionForms(t *testing.T) {
	if fingerprint.CanonicalVersion("v1.24.0") != "1.24.0" {
		t.Fatalf("%q", fingerprint.CanonicalVersion("v1.24.0"))
	}
	if fingerprint.CanonicalVersion("1.24.0 (Ubuntu)") != "1.24.0" {
		t.Fatalf("%q", fingerprint.CanonicalVersion("1.24.0 (Ubuntu)"))
	}
}

func TestNormalizeObservationIdempotent(t *testing.T) {
	obs := model.ObservationRecord{ID: "o1", ObservationType: model.ObservationHTTP}
	_ = obs.SetPayload(model.HTTPObservation{
		Server:  "  nginx/1.24.0  ",
		Title:   "  Grafana  ",
		Headers: map[string][]string{"server": {" nginx "}},
	})
	once := fingerprint.NormalizeObservation(obs)
	twice := fingerprint.NormalizeObservation(once)
	var a, b model.HTTPObservation
	_ = once.DecodePayload(&a)
	_ = twice.DecodePayload(&b)
	if a.Server != b.Server || a.Title != b.Title {
		t.Fatalf("not idempotent: %+v vs %+v", a, b)
	}
	if a.Server != "nginx/1.24.0" {
		t.Fatalf("server=%q", a.Server)
	}
	var raw model.HTTPObservation
	_ = obs.DecodePayload(&raw)
	if raw.Server != "  nginx/1.24.0  " {
		t.Fatalf("raw mutated: %q", raw.Server)
	}
}

func TestNormalizeDoesNotCollapseContradictions(t *testing.T) {
	e := fingerprint.NewEngine()
	if err := e.LoadBuiltinPacks(); err != nil {
		t.Fatal(err)
	}
	nginx := model.ObservationRecord{ID: "n", ObservationType: model.ObservationHTTP, CorrelationGroup: "g1"}
	_ = nginx.SetPayload(model.HTTPObservation{Server: "nginx/1.24.0"})
	apache := model.ObservationRecord{ID: "a", ObservationType: model.ObservationHTTP, CorrelationGroup: "g2"}
	_ = apache.SetPayload(model.HTTPObservation{Server: "Apache/2.4"})
	claims := e.Match([]model.ObservationRecord{nginx, apache})
	var products []string
	for _, c := range claims {
		if c.Kind == model.ClaimProduct {
			products = append(products, c.Product)
		}
	}
	if len(products) < 2 {
		t.Fatalf("contradictory products collapsed: %+v", claims)
	}
}

func TestUnknownServiceStaysUnknown(t *testing.T) {
	e := fingerprint.NewEngine()
	if err := e.LoadBuiltinPacks(); err != nil {
		t.Fatal(err)
	}
	obs := model.ObservationRecord{ID: "u", ObservationType: model.ObservationBanner}
	_ = obs.SetPayload(model.BannerObservation{Text: "xyzzy-unknown-banner-not-a-product"})
	claims := e.Match([]model.ObservationRecord{obs})
	for _, c := range claims {
		if c.Kind == model.ClaimProduct && c.Confidence >= model.ConfidenceStrong {
			t.Fatalf("unknown banner produced strong product %+v", c)
		}
	}
}

func TestIISAliasStillMatches(t *testing.T) {
	e := fingerprint.NewEngine()
	if err := e.LoadBuiltinPacks(); err != nil {
		t.Fatal(err)
	}
	obs := model.ObservationRecord{ID: "i", ObservationType: model.ObservationHTTP}
	_ = obs.SetPayload(model.HTTPObservation{Server: "  Microsoft-IIS/10.0  "})
	claims := e.Match([]model.ObservationRecord{obs})
	found := false
	for _, c := range claims {
		if c.Kind == model.ClaimProduct && (c.Product == "iis" || c.Product == "IIS" || containsFold(c.Product, "iis")) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected IIS claim, got %+v", claims)
	}
}

func containsFold(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || fingerprint.CanonicalProduct(s) == sub)
}
