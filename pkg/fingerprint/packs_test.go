package fingerprint_test

import (
	"testing"

	"github.com/SiriusScan/ping++/pkg/fingerprint"
	"github.com/SiriusScan/ping++/pkg/model"
)

func TestHTTPApplicationPack(t *testing.T) {
	e := fingerprint.NewEngine()
	if err := e.LoadBuiltinPacks(fingerprint.RepoFingerprintsRoot()); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		title, server, gen, wantProduct string
		kind                            model.ClaimKind
	}{
		{"Grafana", "nginx", "", "Grafana", model.ClaimApplication},
		{"Jenkins", "Jetty", "", "Jenkins", model.ClaimApplication},
		{"", "nginx/1.24", "", "nginx", model.ClaimProduct},
		{"", "Microsoft-IIS/10.0", "", "IIS", model.ClaimProduct},
		{"", "", "WordPress 6.4", "WordPress", model.ClaimApplication},
	}
	for _, tc := range cases {
		obs := model.ObservationRecord{ID: "o1", ObservationType: model.ObservationHTTP, CorrelationGroup: "http-response:t"}
		_ = obs.SetPayload(model.HTTPObservation{Title: tc.title, Server: tc.server, MetaGenerator: tc.gen})
		claims := e.Match([]model.ObservationRecord{obs})
		found := false
		for _, c := range claims {
			if c.Product == tc.wantProduct && c.Kind == tc.kind {
				found = true
			}
		}
		if !found {
			t.Fatalf("title=%q server=%q want %s/%s got %+v", tc.title, tc.server, tc.kind, tc.wantProduct, claims)
		}
	}
}

func TestAppliancePackNegativeLookalike(t *testing.T) {
	e := fingerprint.NewEngine()
	_ = e.LoadBuiltinPacks(fingerprint.RepoFingerprintsRoot())
	obs := model.ObservationRecord{ID: "o2", ObservationType: model.ObservationHTTP, CorrelationGroup: "http-response:t"}
	_ = obs.SetPayload(model.HTTPObservation{Title: "Welcome", Server: "Apache"})
	claims := e.Match([]model.ObservationRecord{obs})
	for _, c := range claims {
		if c.Vendor == "Cisco" || c.Product == "Cisco" {
			t.Fatalf("false positive Cisco on generic page: %+v", c)
		}
	}
}

func TestCorrelatedHTTPServerSignals(t *testing.T) {
	e := fingerprint.NewEngine()
	_ = e.LoadBuiltinPacks(fingerprint.RepoFingerprintsRoot())
	obs := model.ObservationRecord{ID: "o3", ObservationType: model.ObservationHTTP, CorrelationGroup: "http-response:same"}
	_ = obs.SetPayload(model.HTTPObservation{Server: "nginx", Title: "nginx"})
	claims := e.Match([]model.ObservationRecord{obs})
	var nginxClaims int
	for _, c := range claims {
		if c.Product == "nginx" {
			nginxClaims++
		}
	}
	if nginxClaims != 1 {
		t.Fatalf("expected single fused nginx claim, got %d (%+v)", nginxClaims, claims)
	}
}
