package fingerprint_test

import (
	"testing"

	"github.com/SiriusScan/ping++/fingerprints"
	"github.com/SiriusScan/ping++/pkg/fingerprint"
	"github.com/SiriusScan/ping++/pkg/fingerprint/adapters"
	"github.com/SiriusScan/ping++/pkg/model"
)

func TestHTTPApplicationPack(t *testing.T) {
	e := fingerprint.NewEngine()
	if err := e.LoadBuiltinPacks(); err != nil {
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
	_ = e.LoadBuiltinPacks()
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
	_ = e.LoadBuiltinPacks()
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

func TestLoadYAMLUnknownFieldFailsClosed(t *testing.T) {
	e := fingerprint.NewEngine()
	err := e.LoadYAML([]byte(`
id: bad-rule
scope: service
unknown_field: nope
matches:
  - field: server
    equals: nginx
claims:
  - kind: product
    product: nginx
    certainty: strong
`))
	if err == nil {
		t.Fatal("expected unknown YAML field to fail closed")
	}
}

func TestBuiltinCorpusScale(t *testing.T) {
	data, err := fingerprints.FS.ReadFile("recog/ssh_banners.xml")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := adapters.ParseRecogXML(data)
	if err != nil {
		t.Fatal(err)
	}
	if rec.RuleCount() < 100 {
		t.Fatalf("ssh recog rules=%d, want hundreds not two", rec.RuleCount())
	}
	httpXML, err := fingerprints.FS.ReadFile("recog/http_servers.xml")
	if err != nil {
		t.Fatal(err)
	}
	httpRec, err := adapters.ParseRecogXML(httpXML)
	if err != nil {
		t.Fatal(err)
	}
	if httpRec.RuleCount() < 100 {
		t.Fatalf("http recog rules=%d", httpRec.RuleCount())
	}
	wraw, err := fingerprints.FS.ReadFile("wappalyzer/technologies.json")
	if err != nil {
		t.Fatal(err)
	}
	w, err := adapters.ParseWappalyzerJSON(wraw)
	if err != nil {
		t.Fatal(err)
	}
	if w.AppCount() < 20 {
		t.Fatalf("wappalyzer apps=%d, still proof-of-concept scale", w.AppCount())
	}
}
