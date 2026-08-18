package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
)

func sampleDoc() ScanDocument {
	asset := model.NewAssetFromIP("54.84.197.231")
	asset.Hostnames = []string{"n8n.shimcounty.com"}
	asset.AddEndpoint(model.NewEndpoint("54.84.197.231", 21, model.TransportTCP, model.EndpointResponsive))
	asset.AddEndpoint(model.NewEndpoint("54.84.197.231", 53, model.TransportTCP, model.EndpointOpen))
	asset.AddEndpoint(model.NewEndpoint("54.84.197.231", 443, model.TransportTCP, model.EndpointOpen))
	asset.AddEndpoint(model.NewEndpoint("54.84.197.231", 22, model.TransportTCP, model.EndpointClosed))

	dns := model.ObservationRecord{
		ID:              "obs:dns:1",
		ProbeID:         "collect.dns",
		ObservationType: "dns",
		Completeness:    "full",
		Endpoint:        &model.EndpointRef{Address: "54.84.197.231", Port: 53, Transport: model.TransportTCP},
	}
	answers := []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"}
	_ = dns.SetPayload(map[string]any{"responded": true, "answers": answers, "server": "54.84.197.231"})
	asset.AddObservation(dns)

	httpObs := model.ObservationRecord{
		ID: "obs:http:1", ProbeID: "collect.http", ObservationType: model.ObservationHTTP,
		Completeness: "full",
		Endpoint:     &model.EndpointRef{Address: "54.84.197.231", Port: 443, Transport: model.TransportTCP},
	}
	_ = httpObs.SetPayload(model.HTTPObservation{StatusCode: 200, Server: "nginx/1.24.0", Title: "Grafana"})
	asset.AddObservation(httpObs)

	miss := model.ObservationRecord{
		ID: "obs:ssh:miss", ProbeID: "collect.ssh", ObservationType: model.ObservationSSH,
		Completeness: "none", Error: "not ssh",
		Endpoint: &model.EndpointRef{Address: "54.84.197.231", Port: 443, Transport: model.TransportTCP},
	}
	asset.AddObservation(miss)

	asset.AddClaim(model.Claim{Kind: model.ClaimProtocol, Product: "http", Subject: "54.84.197.231/tcp/443", Score: 90, Confidence: model.ConfidenceStrong})
	asset.AddClaim(model.Claim{Kind: model.ClaimProduct, Vendor: "F5", Product: "nginx", Version: "1.24.0", Subject: "54.84.197.231/tcp/443", Score: 90, Confidence: model.ConfidenceStrong})
	asset.AddClaim(model.Claim{Kind: model.ClaimApplication, Vendor: "Grafana Labs", Product: "Grafana", Subject: "54.84.197.231/tcp/443", Score: 55, Confidence: model.ConfidenceHint})
	asset.AddClaim(model.Claim{Kind: model.ClaimProtocol, Product: "dns", Subject: "54.84.197.231/tcp/53", Score: 90, Confidence: model.ConfidenceStrong})

	return buildDocument("n8n.shimcounty.com", engine.ProfileDefault, &engine.ScanResult{
		Asset: asset,
		State: &engine.ScanState{
			AssetID:      asset.ID,
			Reachability: model.Reachability{State: model.ReachabilityConfirmed, Reasons: []string{"tcp.open"}},
			Completed:    map[string]bool{"collect.dns:54.84.197.231/tcp/53": true},
		},
	}, time.Second)
}

func TestDocumentKeepsFullObservationPayloads(t *testing.T) {
	doc := sampleDoc()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("JSON dropped DNS answer %q:\n%s", want, raw)
		}
	}

	verbose := doc.Verbose()
	if strings.Contains(verbose, "…") || strings.Contains(verbose, "...") {
		t.Fatalf("verbose dump truncated:\n%s", verbose)
	}
	if !strings.Contains(verbose, "tcp/21") || !strings.Contains(verbose, "responsive") {
		t.Fatalf("missing connect-only endpoint:\n%s", verbose)
	}
	if !strings.Contains(verbose, "93.184.216.34") {
		t.Fatalf("verbose dump dropped DNS answer:\n%s", verbose)
	}
}

func TestFindingsReportShowsAllPositiveMatches(t *testing.T) {
	doc := sampleDoc()
	text := doc.Text()
	for _, want := range []string{
		"tcp/53", "protocol     dns",
		"93.184.216.34",
		"tcp/443",
		"protocol     http",
		"product      F5 nginx 1.24.0  strong  90",
		"application  Grafana Labs Grafana  hint  55",
		`title="Grafana"`,
		"server=nginx/1.24.0",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in findings:\n%s", want, text)
		}
	}
	if strings.Contains(text, "tcp/22") {
		t.Fatalf("closed port leaked into findings:\n%s", text)
	}
	if strings.Contains(text, "tcp/21") || strings.Contains(text, "responsive") {
		t.Fatalf("connect-only/responsive port leaked into findings:\n%s", text)
	}
	if strings.Contains(text, "not ssh") {
		t.Fatalf("negative observation leaked into findings:\n%s", text)
	}
}
