package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
)

func TestDocumentKeepsFullObservationPayloads(t *testing.T) {
	asset := model.NewAssetFromIP("54.84.197.231")
	asset.Hostnames = []string{"n8n.shimcounty.com"}
	asset.AddEndpoint(model.NewEndpoint("54.84.197.231", 21, model.TransportTCP, model.EndpointResponsive))
	asset.AddEndpoint(model.NewEndpoint("54.84.197.231", 53, model.TransportTCP, model.EndpointOpen))
	obs := model.ObservationRecord{
		ID:              "obs:dns:1",
		ProbeID:         "collect.dns",
		ObservationType: "dns",
		Endpoint:        &model.EndpointRef{Address: "54.84.197.231", Port: 53, Transport: model.TransportTCP},
	}
	answers := []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"}
	if err := obs.SetPayload(map[string]any{
		"responded": true,
		"answers":   answers,
		"server":    "54.84.197.231",
	}); err != nil {
		t.Fatal(err)
	}
	asset.AddObservation(obs)

	doc := buildDocument("n8n.shimcounty.com", engine.ProfileDefault, &engine.ScanResult{
		Asset: asset,
		State: &engine.ScanState{
			AssetID:   asset.ID,
			Completed: map[string]bool{"collect.dns:54.84.197.231/tcp/53": true},
		},
	}, time.Second)

	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range answers {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("JSON dropped DNS answer %q:\n%s", want, raw)
		}
	}

	text := doc.Text()
	if strings.Contains(text, "…") || strings.Contains(text, "...") {
		t.Fatalf("text dump truncated:\n%s", text)
	}
	if !strings.Contains(text, "tcp/21") || !strings.Contains(text, "responsive") {
		t.Fatalf("missing connect-only endpoint:\n%s", text)
	}
	if !strings.Contains(text, answers[0]) {
		t.Fatalf("text dump dropped DNS answer:\n%s", text)
	}
}
