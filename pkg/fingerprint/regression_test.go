package fingerprint_test

import (
	"testing"

	"github.com/SiriusScan/ping++/pkg/fingerprint"
	"github.com/SiriusScan/ping++/pkg/model"
)

func TestReplayObservationsThroughEngine(t *testing.T) {
	e := fingerprint.NewEngine()
	if err := e.LoadBuiltinPacks(); err != nil {
		t.Fatal(err)
	}

	obs := model.ObservationRecord{
		ID: "replay-1", ObservationType: model.ObservationHTTP,
		CorrelationGroup: "http-response:10.0.0.1:443:/",
	}
	_ = obs.SetPayload(model.HTTPObservation{
		StatusCode: 200,
		Server:     "nginx/1.24.0",
		Title:      "Grafana",
	})
	claims := e.Match([]model.ObservationRecord{obs})
	if len(claims) < 2 {
		t.Fatalf("expected nginx+grafana claims, got %+v", claims)
	}
}

func TestDevicePackCiscoTitle(t *testing.T) {
	e := fingerprint.NewEngine()
	_ = e.LoadBuiltinPacks()
	obs := model.ObservationRecord{ID: "d1", ObservationType: model.ObservationHTTP, CorrelationGroup: "cisco_web_ui"}
	_ = obs.SetPayload(model.HTTPObservation{Title: "Cisco Systems Login"})
	claims := e.Match([]model.ObservationRecord{obs})
	found := false
	for _, c := range claims {
		if c.Vendor == "Cisco" && c.Kind == model.ClaimDevice {
			found = true
		}
	}
	if !found {
		t.Fatalf("claims=%+v", claims)
	}
}
