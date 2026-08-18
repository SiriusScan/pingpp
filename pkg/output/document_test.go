package output_test

import (
	"strings"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/output"
	"github.com/SiriusScan/ping++/pkg/runner"
)

func TestDocumentSchemaAndText(t *testing.T) {
	asset := model.NewAssetFromIP("93.184.216.34")
	asset.Hostnames = []string{"example.com"}
	ep := model.NewEndpoint("93.184.216.34", 443, model.TransportTCP, model.EndpointOpen)
	asset.AddEndpoint(ep)
	obs := model.ObservationRecord{ObservationType: model.ObservationHTTP, Endpoint: ptr(ep.Ref())}
	_ = obs.SetPayload(model.HTTPObservation{StatusCode: 200, Server: "ECS", Title: "Example Domain"})
	asset.AddObservation(obs)
	asset.AddClaim(model.Claim{Kind: model.ClaimProtocol, Product: "http", Subject: ep.Key(), Confidence: model.ConfidenceExact, Score: 100})

	doc := output.NewDocument("quick", runner.TargetResult{
		Target:  runner.TargetSpec{Input: "example.com", Source: runner.SourceArgv, Kind: runner.TargetHostname},
		Result:  &engine.ScanResult{Asset: asset, State: &engine.ScanState{AssetID: asset.ID, Reachability: model.Reachability{State: model.ReachabilityConfirmed}}},
		Elapsed: time.Second,
	})
	if doc.SchemaVersion != output.SchemaVersion {
		t.Fatalf("schema=%q", doc.SchemaVersion)
	}
	text := doc.Text()
	if !strings.Contains(text, "example.com") || !strings.Contains(text, "http") {
		t.Fatalf("text=%s", text)
	}
}

func TestDocumentShowsResponsiveUnclassified(t *testing.T) {
	asset := model.NewAssetFromIP("34.160.111.145")
	ep := model.NewEndpoint("34.160.111.145", 80, model.TransportTCP, model.EndpointResponsive)
	asset.AddEndpoint(ep)
	doc := output.NewDocument("quick", runner.TargetResult{
		Target:  runner.TargetSpec{Input: "neverssl.com", Kind: runner.TargetHostname},
		Result:  &engine.ScanResult{Asset: asset, State: &engine.ScanState{AssetID: "asset:neverssl.com"}},
		Elapsed: time.Millisecond,
	})
	text := doc.Text()
	if !strings.Contains(text, "responsive") || !strings.Contains(text, "protocol unknown") {
		t.Fatalf("text=%s", text)
	}
	if !strings.Contains(text, "80") {
		t.Fatalf("missing port in %s", text)
	}
}

func ptr[T any](v T) *T { return &v }
