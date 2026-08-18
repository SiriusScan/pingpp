package engine_test

import (
	"context"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
)

func TestPlannerSchedulesHTTPAfterTLS(t *testing.T) {
	reg := engine.NewRegistry()
	httpRan := false
	reg.MustRegister("collect.tls", func(cfg engine.Config) (engine.Collector, error) {
		return &scriptedCollector{id: "collect.tls", obsType: model.ObservationTLS, match: true}, nil
	})
	reg.MustRegister("collect.http", func(cfg engine.Config) (engine.Collector, error) {
		return &scriptedCollector{id: "collect.http", obsType: model.ObservationHTTP, match: true, onRun: func() { httpRan = true }}, nil
	})
	reg.MustRegister("collect.mysql", func(cfg engine.Config) (engine.Collector, error) {
		return &scriptedCollector{id: "collect.mysql", obsType: "mysql", match: true}, nil
	})

	eng, err := engine.NewEngine(engine.Options{
		Profile:       engine.ProfileQuick,
		SkipDiscovery: true,
		TCPPorts:      []uint16{443},
		Registry:      withEnumerate(reg, 443),
		Fingerprints:  stubMatcher{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := eng.ScanTarget(ctx, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !httpRan {
		t.Fatal("planner should schedule HTTP after TLS match")
	}
	if !res.State.HasProtocol(model.EndpointKey("127.0.0.1", 443, model.TransportTCP), "tls") {
		t.Fatalf("expected tls match, state=%+v", res.State)
	}
}

func TestPlannerStopsAfterSSH(t *testing.T) {
	reg := engine.NewRegistry()
	var ran []string
	reg.MustRegister("collect.ssh", func(cfg engine.Config) (engine.Collector, error) {
		return &scriptedCollector{id: "collect.ssh", obsType: "ssh", match: true, onRun: func() { ran = append(ran, "collect.ssh") }}, nil
	})
	reg.MustRegister("collect.banner", func(cfg engine.Config) (engine.Collector, error) {
		return &scriptedCollector{id: "collect.banner", obsType: model.ObservationBanner, match: true, onRun: func() { ran = append(ran, "collect.banner") }}, nil
	})
	reg.MustRegister("collect.http", func(cfg engine.Config) (engine.Collector, error) {
		return &scriptedCollector{id: "collect.http", obsType: model.ObservationHTTP, match: true, onRun: func() { ran = append(ran, "collect.http") }}, nil
	})
	eng, err := engine.NewEngine(engine.Options{
		Profile:       engine.ProfileQuick,
		SkipDiscovery: true,
		TCPPorts:      []uint16{22},
		Registry:      withEnumerate(reg, 22),
		Fingerprints:  stubMatcher{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := eng.ScanTarget(ctx, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	for _, id := range ran {
		if id != "collect.ssh" {
			t.Fatalf("SSH match must not continue into %s (ran=%v)", id, ran)
		}
	}
	if len(ran) == 0 {
		t.Fatal("expected SSH collector to run")
	}
}

func TestPlannerSchedulesEnrichmentForWeakHTTP(t *testing.T) {
	reg := engine.NewRegistry()
	enrichRan := false
	reg.MustRegister("collect.http", func(cfg engine.Config) (engine.Collector, error) {
		return &scriptedCollector{id: "collect.http", obsType: model.ObservationHTTP, match: true}, nil
	})
	reg.MustRegister("collect.http.enrich", func(cfg engine.Config) (engine.Collector, error) {
		return &scriptedCollector{id: "collect.http.enrich", obsType: model.ObservationHTTP, match: true, onRun: func() { enrichRan = true }}, nil
	})
	eng, err := engine.NewEngine(engine.Options{
		Profile:       engine.ProfileQuick,
		SkipDiscovery: true,
		TCPPorts:      []uint16{80},
		Registry:      withEnumerate(reg, 80),
		Fingerprints: stubMatcher{claims: []model.Claim{{
			Kind: model.ClaimProduct, Product: "generic-web", Score: 50,
			Confidence: model.ConfidenceHint, Subject: model.EndpointKey("127.0.0.1", 80, model.TransportTCP),
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := eng.ScanTarget(ctx, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if !enrichRan {
		t.Fatal("weak HTTP product evidence should schedule one enrichment")
	}
}

type scriptedCollector struct {
	id      string
	obsType string
	match   bool
	onRun   func()
}

func (s *scriptedCollector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: s.id, Stage: engine.StageCollect, Priority: 50, Cost: 1}
}

func (s *scriptedCollector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	if s.onRun != nil {
		s.onRun()
	}
	if in.Endpoint == nil {
		return nil, nil
	}
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{
		ID:               s.id,
		ProbeID:          s.id,
		ObservationType:  s.obsType,
		Endpoint:         &ref,
		CorrelationGroup: s.id,
	}
	if s.match {
		obs.Completeness = "full"
	} else {
		obs.Completeness = "none"
		obs.Error = "no match"
	}
	return []model.ObservationRecord{obs}, nil
}

func withEnumerate(reg *engine.Registry, port uint16) *engine.Registry {
	reg.MustRegister("enumerate.tcp", func(cfg engine.Config) (engine.Collector, error) {
		return &openPortEnumerator{port: port}, nil
	})
	return reg
}

type openPortEnumerator struct{ port uint16 }

func (e *openPortEnumerator) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: "enumerate.tcp", Stage: engine.StageEnumeration, Priority: 90, Cost: 1}
}

func (e *openPortEnumerator) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	ip := in.PrimaryIP()
	ep := model.NewEndpoint(ip, e.port, model.TransportTCP, model.EndpointResponsive)
	ref := ep.Ref()
	obs := model.ObservationRecord{
		ProbeID: "enumerate.tcp", ObservationType: model.ObservationTCPEndpoint, Endpoint: &ref, Completeness: "full",
	}
	_ = obs.SetPayload(model.TCPEndpointObservation{State: model.EndpointResponsive})
	return []model.ObservationRecord{obs}, nil
}
