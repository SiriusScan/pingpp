package engine_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
)

func TestPlannerTLSSuccessReplansHTTP(t *testing.T) {
	reg := engine.NewRegistry()
	http := &scriptedCollector{id: "collect.http", protocol: "http", outcome: engine.OutcomeSuccess}
	reg.MustRegister("collect.tls", func(cfg engine.Config) (engine.Collector, error) {
		return &scriptedCollector{id: "collect.tls", protocol: "tls", outcome: engine.OutcomeSuccess}, nil
	})
	reg.MustRegister("collect.http", func(cfg engine.Config) (engine.Collector, error) {
		return http, nil
	})

	res := scanFake(t, withEnumerate(reg, 443), 443)
	if http.runs() != 1 {
		t.Fatalf("HTTP runs=%d, want 1 after TLS success", http.runs())
	}
	if http.lastExtra["tls"] != "1" {
		t.Fatalf("HTTP Extra=%v, want tls=1 from TLS replan", http.lastExtra)
	}
	if !res.State.HasProtocol(model.EndpointKey("127.0.0.1", 443, model.TransportTCP), "tls") {
		t.Fatal("TLS OutcomeSuccess must record protocol match")
	}
}

func TestPlannerSSHSuccessStopsIrrelevantCollectors(t *testing.T) {
	reg := engine.NewRegistry()
	http := &scriptedCollector{id: "collect.http", protocol: "http", outcome: engine.OutcomeSuccess}
	mysql := &scriptedCollector{id: "collect.mysql", protocol: "mysql", outcome: engine.OutcomeSuccess}
	banner := &scriptedCollector{id: "collect.banner", protocol: "banner", outcome: engine.OutcomeSuccess}
	reg.MustRegister("collect.ssh", func(cfg engine.Config) (engine.Collector, error) {
		return &scriptedCollector{id: "collect.ssh", protocol: "ssh", outcome: engine.OutcomeSuccess}, nil
	})
	reg.MustRegister("collect.http", func(cfg engine.Config) (engine.Collector, error) { return http, nil })
	reg.MustRegister("collect.mysql", func(cfg engine.Config) (engine.Collector, error) { return mysql, nil })
	reg.MustRegister("collect.banner", func(cfg engine.Config) (engine.Collector, error) { return banner, nil })

	scanFake(t, withEnumerate(reg, 22), 22)
	if http.runs() != 0 || mysql.runs() != 0 || banner.runs() != 0 {
		t.Fatalf("SSH success must not spray other collectors: http=%d mysql=%d banner=%d", http.runs(), mysql.runs(), banner.runs())
	}
}

func TestPlannerFallbackAfterPortPriorsNoMatch(t *testing.T) {
	reg := engine.NewRegistry()
	ssh := &scriptedCollector{id: "collect.ssh", protocol: "ssh", outcome: engine.OutcomeNoMatch}
	http := &scriptedCollector{id: "collect.http", protocol: "http", outcome: engine.OutcomeSuccess}
	reg.MustRegister("collect.ssh", func(cfg engine.Config) (engine.Collector, error) { return ssh, nil })
	reg.MustRegister("collect.http", func(cfg engine.Config) (engine.Collector, error) { return http, nil })

	scanFake(t, withEnumerate(reg, 22), 22)
	if ssh.runs() != 1 {
		t.Fatalf("SSH prior runs=%d, want 1", ssh.runs())
	}
	if http.runs() != 1 {
		t.Fatalf("HTTP on 22 after SSH NoMatch runs=%d, want 1", http.runs())
	}
}

func TestPlannerRedisOnMySQLPortAfterPriorNoMatch(t *testing.T) {
	reg := engine.NewRegistry()
	mysql := &scriptedCollector{id: "collect.mysql", protocol: "mysql", outcome: engine.OutcomeNoMatch}
	redis := &scriptedCollector{id: "collect.redis", protocol: "redis", outcome: engine.OutcomeSuccess}
	reg.MustRegister("collect.mysql", func(cfg engine.Config) (engine.Collector, error) { return mysql, nil })
	reg.MustRegister("collect.redis", func(cfg engine.Config) (engine.Collector, error) { return redis, nil })

	scanFake(t, withEnumerate(reg, 3306), 3306)
	if mysql.runs() != 1 {
		t.Fatalf("MySQL prior runs=%d, want 1", mysql.runs())
	}
	if redis.runs() != 1 {
		t.Fatalf("Redis on 3306 after MySQL NoMatch runs=%d, want 1", redis.runs())
	}
}

func TestPlannerNoMatchIsNotRetried(t *testing.T) {
	reg := engine.NewRegistry()
	tls := &scriptedCollector{id: "collect.tls", protocol: "tls", outcome: engine.OutcomeNoMatch}
	http := &scriptedCollector{id: "collect.http", protocol: "http", outcome: engine.OutcomeNoMatch}
	reg.MustRegister("collect.tls", func(cfg engine.Config) (engine.Collector, error) { return tls, nil })
	reg.MustRegister("collect.http", func(cfg engine.Config) (engine.Collector, error) { return http, nil })

	res := scanFake(t, withEnumerate(reg, 443), 443)
	if tls.runs() != 1 {
		t.Fatalf("TLS NoMatch runs=%d, want 1", tls.runs())
	}
	key := model.EndpointKey("127.0.0.1", 443, model.TransportTCP)
	if !res.State.IsRuledOut(key, "tls") {
		t.Fatal("NoMatch must rule the protocol out")
	}
	if res.State.HasProtocol(key, "tls") {
		t.Fatal("NoMatch must not record a protocol match")
	}
}

func TestPlannerTerminatesDeterministically(t *testing.T) {
	reg := engine.NewRegistry()
	reg.MustRegister("collect.tls", func(cfg engine.Config) (engine.Collector, error) {
		return &scriptedCollector{id: "collect.tls", protocol: "tls", outcome: engine.OutcomeSuccess}, nil
	})
	reg.MustRegister("collect.http", func(cfg engine.Config) (engine.Collector, error) {
		return &scriptedCollector{id: "collect.http", protocol: "http", outcome: engine.OutcomeSuccess}, nil
	})
	reg = withEnumerate(reg, 443)
	res := scanFake(t, reg, 443)
	p := engine.NewPlanner(reg, engine.ProfileFor(engine.ProfileQuick))
	first := p.Next(res.Asset, res.State)
	second := p.Next(res.Asset, res.State)
	if len(first) != 0 || len(second) != 0 {
		t.Fatalf("planner must be idle after a finished scan: first=%v second=%v", taskIDs(first), taskIDs(second))
	}
}

func TestPlannerSchedulesEnrichmentForWeakHTTP(t *testing.T) {
	reg := engine.NewRegistry()
	enrich := &scriptedCollector{id: "collect.http.enrich", protocol: "http", outcome: engine.OutcomeSuccess}
	reg.MustRegister("collect.http", func(cfg engine.Config) (engine.Collector, error) {
		return &scriptedCollector{id: "collect.http", protocol: "http", outcome: engine.OutcomeSuccess}, nil
	})
	reg.MustRegister("collect.http.enrich", func(cfg engine.Config) (engine.Collector, error) { return enrich, nil })
	scanFakeOpts(t, withEnumerate(reg, 80), 80, stubMatcher{claims: []model.Claim{{
		Kind: model.ClaimProduct, Product: "generic-web", Score: 50,
		Confidence: model.ConfidenceHint, Subject: model.EndpointKey("127.0.0.1", 80, model.TransportTCP),
	}}})
	if enrich.runs() != 1 {
		t.Fatalf("weak HTTP product evidence should schedule one enrichment, runs=%d", enrich.runs())
	}
}

func scanFake(t *testing.T, reg *engine.Registry, port uint16) *engine.ScanResult {
	t.Helper()
	return scanFakeOpts(t, reg, port, stubMatcher{})
}

func scanFakeOpts(t *testing.T, reg *engine.Registry, port uint16, fp engine.Matcher) *engine.ScanResult {
	t.Helper()
	eng, err := engine.NewEngine(engine.Options{
		Profile:       engine.ProfileQuick,
		SkipDiscovery: true,
		TCPPorts:      []uint16{port},
		Registry:      reg,
		Fingerprints:  fp,
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
	return res
}

func taskIDs(tasks []engine.Task) []string {
	out := make([]string, 0, len(tasks))
	for _, task := range tasks {
		out = append(out, task.CollectorID)
	}
	return out
}

type scriptedCollector struct {
	id        string
	protocol  string
	outcome   engine.ProbeOutcome
	mu        sync.Mutex
	n         int
	lastExtra map[string]string
}

func (s *scriptedCollector) Metadata() engine.CollectorMetadata {
	ports := []uint16{}
	tr := []model.Transport{model.TransportTCP}
	prio := 50
	switch s.id {
	case "collect.ssh":
		ports, prio = []uint16{22}, 75
	case "collect.http":
		ports, prio = []uint16{80, 8080, 443, 8443}, 60
	case "collect.tls":
		ports, prio = []uint16{443, 8443}, 70
	case "collect.mysql":
		ports, prio = []uint16{3306}, 55
	case "collect.redis":
		ports, prio = []uint16{6379}, 55
	case "collect.dns":
		ports, prio = []uint16{53}, 60
		tr = []model.Transport{model.TransportUDP, model.TransportTCP}
	case "collect.snmp":
		ports, prio = []uint16{161}, 65
		tr = []model.Transport{model.TransportUDP}
	case "collect.banner":
		prio = 20
	case "collect.http.enrich":
		prio = 10
	}
	return engine.CollectorMetadata{ID: s.id, Stage: engine.StageCollect, Priority: prio, Cost: 1, DefaultPorts: ports, Transports: tr}
}

func (s *scriptedCollector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	res, err := s.RunResult(ctx, in)
	return res.Observations, err
}

func (s *scriptedCollector) RunResult(ctx context.Context, in engine.CollectorInput) (engine.CollectorResult, error) {
	s.mu.Lock()
	s.n++
	if in.Extra != nil {
		s.lastExtra = map[string]string{}
		for k, v := range in.Extra {
			s.lastExtra[k] = v
		}
	}
	s.mu.Unlock()
	if in.Endpoint == nil {
		return engine.CollectorResult{Outcome: s.outcome, Protocol: s.protocol}, nil
	}
	ref := in.Endpoint.Ref()
	obs := model.ObservationRecord{
		ID: s.id, ProbeID: s.id, ObservationType: s.protocol, Endpoint: &ref, CorrelationGroup: s.id,
	}
	return engine.CollectorResult{Outcome: s.outcome, Protocol: s.protocol, Observations: []model.ObservationRecord{obs}}, nil
}

func (s *scriptedCollector) runs() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
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
		ProbeID: "enumerate.tcp", ObservationType: model.ObservationTCPEndpoint, Endpoint: &ref,
	}
	_ = obs.SetPayload(model.TCPEndpointObservation{State: model.EndpointResponsive})
	return []model.ObservationRecord{obs}, nil
}
