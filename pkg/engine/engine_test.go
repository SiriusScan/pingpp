package engine_test

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/discovery/icmp"
	"github.com/SiriusScan/ping++/pkg/discovery/tcp"
	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	httpcol "github.com/SiriusScan/ping++/pkg/protocol/http"
)

func TestProfilePorts(t *testing.T) {
	q := engine.ProfileFor(engine.ProfileQuick)
	if len(q.TCPPorts) < 3 {
		t.Fatalf("quick ports=%v", q.TCPPorts)
	}
	d := engine.ProfileFor(engine.ProfileDefault)
	if len(d.TCPPorts) < 50 {
		t.Fatalf("default ports too small: %d", len(d.TCPPorts))
	}
	if len(d.UDPPorts) == 0 {
		t.Fatal("default should include UDP priors")
	}
}

func TestPlannerPortPriorsNotIdentity(t *testing.T) {
	reg := engine.BuildDefaultRegistry(icmp.Register, tcp.Register)
	// Register a fake classify collector to exercise planning
	reg.MustRegister("collect.ssh", func(cfg engine.Config) (engine.Collector, error) {
		return &stubCollector{id: "collect.ssh", stage: engine.StageClassify}, nil
	})
	reg.MustRegister("collect.http", func(cfg engine.Config) (engine.Collector, error) {
		return &stubCollector{id: "collect.http", stage: engine.StageClassify}, nil
	})

	p := engine.NewPlanner(reg, engine.ProfileFor(engine.ProfileQuick))
	asset := model.NewAssetFromIP("192.0.2.10")
	asset.AddEndpoint(model.NewEndpoint("192.0.2.10", 22, model.TransportTCP, model.EndpointOpen))
	asset.AddEndpoint(model.NewEndpoint("192.0.2.10", 80, model.TransportTCP, model.EndpointOpen))

	tasks := p.PlanClassification(asset, &engine.ScanState{Completed: map[string]bool{}})
	if len(tasks) == 0 {
		t.Fatal("expected classification tasks")
	}
	// Port 22 should prefer ssh collector first among its tasks
	var sshPriority, httpOn22 int
	for _, task := range tasks {
		if task.Endpoint != nil && task.Endpoint.Port == 22 && task.CollectorID == "collect.ssh" {
			sshPriority = task.Priority
		}
		if task.Endpoint != nil && task.Endpoint.Port == 22 && task.CollectorID == "collect.http" {
			httpOn22++
		}
	}
	if sshPriority == 0 {
		t.Fatal("expected ssh prior for port 22")
	}
	if httpOn22 != 0 {
		t.Fatal("port 22 must not schedule HTTP merely because it is open")
	}
}

func TestPlannerUnknownUDPStillSchedulesProtocolCollectors(t *testing.T) {
	reg := engine.NewRegistry()
	reg.MustRegister("collect.dns", func(cfg engine.Config) (engine.Collector, error) {
		return &scriptedCollector{id: "collect.dns", protocol: "dns", outcome: engine.OutcomeSuccess}, nil
	})
	p := engine.NewPlanner(reg, engine.ProfileFor(engine.ProfileDefault))
	asset := model.NewAssetFromIP("192.0.2.10")
	asset.AddEndpoint(model.NewEndpoint("192.0.2.10", 53, model.TransportUDP, model.EndpointUnknown))
	tasks := p.Next(asset, &engine.ScanState{Completed: map[string]bool{}})
	if len(tasks) != 1 || tasks[0].CollectorID != "collect.dns" {
		t.Fatalf("unknown UDP 53 tasks=%v, want collect.dns", taskIDs(tasks))
	}
}

func TestPlannerClosedUDPIsNotClassified(t *testing.T) {
	reg := engine.NewRegistry()
	reg.MustRegister("collect.dns", func(cfg engine.Config) (engine.Collector, error) {
		return &scriptedCollector{id: "collect.dns", protocol: "dns", outcome: engine.OutcomeSuccess}, nil
	})
	p := engine.NewPlanner(reg, engine.ProfileFor(engine.ProfileDefault))
	asset := model.NewAssetFromIP("192.0.2.10")
	asset.AddEndpoint(model.NewEndpoint("192.0.2.10", 53, model.TransportUDP, model.EndpointClosed))
	tasks := p.Next(asset, &engine.ScanState{Completed: map[string]bool{}})
	if len(tasks) != 0 {
		t.Fatalf("closed UDP must not schedule collectors: %v", taskIDs(tasks))
	}
}

func TestPlannerUnknownPortUsesBannerThenTLS(t *testing.T) {
	reg := engine.NewRegistry()
	for _, id := range []string{"collect.banner", "collect.tls", "collect.http", "collect.ssh"} {
		id := id
		reg.MustRegister(id, func(cfg engine.Config) (engine.Collector, error) {
			return &stubCollector{id: id, stage: engine.StageCollect}, nil
		})
	}
	p := engine.NewPlanner(reg, engine.ProfileFor(engine.ProfileDefault))
	asset := model.NewAssetFromIP("192.0.2.10")
	asset.AddEndpoint(model.NewEndpoint("192.0.2.10", 9999, model.TransportTCP, model.EndpointResponsive))
	tasks := p.PlanClassification(asset, &engine.ScanState{Completed: map[string]bool{}})
	if len(tasks) < 2 {
		t.Fatalf("unknown port sequence too short: %v", taskIDs(tasks))
	}
	if tasks[0].CollectorID != "collect.banner" {
		t.Fatalf("first unknown-port collector=%s want collect.banner", tasks[0].CollectorID)
	}
	if tasks[1].CollectorID != "collect.tls" {
		t.Fatalf("second unknown-port collector=%s want collect.tls", tasks[1].CollectorID)
	}
}

func TestPlannerUDPPortUsesRegistryMetadata(t *testing.T) {
	reg := engine.NewRegistry()
	reg.MustRegister("collect.snmp", func(cfg engine.Config) (engine.Collector, error) {
		return &metaCollector{id: "collect.snmp", stage: engine.StageCollect, ports: []uint16{161}, tr: model.TransportUDP}, nil
	})
	reg.MustRegister("collect.http", func(cfg engine.Config) (engine.Collector, error) {
		return &metaCollector{id: "collect.http", stage: engine.StageCollect, ports: []uint16{80}, tr: model.TransportTCP}, nil
	})
	p := engine.NewPlanner(reg, engine.ProfileFor(engine.ProfileDefault))
	asset := model.NewAssetFromIP("192.0.2.10")
	asset.AddEndpoint(model.NewEndpoint("192.0.2.10", 161, model.TransportUDP, model.EndpointResponsive))
	tasks := p.PlanClassification(asset, &engine.ScanState{Completed: map[string]bool{}})
	if len(tasks) != 1 || tasks[0].CollectorID != "collect.snmp" {
		t.Fatalf("UDP 161 tasks=%v", taskIDs(tasks))
	}
}

func TestEngineEnumerationPipeline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	reg := engine.BuildDefaultRegistry(icmp.Register, tcp.Register)
	eng, err := engine.NewEngine(engine.Options{
		Profile:       engine.ProfileQuick,
		SkipDiscovery: true,
		TCPPorts:      []uint16{port},
		RatePerSecond: 1000,
		Registry:      reg,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := eng.ScanTarget(ctx, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Asset == nil {
		t.Fatal("nil asset")
	}
	found := false
	for _, ep := range res.Asset.Endpoints {
		if ep.Port == port && ep.State == model.EndpointResponsive {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected responsive (connect-only) endpoint %d, got %+v", port, res.Asset.Endpoints)
	}
	if res.State.Reachability.State != model.ReachabilityConfirmed {
		t.Fatalf("reachability=%q", res.State.Reachability.State)
	}
}

func TestProtocolConfirmPromotesEndpointOpen(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Skipf("need 8080 for HTTP prior: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "test-httpd")
			_, _ = w.Write([]byte("<title>ok</title>"))
		}))
	}()

	reg := engine.BuildDefaultRegistry(icmp.Register, tcp.Register, httpcol.Register)
	eng, err := engine.NewEngine(engine.Options{
		Profile:       engine.ProfileDefault,
		SkipDiscovery: true,
		TCPPorts:      []uint16{8080},
		RatePerSecond: 1000,
		Registry:      reg,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	res, err := eng.ScanTarget(ctx, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	var state model.EndpointState
	var sawHTTP bool
	for _, ep := range res.Asset.Endpoints {
		if ep.Port == 8080 {
			state = ep.State
		}
	}
	for _, o := range res.Asset.Observations {
		if o.ObservationType == model.ObservationHTTP {
			sawHTTP = true
		}
	}
	if state != model.EndpointResponsive && state != model.EndpointOpen {
		t.Fatalf("enumerated HTTP prior state=%q, endpoints=%+v", state, res.Asset.Endpoints)
	}
	if !sawHTTP {
		t.Fatal("expected collect.http observation even before HTTP emits ProbeOutcome")
	}
	foundProto := false
	for _, c := range res.Asset.Claims {
		if c.Kind == model.ClaimProtocol && c.Value == "http" {
			foundProto = true
		}
	}
	if !foundProto {
		t.Fatalf("engine must attach endpoint-scoped protocol claims, claims=%+v", res.Asset.Claims)
	}
}

func TestEngineOwnsFingerprints(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	reg := engine.BuildDefaultRegistry(icmp.Register, tcp.Register)
	eng, err := engine.NewEngine(engine.Options{
		Profile:       engine.ProfileQuick,
		SkipDiscovery: true,
		TCPPorts:      []uint16{port},
		RatePerSecond: 1000,
		Registry:      reg,
		Fingerprints: stubMatcher{claims: []model.Claim{{
			Kind: model.ClaimProduct, Product: "nginx", Score: 90,
			Confidence: model.ConfidenceStrong,
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := eng.ScanTarget(ctx, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Asset.Observations) == 0 {
		t.Fatal("expected enumeration observations")
	}
	found := false
	for _, c := range res.Asset.Claims {
		if c.Product == "nginx" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ScanTarget must attach matcher claims: claims=%+v obs=%d", res.Asset.Claims, len(res.Asset.Observations))
	}
}

func TestClassificationPassesHostnameTarget(t *testing.T) {
	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), "localhost")
	if err != nil || len(addrs) == 0 {
		t.Fatalf("resolve localhost: %v", err)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(addrs[0].IP.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	var gotHost string
	reg := engine.BuildDefaultRegistry(icmp.Register, tcp.Register)
	reg.MustRegister("collect.banner", func(cfg engine.Config) (engine.Collector, error) {
		return &hostnameCaptureCollector{host: &gotHost}, nil
	})
	eng, err := engine.NewEngine(engine.Options{
		Profile:       engine.ProfileQuick,
		SkipDiscovery: true,
		TCPPorts:      []uint16{port},
		RatePerSecond: 1000,
		Registry:      reg,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := eng.ScanTarget(ctx, "localhost"); err != nil {
		t.Fatal(err)
	}
	if gotHost != "localhost" {
		t.Fatalf("classification Target.Hostname=%q, want localhost", gotHost)
	}
}

func TestBudgetStopsProbes(t *testing.T) {
	b := engine.DefaultBudget()
	b.MaxProbesPerHost = 2
	b.ProbesUsed = 2
	if b.RemainingProbes() {
		t.Fatal("budget exhausted should not remain")
	}
}

func TestNetworkBudgetStopsLaterCollectors(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	reg := engine.BuildDefaultRegistry(icmp.Register, tcp.Register)
	var classifyRuns atomic.Int32
	reg.MustRegister("collect.http", func(cfg engine.Config) (engine.Collector, error) {
		return countingCollector{id: "collect.http", n: &classifyRuns}, nil
	})
	reg.MustRegister("collect.banner", func(cfg engine.Config) (engine.Collector, error) {
		return countingCollector{id: "collect.banner", n: &classifyRuns}, nil
	})

	eng, err := engine.NewEngine(engine.Options{
		Profile:       engine.ProfileQuick,
		SkipDiscovery: true,
		TCPPorts:      []uint16{port, port + 1, port + 2, port + 3},
		RatePerSecond: 1000,
		Registry:      reg,
		MaxNetworkOps: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := eng.ScanTarget(ctx, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if res.State.Budget.NetworkOps < 1 {
		t.Fatalf("expected network ops from enumerate, got %d", res.State.Budget.NetworkOps)
	}
	if classifyRuns.Load() != 0 {
		t.Fatalf("classification should not run after network budget is spent, runs=%d", classifyRuns.Load())
	}
}

type countingCollector struct {
	id string
	n  *atomic.Int32
}

func (c countingCollector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: c.id, Stage: engine.StageCollect, Priority: 50, Cost: 1}
}

func (c countingCollector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	c.n.Add(1)
	return nil, nil
}

func TestScanResolvedAllAddresses(t *testing.T) {
	reg := engine.BuildDefaultRegistry(icmp.Register, tcp.Register)
	eng, err := engine.NewEngine(engine.Options{
		Profile:       engine.ProfileQuick,
		SkipDiscovery: true,
		TCPPorts:      []uint16{1},
		RatePerSecond: 1000,
		Registry:      reg,
		Fingerprints:  stubMatcher{},
		MaxNetworkOps: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	target := model.NewTargetHostname("multi.test", "192.0.2.10", "192.0.2.11")
	res, err := eng.ScanResolved(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Asset.Addresses) != 2 {
		t.Fatalf("addresses=%v want 2", res.Asset.Addresses)
	}
	if len(res.Asset.Hostnames) == 0 || res.Asset.Hostnames[0] != "multi.test" {
		t.Fatalf("hostnames=%v", res.Asset.Hostnames)
	}
	for _, ip := range []string{"192.0.2.10", "192.0.2.11"} {
		key := "enumerate.tcp:" + ip
		if res.State == nil || !res.State.IsComplete(key) {
			t.Fatalf("missing completed key %s in %+v", key, res.State.Completed)
		}
	}
}

func TestScanResolvedSharesNetworkBudget(t *testing.T) {
	reg := engine.BuildDefaultRegistry(icmp.Register, tcp.Register)
	eng, err := engine.NewEngine(engine.Options{
		Profile:       engine.ProfileQuick,
		SkipDiscovery: true,
		TCPPorts:      []uint16{1, 2, 3, 4},
		RatePerSecond: 1000,
		Registry:      reg,
		Fingerprints:  stubMatcher{},
		MaxNetworkOps: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	target := model.NewTargetHostname("multi.test", "192.0.2.10", "192.0.2.11")
	res, err := eng.ScanResolved(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if res.State.Budget.NetworkOps > 1 {
		t.Fatalf("shared budget exceeded: ops=%d", res.State.Budget.NetworkOps)
	}
}

func TestCollectorPanicIsInternalError(t *testing.T) {
	reg := engine.NewRegistry()
	reg.MustRegister("enumerate.tcp", func(cfg engine.Config) (engine.Collector, error) {
		return &openPortEnumerator{port: 22}, nil
	})
	reg.MustRegister("collect.banner", func(cfg engine.Config) (engine.Collector, error) {
		return panicCollector{id: "collect.banner"}, nil
	})
	eng, err := engine.NewEngine(engine.Options{
		Profile:       engine.ProfileQuick,
		SkipDiscovery: true,
		TCPPorts:      []uint16{22},
		RatePerSecond: 1000,
		Registry:      reg,
		Fingerprints:  stubMatcher{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = eng.ScanResolved(ctx, model.NewTargetIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("panic must not escape scan: %v", err)
	}
}

type panicCollector struct{ id string }

func (p panicCollector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: p.id, Stage: engine.StageCollect, Priority: 20, Cost: 1, Transports: []model.Transport{model.TransportTCP}}
}
func (p panicCollector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	panic("collector boom")
}

func TestRateLimiter(t *testing.T) {
	l := engine.NewRateLimiter(1000)
	done := make(chan struct{})
	if !l.Wait(done) {
		t.Fatal("first wait")
	}
}

type stubCollector struct {
	id    string
	stage engine.Stage
}

func (s *stubCollector) Metadata() engine.CollectorMetadata {
	ports := []uint16{}
	switch s.id {
	case "collect.ssh":
		ports = []uint16{22}
	case "collect.http":
		ports = []uint16{80, 8080, 443, 8443}
	case "collect.tls":
		ports = []uint16{443, 8443}
	}
	return engine.CollectorMetadata{ID: s.id, Stage: s.stage, Priority: 50, Cost: 1, DefaultPorts: ports, Transports: []model.Transport{model.TransportTCP}}
}

type metaCollector struct {
	id    string
	stage engine.Stage
	ports []uint16
	tr    model.Transport
}

func (s *metaCollector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{
		ID: s.id, Stage: s.stage, Priority: 50, Cost: 1,
		DefaultPorts: append([]uint16(nil), s.ports...),
		Transports:   []model.Transport{s.tr},
	}
}

func (s *metaCollector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	return nil, nil
}

func (s *stubCollector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	return nil, nil
}

type hostnameCaptureCollector struct {
	host *string
}

func (c *hostnameCaptureCollector) Metadata() engine.CollectorMetadata {
	return engine.CollectorMetadata{ID: "collect.banner", Stage: engine.StageCollect, Priority: 10, Cost: 1}
}

func (c *hostnameCaptureCollector) Run(ctx context.Context, in engine.CollectorInput) ([]model.ObservationRecord, error) {
	if in.Target != nil && c.host != nil {
		*c.host = in.Target.Hostname
	}
	return nil, nil
}

type stubMatcher struct {
	claims []model.Claim
}

func (s stubMatcher) Match([]model.ObservationRecord) []model.Claim {
	return append([]model.Claim(nil), s.claims...)
}
