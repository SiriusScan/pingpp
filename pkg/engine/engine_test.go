package engine_test

import (
	"context"
	"net"
	"net/http"
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

func TestEngineEnumerationPipeline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
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
	defer ln.Close()
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
	for _, ep := range res.Asset.Endpoints {
		if ep.Port == 8080 {
			state = ep.State
		}
	}
	if state != model.EndpointOpen {
		t.Fatalf("HTTP-confirmed port state=%q want open, endpoints=%+v", state, res.Asset.Endpoints)
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
	defer ln.Close()
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
	return engine.CollectorMetadata{ID: s.id, Stage: s.stage, Priority: 50, Cost: 1}
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
