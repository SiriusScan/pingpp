package engine_test

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/discovery/tcp"
	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	httpcol "github.com/SiriusScan/ping++/pkg/protocol/http"
)

func TestScanResolvedIPv6OutcomeMatrix(t *testing.T) {
	ln6, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<title>v6-live</title>"))
	})}
	go func() { _ = srv.Serve(ln6) }()
	t.Cleanup(func() { _ = srv.Close(); _ = ln6.Close() })
	port := uint16(ln6.Addr().(*net.TCPAddr).Port)

	reg := engine.BuildDefaultRegistry(tcp.Register, httpcol.Register)
	eng, err := engine.NewEngine(engine.Options{
		Profile:          engine.ProfileQuick,
		SkipDiscovery:    true,
		SkipICMP:         true,
		TCPPorts:         []uint16{port},
		RatePerSecond:    1000,
		Registry:         reg,
		Fingerprints:     stubMatcher{},
		MaxNetworkOps:    32,
		MaxProbesPerHost: 32,
		ProbeTimeout:     400 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	// Ordered IPv4 then IPv6: refused 127.0.0.2, timeout TEST-NET, live ::1.
	target := model.NewTargetHostname("dual.test", "127.0.0.2", "192.0.2.1", "::1")
	res, err := eng.ScanResolved(ctx, target)
	if err != nil {
		t.Fatal(err)
	}

	byIP := map[string][]model.Endpoint{}
	for _, ep := range res.Asset.Endpoints {
		if ep.Port != port {
			continue
		}
		byIP[ep.Address] = append(byIP[ep.Address], ep)
	}
	refused := byIP["127.0.0.2"]
	if len(refused) == 0 {
		t.Fatalf("missing refused IPv4 endpoints: %+v", res.Asset.Endpoints)
	}
	if refused[0].Execution != model.ExecutionAttempted {
		t.Fatalf("refused execution=%q want attempted (network answered)", refused[0].Execution)
	}
	if refused[0].State != model.EndpointClosed && refused[0].State != model.EndpointUnknown {
		t.Fatalf("refused state=%q", refused[0].State)
	}

	timed := byIP["192.0.2.1"]
	if len(timed) == 0 {
		t.Fatalf("missing TEST-NET endpoints")
	}
	if timed[0].Execution == model.ExecutionNotAttemptedBudget || timed[0].Execution == model.ExecutionNotAttemptedCancelled {
		t.Fatalf("timeout address recorded as never-asked: %q", timed[0].Execution)
	}

	live := byIP["::1"]
	if len(live) == 0 {
		t.Fatalf("missing IPv6 live endpoints")
	}
	if live[0].Execution == model.ExecutionNotAttemptedBudget {
		t.Fatal("IPv6 sibling starved by IPv4 probes")
	}
}

func TestScanResolvedBudgetSkipDistinctFromNegativeAnswer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
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
	reg := engine.BuildDefaultRegistry(tcp.Register)
	eng, err := engine.NewEngine(engine.Options{
		Profile:       engine.ProfileQuick,
		SkipDiscovery: true,
		SkipICMP:      true,
		TCPPorts:      []uint16{port},
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
	target := model.NewTargetHostname("budget.test", "127.0.0.1", "::1")
	res, err := eng.ScanResolved(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	var sawAttempted bool
	var sawLiveIPv6Addr bool
	var v6Attempted bool
	for _, a := range res.Asset.Addresses {
		if a.IP == "::1" {
			sawLiveIPv6Addr = true
		}
	}
	for _, ep := range res.Asset.Endpoints {
		switch {
		case ep.Address == "127.0.0.1" && (ep.Execution == model.ExecutionAttempted || ep.Execution == model.ExecutionTimedOut):
			sawAttempted = true
		case ep.Address == "::1" && ep.Execution == model.ExecutionAttempted:
			v6Attempted = true
		}
	}
	if !sawAttempted {
		t.Fatalf("expected IPv4 address attempted, endpoints=%+v", res.Asset.Endpoints)
	}
	if !sawLiveIPv6Addr {
		t.Fatalf("expected IPv6 sibling retained on logical asset, addresses=%v", res.Asset.Addresses)
	}
	if v6Attempted {
		t.Fatal("exhausted budget still probed IPv6 sibling")
	}
}
