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

func TestScanResolvedDeadAddressDoesNotStarveSibling(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("127.0.0.2 not bindable: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "live-httpd")
		_, _ = w.Write([]byte("<title>live-sibling</title>"))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close(); _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	dead := "127.0.0.1"
	live := "127.0.0.2"
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
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	// 127.0.0.1 sorts before 127.0.0.2, so the dead loopback is probed first.
	target := model.NewTargetHostname("multi.test", live, dead)
	res, err := eng.ScanResolved(ctx, target)
	if err != nil {
		t.Fatal(err)
	}

	var sawLiveHTTP bool
	for _, o := range res.Asset.Observations {
		if o.ObservationType != model.ObservationHTTP {
			continue
		}
		if o.Endpoint == nil {
			t.Fatal("HTTP observation missing endpoint")
		}
		if o.Endpoint.Address != live {
			t.Fatalf("HTTP evidence attributed to %s want %s", o.Endpoint.Address, live)
		}
		var p model.HTTPObservation
		if err := o.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.TransportIP != "" && p.TransportIP != live {
			t.Fatalf("transport_ip=%s want %s", p.TransportIP, live)
		}
		if p.StatusCode == 200 && p.Title == "live-sibling" {
			sawLiveHTTP = true
		}
	}
	if !sawLiveHTTP {
		t.Fatalf("dead first address starved live sibling; observations=%d endpoints=%+v", len(res.Asset.Observations), res.Asset.Endpoints)
	}
}
