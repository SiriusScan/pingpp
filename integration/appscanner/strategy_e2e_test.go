package appscanner

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/output"
	"github.com/SiriusScan/ping++/pkg/scan"
)

func TestStrategyDefaultsToEnginePath(t *testing.T) {
	s := NewStrategy()
	if s.UseLegacyRunner {
		t.Fatal("UseLegacyRunner must default false; Engine/Session is the supported path")
	}
}

func TestAdapterEngineSessionToSiriusHost(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		_, _ = w.Write([]byte("<title>adapter-e2e</title>"))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close(); _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	res, err := scan.Scan(ctx, "127.0.0.1", scan.ScanOptions{
		Options: engine.Options{
			Profile:       engine.ProfileQuick,
			SkipDiscovery: true,
			SkipICMP:      true,
			ProbeTypes:    []string{"tcp", "http"},
			TCPPorts:      []uint16{port},
			RatePerSecond: 1000,
		},
		Timeout: 8 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	alive := res.State.Reachability.State == "confirmed" || res.State.Reachability.State == "probable"
	host := output.ToSiriusHost(res.Asset, alive)
	if host["ip"] != "127.0.0.1" {
		t.Fatalf("ip=%v", host["ip"])
	}
	eps, ok := host["endpoints"].([]map[string]interface{})
	if !ok || len(eps) == 0 {
		t.Fatalf("endpoints=%v", host["endpoints"])
	}
	if _, ok := host["claims"]; !ok {
		t.Fatal("missing claims")
	}
	sawPort := false
	for _, ep := range eps {
		if ep["port"] == port || ep["port"] == int(port) || ep["port"] == float64(port) {
			sawPort = true
			if ep["address"] != "127.0.0.1" {
				t.Fatalf("endpoint address=%v", ep["address"])
			}
		}
	}
	if !sawPort {
		t.Fatalf("listener port %d missing from %+v", port, eps)
	}
}
