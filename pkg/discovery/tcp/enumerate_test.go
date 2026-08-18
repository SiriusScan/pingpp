package tcp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/transport"
)

func TestEnumerateAllRequestedPorts(t *testing.T) {
	openLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = openLn.Close() }()
	go func() {
		for {
			c, err := openLn.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	openPort := uint16(openLn.Addr().(*net.TCPAddr).Port)

	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := uint16(closedLn.Addr().(*net.TCPAddr).Port)
	_ = closedLn.Close()

	c, err := NewEnumerate(engine.Config{
		Timeout:     400 * time.Millisecond,
		Ports:       []uint16{openPort, closedPort},
		Concurrency: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	asset := model.NewAssetFromIP("127.0.0.1")
	obs, err := c.Run(context.Background(), engine.CollectorInput{Asset: asset})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 2 {
		t.Fatalf("want observation per port, got %d", len(obs))
	}

	states := map[uint16]model.EndpointState{}
	for _, o := range obs {
		var p model.TCPEndpointObservation
		_ = o.DecodePayload(&p)
		states[o.Endpoint.Port] = p.State
	}
	if states[openPort] != model.EndpointResponsive {
		t.Fatalf("connect-only port state=%q want responsive", states[openPort])
	}
	if states[closedPort] != model.EndpointClosed {
		t.Fatalf("closed port state=%q (want closed/RST)", states[closedPort])
	}
}

func TestDefaultPortsCurated(t *testing.T) {
	if len(DefaultPorts) < 5 {
		t.Fatalf("DefaultPorts=%v", DefaultPorts)
	}
	p := engine.ProfileFor(engine.ProfileDefault)
	if len(p.TCPPorts) < 60 {
		t.Fatalf("profile default TCP ports=%d", len(p.TCPPorts))
	}
}

func TestEnumerateFilteredPortsConcurrent(t *testing.T) {
	const n = 48
	ports := make([]uint16, n)
	for i := range ports {
		ports[i] = uint16(20000 + i)
	}
	timeout := 120 * time.Millisecond
	c, err := NewEnumerate(engine.Config{
		Timeout:     timeout,
		Ports:       ports,
		Concurrency: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	meter := &transport.Meter{}
	ctx := transport.WithMeter(context.Background(), meter)
	start := time.Now()
	obs, err := c.Run(ctx, engine.CollectorInput{Asset: model.NewAssetFromIP("192.0.2.1")})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != n {
		t.Fatalf("want %d observations, got %d", n, len(obs))
	}
	ops, _, _, _ := meter.Snapshot()
	if ops < n {
		t.Fatalf("network ops=%d, want at least %d dials", ops, n)
	}
	// Sequential would be n*timeout. Concurrent workers should beat half of that
	// when the target actually times out. Immediate unreachability is also OK.
	if elapsed > timeout*time.Duration(n)/2 {
		t.Fatalf("filtered enumerate wall time %v too close to sequential %v", elapsed, timeout*time.Duration(n))
	}
}

func TestEnumerateRespectsCancel(t *testing.T) {
	ports := make([]uint16, 40)
	for i := range ports {
		ports[i] = uint16(21000 + i)
	}
	c, err := NewEnumerate(engine.Config{
		Timeout:     2 * time.Second,
		Ports:       ports,
		Concurrency: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err = c.Run(ctx, engine.CollectorInput{Asset: model.NewAssetFromIP("192.0.2.1")})
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Fatalf("cancel took %v", elapsed)
	}
	if err == nil {
		t.Fatal("expected context error after cancel")
	}
}

func TestEnumerateStopsAtNetworkBudget(t *testing.T) {
	ports := []uint16{22001, 22002, 22003, 22004, 22005}
	c, err := NewEnumerate(engine.Config{
		Timeout:     200 * time.Millisecond,
		Ports:       ports,
		Concurrency: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	meter := &transport.Meter{MaxNetworkOps: 2}
	ctx := transport.WithMeter(context.Background(), meter)
	obs, _ := c.Run(ctx, engine.CollectorInput{Asset: model.NewAssetFromIP("127.0.0.1")})
	ops, _, _, _ := meter.Snapshot()
	if ops > 2 {
		t.Fatalf("ops=%d, want budget cap 2", ops)
	}
	unknown := 0
	for _, o := range obs {
		var p model.TCPEndpointObservation
		_ = o.DecodePayload(&p)
		if p.State == model.EndpointUnknown {
			unknown++
		}
	}
	if unknown == 0 && len(obs) != 2 {
		t.Fatalf("budget should leave unprobed/unknown ports, obs=%d unknown=%d", len(obs), unknown)
	}
}
