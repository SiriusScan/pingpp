package udp

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
)

func TestClassifyUDPSilenceIsUnknown(t *testing.T) {
	if got := classifyUDPErr(context.DeadlineExceeded); got != model.EndpointUnknown {
		t.Fatalf("deadline=%q", got)
	}
	if got := classifyUDPErr(fmt.Errorf("read udp: i/o timeout")); got != model.EndpointUnknown {
		t.Fatalf("timeout=%q", got)
	}
	if got := classifyUDPErr(fmt.Errorf("read: connection refused")); got != model.EndpointClosed {
		t.Fatalf("refused=%q", got)
	}
}

func TestEnumerateUDPReportsResponsivePort(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	go func() {
		buf := make([]byte, 64)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(buf[:n], addr)
	}()

	c, err := NewEnumerate(engine.Config{
		Timeout:  400 * time.Millisecond,
		UDPPorts: []uint16{port},
	})
	if err != nil {
		t.Fatal(err)
	}
	obs, err := c.Run(context.Background(), engine.CollectorInput{
		Asset: model.NewAssetFromIP("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 {
		t.Fatalf("obs=%d", len(obs))
	}
	var p model.UDPEndpointObservation
	_ = obs[0].DecodePayload(&p)
	if p.State != model.EndpointResponsive {
		t.Fatalf("state=%q want responsive", p.State)
	}
	if obs[0].Endpoint == nil || obs[0].Endpoint.Transport != model.TransportUDP {
		t.Fatalf("endpoint=%+v", obs[0].Endpoint)
	}
}

func TestEnumerateUDPSilenceIsUnknown(t *testing.T) {
	c, err := NewEnumerate(engine.Config{
		Timeout:  200 * time.Millisecond,
		UDPPorts: []uint16{1},
	})
	if err != nil {
		t.Fatal(err)
	}
	obs, err := c.Run(context.Background(), engine.CollectorInput{
		Asset: model.NewAssetFromIP("192.0.2.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 {
		t.Fatalf("silence must still emit a UDP candidate, obs=%d", len(obs))
	}
	var p model.UDPEndpointObservation
	_ = obs[0].DecodePayload(&p)
	if p.State != model.EndpointUnknown {
		t.Fatalf("state=%q want unknown (silence is not exclusion)", p.State)
	}
}

func TestEnumerateUDPClosedOnPortUnreachable(t *testing.T) {
	c, err := NewEnumerate(engine.Config{
		Timeout:  300 * time.Millisecond,
		UDPPorts: []uint16{1},
	})
	if err != nil {
		t.Fatal(err)
	}
	obs, err := c.Run(context.Background(), engine.CollectorInput{
		Asset: model.NewAssetFromIP("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 {
		t.Fatalf("obs=%d", len(obs))
	}
	var p model.UDPEndpointObservation
	_ = obs[0].DecodePayload(&p)
	if p.State != model.EndpointClosed && p.State != model.EndpointUnknown {
		t.Fatalf("localhost UDP/1 state=%q want closed or unknown", p.State)
	}
}
