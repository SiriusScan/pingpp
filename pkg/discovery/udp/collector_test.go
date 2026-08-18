package udp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
)

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
