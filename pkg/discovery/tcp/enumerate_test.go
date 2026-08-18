package tcp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
)

func TestEnumerateAllRequestedPorts(t *testing.T) {
	openLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer openLn.Close()
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
	closedLn.Close()

	c, err := NewEnumerate(engine.Config{
		Timeout: 400 * time.Millisecond,
		Ports:   []uint16{openPort, closedPort},
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
	// Engine default profile should expose the PRD curated set.
	p := engine.ProfileFor(engine.ProfileDefault)
	if len(p.TCPPorts) < 60 {
		t.Fatalf("profile default TCP ports=%d", len(p.TCPPorts))
	}
}
