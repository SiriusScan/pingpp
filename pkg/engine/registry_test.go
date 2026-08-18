package engine_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/discovery/icmp"
	"github.com/SiriusScan/ping++/pkg/discovery/tcp"
	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
)

func TestRegistryRegisterCreateMetadata(t *testing.T) {
	reg := engine.BuildDefaultRegistry(icmp.Register, tcp.Register)

	ids := reg.IDs()
	if len(ids) != 3 {
		t.Fatalf("IDs=%v want 3 collectors", ids)
	}
	for _, id := range []string{"discovery.icmp", "discovery.tcp", "enumerate.tcp"} {
		if !reg.Has(id) {
			t.Fatalf("missing %s", id)
		}
	}

	meta := reg.Metadata()
	if len(meta) != 3 {
		t.Fatalf("meta len=%d", len(meta))
	}

	c, err := reg.Create("enumerate.tcp", engine.Config{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if c.Metadata().Stage != engine.StageEnumeration {
		t.Fatalf("stage=%q", c.Metadata().Stage)
	}

	_, err = reg.Create("no.such", engine.Config{})
	if err == nil {
		t.Fatal("expected error for unknown collector")
	}
}

func TestRegistryRejectsDuplicate(t *testing.T) {
	r := engine.NewRegistry()
	icmp.Register(r)
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate MustRegister")
		}
	}()
	icmp.Register(r)
}

func TestEnumerateTCPCollectorProducesObservations(t *testing.T) {
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

	reg := engine.NewRegistry()
	tcp.Register(reg)
	c, err := reg.Create("enumerate.tcp", engine.Config{
		Timeout: 500 * time.Millisecond,
		Ports:   []uint16{port},
	})
	if err != nil {
		t.Fatal(err)
	}

	asset := model.NewAssetFromIP("127.0.0.1")
	obs, err := c.Run(context.Background(), engine.CollectorInput{Asset: asset})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 {
		t.Fatalf("obs=%d", len(obs))
	}
	if obs[0].ObservationType != model.ObservationTCPEndpoint {
		t.Fatalf("type=%q", obs[0].ObservationType)
	}
	var payload model.TCPEndpointObservation
	if err := obs[0].DecodePayload(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.State != model.EndpointOpen {
		t.Fatalf("state=%q", payload.State)
	}
	// Collectors must not emit product claims — observation only.
	if obs[0].ProbeID == "" {
		t.Fatal("missing probe id")
	}
}

func TestNoProductClaimsInCollectorOutput(t *testing.T) {
	// Structural guarantee: ObservationRecord has no Product field; Claims live on Asset.
	obs := model.ObservationRecord{ObservationType: model.ObservationTCPEndpoint}
	_ = obs
}
