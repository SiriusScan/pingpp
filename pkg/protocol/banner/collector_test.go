package banner_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/protocol/banner"
)

func TestBannerReadsBytesWithoutProtocolClaim(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = c.Write([]byte("HELLO-BANNER\r\n"))
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	c, err := banner.New(engine.Config{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointResponsive)
	res, err := c.RunResult(context.Background(), engine.CollectorInput{
		Asset:    model.NewAssetFromIP("127.0.0.1"),
		Endpoint: &ep,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != engine.OutcomeSuccess {
		t.Fatalf("outcome=%q", res.Outcome)
	}
	if res.Protocol != "banner" {
		t.Fatalf("protocol=%q", res.Protocol)
	}
	if len(res.Observations) != 1 {
		t.Fatalf("obs=%d", len(res.Observations))
	}
	if res.Observations[0].ObservationType != model.ObservationBanner {
		t.Fatalf("type=%q", res.Observations[0].ObservationType)
	}
	var payload model.BannerObservation
	if err := res.Observations[0].DecodePayload(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Text == "" || payload.Hex == "" {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestBannerNoMatchOnSilentPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
		_ = c.Close()
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	c, _ := banner.New(engine.Config{Timeout: 80 * time.Millisecond})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointResponsive)
	res, err := c.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != engine.OutcomeNoMatch && res.Outcome != engine.OutcomeTimeout {
		t.Fatalf("silent banner outcome=%q", res.Outcome)
	}
}
