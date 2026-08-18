package mqtt_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/protocol/mqtt"
)

func TestMQTTAcceptsCONNACK(t *testing.T) {
	ln := serve(t, []byte{0x20, 0x02, 0x00, 0x00})
	defer func() { _ = ln.Close() }()
	assertOutcome(t, ln, engine.OutcomeSuccess)
}

func TestMQTTRejectsHTTPLookalike(t *testing.T) {
	ln := serve(t, []byte("HTTP/1.1 200 OK\r\n"))
	defer func() { _ = ln.Close() }()
	assertOutcome(t, ln, engine.OutcomeNoMatch)
}

func assertOutcome(t *testing.T, ln net.Listener, want engine.ProbeOutcome) {
	t.Helper()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	c, _ := mqtt.New(engine.Config{Timeout: time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := c.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != want {
		t.Fatalf("outcome=%q want %q", res.Outcome, want)
	}
}

func serve(t *testing.T, reply []byte) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		_, _ = c.Write(reply)
	}()
	return ln
}
