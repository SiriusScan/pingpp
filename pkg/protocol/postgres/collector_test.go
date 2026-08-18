package postgres_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/protocol/postgres"
)

func TestPostgresMatchSN(t *testing.T) {
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
		buf := make([]byte, 8)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("N"))
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	c, _ := postgres.New(engine.Config{Timeout: time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := c.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != engine.OutcomeSuccess {
		t.Fatalf("outcome=%q", res.Outcome)
	}
}

func TestPostgresRejectsHTTP(t *testing.T) {
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
		buf := make([]byte, 8)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("HTTP/1.1"))
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	c, _ := postgres.New(engine.Config{Timeout: time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := c.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != engine.OutcomeNoMatch {
		t.Fatalf("outcome=%q", res.Outcome)
	}
}
