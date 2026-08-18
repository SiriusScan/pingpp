package transport_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/internal/tlstest"
	"github.com/SiriusScan/ping++/pkg/transport"
)

func TestUpgradeTLSDoesNotCountDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	cert := tlstest.Certificate(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		sc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
		_ = sc.Handshake()
		_ = sc.Close()
	}()

	meter := &transport.Meter{}
	ctx := transport.WithMeter(context.Background(), meter)
	host, port := splitHostPort(t, ln.Addr().String())
	raw, err := transport.DialTCP(ctx, host, port, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	ops, _, _, _ := meter.Snapshot()
	if ops != 1 {
		t.Fatalf("after dial ops=%d want 1", ops)
	}
	up, err := transport.UpgradeTLS(ctx, raw, "127.0.0.1", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = up.Close()
	ops, _, _, _ = meter.Snapshot()
	if ops != 1 {
		t.Fatalf("STARTTLS must not count a dial, ops=%d", ops)
	}
	<-done
}

func splitHostPort(t *testing.T, addr string) (string, uint16) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := net.LookupPort("tcp", portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, uint16(p)
}
