package transport_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/transport"
)

func TestMeterCountsDialsAndRespectsBudget(t *testing.T) {
	m := &transport.Meter{MaxNetworkOps: 2}
	ctx := transport.WithMeter(context.Background(), m)
	if _, err := transport.DialTCP(ctx, "127.0.0.1", 1, 50*time.Millisecond); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		// connection refused is expected
	}
	if _, err := transport.DialTCP(ctx, "127.0.0.1", 1, 50*time.Millisecond); err != nil && errors.Is(err, transport.ErrBudgetExceeded) {
		t.Fatal("second dial should still be under budget")
	}
	_, err := transport.DialTCP(ctx, "127.0.0.1", 1, 50*time.Millisecond)
	if !errors.Is(err, transport.ErrBudgetExceeded) {
		t.Fatalf("third dial err=%v, want budget exceeded", err)
	}
	ops, conns, _, _ := m.Snapshot()
	if ops != 2 || conns != 2 {
		t.Fatalf("ops=%d conns=%d", ops, conns)
	}
}

func TestMeterCountsConnBytes(t *testing.T) {
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
		buf := make([]byte, 16)
		n, _ := c.Read(buf)
		_, _ = c.Write(buf[:n])
		_ = c.Close()
	}()

	m := &transport.Meter{}
	ctx := transport.WithMeter(context.Background(), m)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	conn, err := transport.DialTCP(ctx, "127.0.0.1", port, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}
	ops, _, read, sent := m.Snapshot()
	if ops != 1 {
		t.Fatalf("ops=%d want 1", ops)
	}
	if sent < 5 || read < 5 {
		t.Fatalf("bytes sent=%d read=%d", sent, read)
	}
}

func TestCountDialRespectsBudget(t *testing.T) {
	m := &transport.Meter{MaxNetworkOps: 1}
	ctx := transport.WithMeter(context.Background(), m)
	if err := transport.CountDial(ctx); err != nil {
		t.Fatal(err)
	}
	if err := transport.CountDial(ctx); !errors.Is(err, transport.ErrBudgetExceeded) {
		t.Fatalf("err=%v want budget exceeded", err)
	}
}

func TestWrapUDPKeepsPacketConn(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	raw, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	m := &transport.Meter{}
	ctx := transport.WithMeter(context.Background(), m)
	wrapped := transport.WrapConn(ctx, raw)
	if _, ok := wrapped.(net.PacketConn); !ok {
		t.Fatal("wrapped UDP conn must remain a PacketConn")
	}
}

func TestMeterNilIsSafe(t *testing.T) {
	var m *transport.Meter
	if err := m.AddDial(); err != nil {
		t.Fatal(err)
	}
	m.AddBytes(1, 1)
	ops, _, _, _ := m.Snapshot()
	if ops != 0 {
		t.Fatalf("nil meter ops=%d", ops)
	}
}
