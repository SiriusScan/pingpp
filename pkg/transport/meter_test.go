package transport_test

import (
	"context"
	"errors"
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
