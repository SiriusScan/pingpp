package transport_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/transport"
)

func TestLimiterCapsConcurrentCountDial(t *testing.T) {
	const rate = 20
	const ops = 40
	lim := transport.NewLimiter(rate)
	if lim == nil {
		t.Fatal("expected limiter")
	}
	ctx := transport.WithLimiter(context.Background(), lim)
	m := &transport.Meter{}
	ctx = transport.WithMeter(ctx, m)

	start := time.Now()
	var wg sync.WaitGroup
	var errs atomic.Int32
	wg.Add(ops)
	for i := 0; i < ops; i++ {
		go func() {
			defer wg.Done()
			if err := transport.CountDial(ctx); err != nil {
				errs.Add(1)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	if errs.Load() != 0 {
		t.Fatalf("CountDial errors=%d", errs.Load())
	}
	got, _, _, _ := m.Snapshot()
	if got != ops {
		t.Fatalf("ops=%d want %d", got, ops)
	}
	// burst == rate, so the second half of ops needs about 1s at 20/s.
	if elapsed < 800*time.Millisecond {
		t.Fatalf("elapsed %s too fast for rate=%d ops=%d", elapsed, rate, ops)
	}
	if elapsed > 4*time.Second {
		t.Fatalf("elapsed %s too slow for rate=%d ops=%d", elapsed, rate, ops)
	}
}

func TestLimiterNilUnlimited(t *testing.T) {
	if transport.NewLimiter(0) != nil {
		t.Fatal("rate 0 must be unlimited")
	}
	ctx := transport.WithLimiter(context.Background(), nil)
	if transport.ContextLimiter(ctx) != nil {
		t.Fatal("nil limiter must not attach")
	}
	if err := transport.CountDial(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestLimiterRespectsCancel(t *testing.T) {
	lim := transport.NewLimiter(1)
	ctx, cancel := context.WithCancel(transport.WithLimiter(context.Background(), lim))
	if err := transport.CountDial(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := transport.CountDial(ctx); err == nil {
		t.Fatal("expected canceled wait")
	}
}
