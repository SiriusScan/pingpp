package transport_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/transport"
)

func TestHostLimiterAcquireDoesNotCountDial(t *testing.T) {
	m := &transport.Meter{MaxNetworkOps: 0} // 0 = unlimited
	h := transport.NewHostLimiter(1)
	ctx := transport.WithMeter(context.Background(), m)
	ctx = transport.WithHostLimiter(ctx, h)
	release, err := transport.AcquireHost(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ops, _, _, _ := m.Snapshot()
	if ops != 0 {
		t.Fatalf("host permit consumed network ops=%d", ops)
	}
}

func TestHostLimiterBoundsInFlightDials(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	// Do not Accept: handshake completes into the backlog while Dial holds the permit.
	h := transport.NewHostLimiter(2)
	ctx := transport.WithHostLimiter(context.Background(), h)
	var live, maxLive atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := transport.DialTCP(ctx, "127.0.0.1", port, time.Second)
			if err != nil {
				return
			}
			n := live.Add(1)
			for {
				cur := maxLive.Load()
				if n <= cur || maxLive.CompareAndSwap(cur, n) {
					break
				}
			}
			time.Sleep(80 * time.Millisecond)
			live.Add(-1)
			_ = c.Close()
		}()
	}
	wg.Wait()
	if maxLive.Load() > 2 {
		t.Fatalf("max in-flight dials=%d want <=2", maxLive.Load())
	}
}

func TestTwoHostsUseIndependentLimiters(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	h1 := transport.NewHostLimiter(1)
	h2 := transport.NewHostLimiter(1)
	ctx1 := transport.WithHostLimiter(context.Background(), h1)
	ctx2 := transport.WithHostLimiter(context.Background(), h2)
	hold, err := transport.AcquireHost(ctx1)
	if err != nil {
		t.Fatal(err)
	}
	defer hold()
	c, err := transport.DialTCP(ctx2, "127.0.0.1", port, time.Second)
	if err != nil {
		t.Fatalf("host2 blocked by host1 permit: %v", err)
	}
	_ = c.Close()
}

func TestHostLimiterCancelWhileWaiting(t *testing.T) {
	h := transport.NewHostLimiter(1)
	ctx := transport.WithHostLimiter(context.Background(), h)
	release, err := h.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	waitCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	_, err = transport.DialTCP(waitCtx, "127.0.0.1", 1, time.Second)
	if err == nil {
		t.Fatal("expected wait cancel")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}

func TestDialErrorReleasesHostPermit(t *testing.T) {
	h := transport.NewHostLimiter(1)
	ctx := transport.WithHostLimiter(context.Background(), h)
	_, err := transport.DialTCP(ctx, "127.0.0.1", 1, 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected failed dial")
	}
	c, err := transport.DialTCP(ctx, "127.0.0.1", 1, 50*time.Millisecond)
	if c != nil {
		_ = c.Close()
	}
	if errors.Is(err, context.DeadlineExceeded) && errors.Is(err, context.Canceled) {
		t.Fatalf("second dial blocked: %v", err)
	}
}

func TestHostLimiterPanicDuringDialReleases(t *testing.T) {
	h := transport.NewHostLimiter(1)
	ctx := transport.WithHostLimiter(context.Background(), h)
	func() {
		defer func() { _ = recover() }()
		release, err := transport.AcquireHost(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		panic("collector boom")
	}()
	release, err := transport.AcquireHost(ctx)
	if err != nil {
		t.Fatalf("permit leaked after panic: %v", err)
	}
	release()
}
