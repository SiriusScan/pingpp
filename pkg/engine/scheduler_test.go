package engine

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/model"
)

func TestSchedulerRunAllInvokesEveryTaskOnCancel(t *testing.T) {
	s := NewScheduler(1000, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var seen []string
	var mu sync.Mutex
	tasks := []Task{
		{CollectorID: "a", Endpoint: ep("192.0.2.1", 1)},
		{CollectorID: "b", Endpoint: ep("192.0.2.1", 2)},
		{CollectorID: "c", Endpoint: ep("192.0.2.1", 3)},
	}
	err := s.RunAll(ctx, tasks, func(_ context.Context, task Task) error {
		mu.Lock()
		seen = append(seen, task.CollectorID)
		mu.Unlock()
		return ctx.Err()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if len(seen) != 3 {
		t.Fatalf("seen=%v want 3 terminal calls", seen)
	}
}

func TestSchedulerRunAllCancelNeverReturnsNil(t *testing.T) {
	s := NewScheduler(1, 1)
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	tasks := make([]Task, 8)
	for i := range tasks {
		tasks[i] = Task{CollectorID: "x", Endpoint: ep("192.0.2.1", uint16(i+1))}
	}
	var calls atomic.Int32
	go func() {
		<-started
		cancel()
	}()
	err := s.RunAll(ctx, tasks, func(ctx context.Context, task Task) error {
		calls.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		time.Sleep(20 * time.Millisecond)
		return ctx.Err()
	})
	if err == nil {
		t.Fatal("cancelled RunAll returned nil")
	}
	if int(calls.Load()) != len(tasks) {
		t.Fatalf("calls=%d want %d", calls.Load(), len(tasks))
	}
}

func TestSchedulerRateLimiterCancelStillCallsFn(t *testing.T) {
	s := NewScheduler(1, 2) // 1 probe/sec so second waits
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	tasks := []Task{
		{CollectorID: "a", Endpoint: ep("192.0.2.1", 1)},
		{CollectorID: "b", Endpoint: ep("192.0.2.1", 2)},
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.RunAll(ctx, tasks, func(ctx context.Context, task Task) error {
			calls.Add(1)
			if task.CollectorID == "a" {
				cancel()
			}
			return ctx.Err()
		})
	}()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected cancel error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunAll hung")
	}
	if calls.Load() != 2 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestSchedulerRunAllRaceCancel(t *testing.T) {
	s := NewScheduler(1000, 4)
	for i := 0; i < 32; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		tasks := make([]Task, 16)
		for j := range tasks {
			tasks[j] = Task{CollectorID: "r", Endpoint: ep("192.0.2.1", uint16(j+1))}
		}
		var calls atomic.Int32
		go func() {
			time.Sleep(time.Millisecond)
			cancel()
		}()
		err := s.RunAll(ctx, tasks, func(context.Context, Task) error {
			calls.Add(1)
			return ctx.Err()
		})
		if int(calls.Load()) != len(tasks) {
			t.Fatalf("iter %d calls=%d err=%v", i, calls.Load(), err)
		}
		if ctx.Err() != nil && err == nil {
			t.Fatalf("iter %d cancel with nil error", i)
		}
	}
}

func ep(ip string, port uint16) *model.Endpoint {
	e := model.NewEndpoint(ip, port, model.TransportTCP, model.EndpointUnknown)
	return &e
}
