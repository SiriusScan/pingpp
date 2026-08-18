package runner_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/runner"
)

func TestScanRunOneBadTargetDoesNotAbort(t *testing.T) {
	src, err := runner.NewTargetSource(runner.WithTargets("192.0.2.1", "192.0.2.2", "192.0.2.3"))
	if err != nil {
		t.Fatal(err)
	}
	sink := &runner.CollectingSink{}
	scan := &runner.ConcurrentScanner{Fn: func(_ context.Context, target string) (*engine.ScanResult, error) {
		if target == "192.0.2.2" {
			return nil, fmt.Errorf("engine boom")
		}
		return &engine.ScanResult{}, nil
	}}
	run, err := runner.NewScanRun(runner.ScanRunOptions{
		Scanner:         scan,
		Targets:         src,
		HostConcurrency: 2,
		Sink:            sink,
	})
	if err != nil {
		t.Fatal(err)
	}
	sum, err := run.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sum.Targets != 3 || sum.Completed != 3 {
		t.Fatalf("summary=%+v", sum)
	}
	if sum.Failed != 1 {
		t.Fatalf("failed=%d want 1", sum.Failed)
	}
	if len(sink.Results) != 3 {
		t.Fatalf("results=%d", len(sink.Results))
	}
}

func TestScanRunFailFastStopsRemaining(t *testing.T) {
	src, err := runner.NewTargetSource(runner.WithTargets("192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"))
	if err != nil {
		t.Fatal(err)
	}
	var started atomic.Int32
	scan := &runner.ConcurrentScanner{
		Delay: 20 * time.Millisecond,
		Fn: func(_ context.Context, target string) (*engine.ScanResult, error) {
			started.Add(1)
			if target == "192.0.2.1" {
				return nil, fmt.Errorf("engine boom")
			}
			return &engine.ScanResult{}, nil
		},
	}
	run, err := runner.NewScanRun(runner.ScanRunOptions{
		Scanner:         scan,
		Targets:         src,
		HostConcurrency: 1,
		FailFast:        true,
		Sink:            &runner.CollectingSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	sum, _ := run.Run(context.Background())
	if started.Load() > 2 {
		t.Fatalf("fail-fast still scanned %d", started.Load())
	}
	if sum.Failed < 1 {
		t.Fatalf("summary=%+v", sum)
	}
}

func TestScanRunHostConcurrencyCap(t *testing.T) {
	src, err := runner.NewTargetSource(runner.WithTargets("192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"))
	if err != nil {
		t.Fatal(err)
	}
	scan := &runner.ConcurrentScanner{Delay: 40 * time.Millisecond}
	run, err := runner.NewScanRun(runner.ScanRunOptions{
		Scanner:         scan,
		Targets:         src,
		HostConcurrency: 2,
		Sink:            runner.NopSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if scan.Peak > 2 {
		t.Fatalf("peak concurrency %d want <= 2", scan.Peak)
	}
	if scan.Peak < 2 {
		t.Fatalf("peak concurrency %d want 2", scan.Peak)
	}
}

func TestScanRunResolutionIsNotFailed(t *testing.T) {
	src, err := runner.NewTargetSource(runner.WithTargets("no-such-host.invalid"))
	if err != nil {
		t.Fatal(err)
	}
	sink := &runner.CollectingSink{}
	scan := &runner.ConcurrentScanner{Fn: func(context.Context, string) (*engine.ScanResult, error) {
		return nil, fmt.Errorf("lookup no-such-host.invalid: no such host")
	}}
	run, err := runner.NewScanRun(runner.ScanRunOptions{Scanner: scan, Targets: src, Sink: sink})
	if err != nil {
		t.Fatal(err)
	}
	sum, err := run.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sum.Failed != 0 {
		t.Fatalf("NXDOMAIN must not be operational failure: %+v", sum)
	}
	if len(sink.Results) != 1 || sink.Results[0].Err == nil || sink.Results[0].Err.Kind != runner.ErrKindResolution {
		t.Fatalf("results=%+v", sink.Results)
	}
}

func TestScanRunInputErrorIsRunError(t *testing.T) {
	src, err := runner.NewTargetSource(runner.WithTargets("10.0.0.0/8"), runner.WithMaxTargets(1000))
	if err != nil {
		t.Fatal(err)
	}
	run, err := runner.NewScanRun(runner.ScanRunOptions{
		Scanner: &runner.ConcurrentScanner{},
		Targets: src,
		Sink:    runner.NopSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = run.Run(context.Background())
	var runErr *runner.RunError
	if !errors.As(err, &runErr) || runErr.Kind != runner.ErrKindInput {
		t.Fatalf("err=%v want RunError input", err)
	}
}

func TestScanRunDeadlineExceeded(t *testing.T) {
	src, err := runner.NewTargetSource(runner.WithTargets("192.0.2.1", "192.0.2.2"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	run, err := runner.NewScanRun(runner.ScanRunOptions{
		Scanner:         &runner.ConcurrentScanner{Delay: time.Second},
		Targets:         src,
		HostConcurrency: 2,
		Sink:            runner.NopSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = run.Run(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v want deadline exceeded", err)
	}
}

func TestScanRunCancel(t *testing.T) {
	src, err := runner.NewTargetSource(runner.WithTargets("192.0.2.1", "192.0.2.2"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	scan := &runner.ConcurrentScanner{Delay: time.Second}
	run, err := runner.NewScanRun(runner.ScanRunOptions{
		Scanner:         scan,
		Targets:         src,
		HostConcurrency: 2,
		Sink:            runner.NopSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, err = run.Run(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}

func TestScanRunManyTargetsBoundedAndCancel(t *testing.T) {
	targets := make([]string, 80)
	for i := range targets {
		targets[i] = fmt.Sprintf("192.0.2.%d", i+1)
	}
	src, err := runner.NewTargetSource(runner.WithTargets(targets...))
	if err != nil {
		t.Fatal(err)
	}
	scan := &runner.ConcurrentScanner{Delay: 5 * time.Millisecond}
	run, err := runner.NewScanRun(runner.ScanRunOptions{
		Scanner:         scan,
		Targets:         src,
		HostConcurrency: 8,
		Sink:            runner.NopSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	sum, err := run.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sum.Targets != 80 || sum.Completed != 80 {
		t.Fatalf("summary=%+v", sum)
	}
	if scan.Peak > 8 {
		t.Fatalf("peak=%d", scan.Peak)
	}

	src2, err := runner.NewTargetSource(runner.WithTargets(targets...))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	slow := &runner.ConcurrentScanner{Delay: 200 * time.Millisecond}
	run2, err := runner.NewScanRun(runner.ScanRunOptions{
		Scanner:         slow,
		Targets:         src2,
		HostConcurrency: 8,
		Sink:            runner.NopSink{},
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, err = run2.Run(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel err=%v", err)
	}
}
