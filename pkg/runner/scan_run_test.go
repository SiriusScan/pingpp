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
