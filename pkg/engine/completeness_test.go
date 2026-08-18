package engine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/model"
)

type completenessMatcher struct{}

func (completenessMatcher) Match([]model.ObservationRecord) []model.Claim { return nil }

type countingCollector struct {
	id      string
	runs    *atomic.Int32
	onRun   func()
	outcome ProbeOutcome
}

func (c *countingCollector) Metadata() CollectorMetadata {
	return CollectorMetadata{ID: c.id, Stage: StageCollect, Priority: 50, Cost: 1}
}

func (c *countingCollector) Run(_ context.Context, _ CollectorInput) ([]model.ObservationRecord, error) {
	if c.runs != nil {
		c.runs.Add(1)
	}
	if c.onRun != nil {
		c.onRun()
	}
	return nil, nil
}

func (c *countingCollector) RunResult(ctx context.Context, in CollectorInput) (CollectorResult, error) {
	obs, err := c.Run(ctx, in)
	out := c.outcome
	if out == "" {
		out = OutcomeSuccess
	}
	return CollectorResult{Outcome: out, Protocol: "test", Observations: obs}, err
}

func TestCancelBeforeStartZeroCollectorInvocations(t *testing.T) {
	var runs atomic.Int32
	reg := NewRegistry()
	reg.MustRegister("collect.test", func(Config) (Collector, error) {
		return &countingCollector{id: "collect.test", runs: &runs}, nil
	})
	eng, err := NewEngine(Options{
		Profile: ProfileQuick, SkipDiscovery: true, SkipICMP: true,
		TCPPorts: []uint16{9}, RatePerSecond: 1000, Registry: reg, Fingerprints: completenessMatcher{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	asset := model.NewAssetFromIP("192.0.2.8")
	ep := model.NewEndpoint("192.0.2.8", 9, model.TransportTCP, model.EndpointResponsive)
	asset.AddEndpoint(ep)
	target := model.NewTargetIP("192.0.2.8")
	state := eng.newScanState(asset.ID)
	tasks := []Task{{
		CollectorID: "collect.test", Asset: asset, Endpoint: &asset.Endpoints[0],
		Target: &target, Stage: StageCollect, Priority: 1,
	}}
	err = eng.runTasks(ctx, tasks, asset, &target, state)
	if err == nil {
		t.Fatal("expected cancel error")
	}
	if runs.Load() != 0 {
		t.Fatalf("collector ran %d times", runs.Load())
	}
	if state.Budget.ProbesUsed != 0 {
		t.Fatalf("probes used=%d", state.Budget.ProbesUsed)
	}
	if state.Requests[asset.Endpoints[0].Key()] != 0 {
		t.Fatalf("requests=%v", state.Requests)
	}
	if len(asset.Observations) != 0 {
		t.Fatalf("observations=%d", len(asset.Observations))
	}
	if state.IsRuledOut(asset.Endpoints[0].Key(), "test") {
		t.Fatal("ruled out cancelled work")
	}
	if asset.Endpoints[0].Execution != model.ExecutionNotAttemptedCancelled {
		t.Fatalf("execution=%q", asset.Endpoints[0].Execution)
	}
}

func TestDeadlineMarksTimedOutNotBudget(t *testing.T) {
	reg := NewRegistry()
	reg.MustRegister("collect.test", func(Config) (Collector, error) {
		return &countingCollector{id: "collect.test"}, nil
	})
	eng, err := NewEngine(Options{
		Profile: ProfileQuick, SkipDiscovery: true, Registry: reg,
		RatePerSecond: 1000, Fingerprints: completenessMatcher{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	asset := model.NewAssetFromIP("192.0.2.8")
	ep := model.NewEndpoint("192.0.2.8", 9, model.TransportTCP, model.EndpointResponsive)
	asset.AddEndpoint(ep)
	target := model.NewTargetIP("192.0.2.8")
	state := eng.newScanState(asset.ID)
	err = eng.runTasks(ctx, []Task{{
		CollectorID: "collect.test", Endpoint: &asset.Endpoints[0], Target: &target, Priority: 1,
	}}, asset, &target, state)
	if err == nil {
		t.Fatal("expected deadline error")
	}
	if asset.Endpoints[0].Execution != model.ExecutionTimedOut {
		t.Fatalf("execution=%q want timed_out", asset.Endpoints[0].Execution)
	}
}

func TestBudgetExhaustionDoesNotLookLikeCancel(t *testing.T) {
	reg := NewRegistry()
	reg.MustRegister("collect.test", func(Config) (Collector, error) {
		return &countingCollector{id: "collect.test"}, nil
	})
	eng, err := NewEngine(Options{
		Profile: ProfileQuick, SkipDiscovery: true, Registry: reg,
		RatePerSecond: 1000, Fingerprints: completenessMatcher{}, MaxProbesPerHost: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	asset := model.NewAssetFromIP("192.0.2.8")
	ep := model.NewEndpoint("192.0.2.8", 9, model.TransportTCP, model.EndpointResponsive)
	asset.AddEndpoint(ep)
	target := model.NewTargetIP("192.0.2.8")
	state := eng.newScanState(asset.ID)
	state.Budget.ProbesUsed = 1
	err = eng.runTasks(context.Background(), []Task{{
		CollectorID: "collect.test", Endpoint: &asset.Endpoints[0], Target: &target, Priority: 1,
	}}, asset, &target, state)
	if err != nil {
		t.Fatal(err)
	}
	if asset.Endpoints[0].Execution != model.ExecutionNotAttemptedBudget {
		t.Fatalf("execution=%q", asset.Endpoints[0].Execution)
	}
}

func TestLaterCancelledTaskDoesNotEraseAttempted(t *testing.T) {
	var secondRuns atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	reg := NewRegistry()
	reg.MustRegister("collect.first", func(Config) (Collector, error) {
		return &countingCollector{id: "collect.first", onRun: cancel, outcome: OutcomeSuccess}, nil
	})
	reg.MustRegister("collect.second", func(Config) (Collector, error) {
		return &countingCollector{id: "collect.second", runs: &secondRuns}, nil
	})
	eng, err := NewEngine(Options{
		Profile: ProfileQuick, SkipDiscovery: true, Registry: reg,
		RatePerSecond: 1000, MaxConcurrentPerHost: 1, Fingerprints: completenessMatcher{},
	})
	if err != nil {
		t.Fatal(err)
	}
	asset := model.NewAssetFromIP("192.0.2.8")
	ep := model.NewEndpoint("192.0.2.8", 80, model.TransportTCP, model.EndpointResponsive)
	asset.AddEndpoint(ep)
	target := model.NewTargetIP("192.0.2.8")
	state := eng.newScanState(asset.ID)
	ptr := &asset.Endpoints[0]
	err = eng.runTasks(ctx, []Task{
		{CollectorID: "collect.first", Endpoint: ptr, Target: &target, Priority: 2},
		{CollectorID: "collect.second", Endpoint: ptr, Target: &target, Priority: 1},
	}, asset, &target, state)
	if err == nil {
		t.Fatal("expected cancel from first collector")
	}
	if ptr.Execution != model.ExecutionAttempted {
		t.Fatalf("execution=%q (later cancel erased attempted)", ptr.Execution)
	}
	if secondRuns.Load() != 0 {
		t.Fatalf("second collector ran")
	}
}

func TestQueueBacklogCancellationMarksEveryTask(t *testing.T) {
	var runs atomic.Int32
	reg := NewRegistry()
	reg.MustRegister("collect.slow", func(Config) (Collector, error) {
		return &countingCollector{id: "collect.slow", runs: &runs, onRun: func() {
			time.Sleep(30 * time.Millisecond)
		}}, nil
	})
	eng, err := NewEngine(Options{
		Profile: ProfileQuick, SkipDiscovery: true, Registry: reg,
		RatePerSecond: 1000, MaxConcurrentPerHost: 1, Fingerprints: completenessMatcher{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(10*time.Millisecond, cancel)
	asset := model.NewAssetFromIP("192.0.2.8")
	target := model.NewTargetIP("192.0.2.8")
	for i := 0; i < 5; i++ {
		ep := model.NewEndpoint("192.0.2.8", uint16(20+i), model.TransportTCP, model.EndpointResponsive)
		asset.AddEndpoint(ep)
	}
	var tasks []Task
	for i := range asset.Endpoints {
		tasks = append(tasks, Task{
			CollectorID: "collect.slow", Endpoint: &asset.Endpoints[i], Target: &target, Priority: 1,
		})
	}
	state := eng.newScanState(asset.ID)
	_ = eng.runTasks(ctx, tasks, asset, &target, state)
	for _, ep := range asset.Endpoints {
		if ep.Execution == "" {
			t.Fatalf("missing terminal execution on %+v", ep)
		}
	}
}
