package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
)

// Error kinds for TargetResult. Unknown/unresponsive is not automatically Failed.
const (
	ErrKindInput      = "input"
	ErrKindResolution = "resolution"
	ErrKindTimeout    = "timeout"
	ErrKindCancelled  = "cancelled"
	ErrKindEngine     = "engine"
	ErrKindOutput     = "output"
	ErrKindInternal   = "internal"
)

// TargetScanner scans one admitted target string. scan.Session implements this.
type TargetScanner interface {
	Scan(ctx context.Context, target string) (*engine.ScanResult, error)
}

// ResultSink receives one finished target. CLI/Sirius own formatting.
type ResultSink interface {
	WriteResult(ctx context.Context, result TargetResult) error
}

// EventSink is optional coarse progress.
type EventSink interface {
	Event(ev Event)
}

// Event is a run/target lifecycle notice. Kind matches the contract names.
type Event struct {
	Kind    string
	Target  TargetSpec
	Message string
}

// TargetError is a typed per-target failure.
type TargetError struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

func (e *TargetError) Error() string {
	if e == nil {
		return ""
	}
	if e.Kind == "" {
		return e.Message
	}
	return e.Kind + ": " + e.Message
}

// TargetResult is one admitted target after Scan (or after a typed error).
type TargetResult struct {
	Target  TargetSpec
	Result  *engine.ScanResult
	Elapsed time.Duration
	Err     *TargetError
}

// Summary is the run rollup. Failed counts operational executions, not NXDOMAIN.
type Summary struct {
	Targets   int
	Completed int
	Failed    int
	Cancelled int
}

// ScanRun is production multi-target execution (Runner V2). It does not own
// JSON flags, probe switches, or hostname pre-resolution.
type ScanRun struct {
	scanner  TargetScanner
	targets  TargetSource
	workers  int
	failFast bool
	sink     ResultSink
	events   EventSink
}

// ScanRunOptions configures ScanRun.
type ScanRunOptions struct {
	Scanner         TargetScanner
	Targets         TargetSource
	HostConcurrency int
	FailFast        bool
	Sink            ResultSink
	Events          EventSink
}

// NewScanRun validates options. HostConcurrency defaults to 50.
func NewScanRun(opts ScanRunOptions) (*ScanRun, error) {
	if opts.Scanner == nil {
		return nil, fmt.Errorf("scanner required")
	}
	if opts.Targets == nil {
		return nil, fmt.Errorf("target source required")
	}
	n := opts.HostConcurrency
	if n <= 0 {
		n = 50
	}
	sink := opts.Sink
	if sink == nil {
		sink = NopSink{}
	}
	return &ScanRun{
		scanner:  opts.Scanner,
		targets:  opts.Targets,
		workers:  n,
		failFast: opts.FailFast,
		sink:     sink,
		events:   opts.Events,
	}, nil
}

// NopSink discards results.
type NopSink struct{}

func (NopSink) WriteResult(context.Context, TargetResult) error { return nil }

// Run streams targets through a bounded worker pool.
func (r *ScanRun) Run(ctx context.Context) (Summary, error) {
	if r == nil {
		return Summary{}, fmt.Errorf("nil scan run")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	r.emit(Event{Kind: "run_started"})

	work := make(chan TargetSpec, r.workers)
	var summary Summary
	var mu sync.Mutex
	var failOnce sync.Once
	fail := func() {
		failOnce.Do(cancel)
	}

	var producerErr error
	var producerWG sync.WaitGroup
	producerWG.Add(1)
	go func() {
		defer producerWG.Done()
		defer close(work)
		for {
			spec, err := r.targets.Next(ctx)
			if errors.Is(err, io.EOF) {
				return
			}
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				kind := classifyError(err)
				if kind == ErrKindInput {
					tr := TargetResult{Target: spec, Err: &TargetError{Kind: kind, Message: err.Error()}}
					mu.Lock()
					summary.Targets++
					summary.Completed++
					if operational(kind) {
						summary.Failed++
					}
					mu.Unlock()
					r.emit(Event{Kind: "target_failed", Target: spec, Message: err.Error()})
					if werr := r.sink.WriteResult(ctx, tr); werr != nil {
						producerErr = fmt.Errorf("%w: %v", werr, err)
						fail()
						return
					}
					if r.failFast {
						fail()
						return
					}
					continue
				}
				producerErr = err
				fail()
				return
			}
			r.emit(Event{Kind: "target_accepted", Target: spec})
			select {
			case <-ctx.Done():
				return
			case work <- spec:
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < r.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for spec := range work {
				if ctx.Err() != nil {
					mu.Lock()
					summary.Cancelled++
					mu.Unlock()
					continue
				}
				r.emit(Event{Kind: "target_started", Target: spec})
				started := time.Now()
				res, err := r.scanner.Scan(ctx, spec.Input)
				tr := TargetResult{Target: spec, Result: res, Elapsed: time.Since(started)}
				if err != nil {
					kind := classifyError(err)
					tr.Err = &TargetError{Kind: kind, Message: err.Error()}
					r.emit(Event{Kind: "target_failed", Target: spec, Message: err.Error()})
				} else {
					r.emit(Event{Kind: "target_completed", Target: spec})
				}
				mu.Lock()
				summary.Targets++
				summary.Completed++
				if tr.Err != nil {
					if tr.Err.Kind == ErrKindCancelled {
						summary.Cancelled++
					}
					if operational(tr.Err.Kind) {
						summary.Failed++
					}
				}
				mu.Unlock()
				if werr := r.sink.WriteResult(ctx, tr); werr != nil {
					mu.Lock()
					producerErr = werr
					summary.Failed++
					mu.Unlock()
					fail()
					return
				}
				if r.failFast && tr.Err != nil && operational(tr.Err.Kind) {
					fail()
					return
				}
			}
		}()
	}

	wg.Wait()
	producerWG.Wait()

	r.emit(Event{Kind: "run_completed"})
	if producerErr != nil && !errors.Is(producerErr, context.Canceled) {
		return summary, producerErr
	}
	if ctx.Err() != nil && summary.Failed == 0 && summary.Cancelled > 0 {
		return summary, ctx.Err()
	}
	return summary, nil
}

func operational(kind string) bool {
	switch kind {
	case ErrKindEngine, ErrKindOutput, ErrKindInternal:
		return true
	default:
		return false
	}
}

func classifyError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) {
		return ErrKindCancelled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrKindTimeout
	}
	if errors.Is(err, ErrUnsupportedTarget) || errors.Is(err, ErrInvalidTarget) || errors.Is(err, ErrMaxTargets) {
		return ErrKindInput
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return ErrKindResolution
	}
	msg := err.Error()
	if strings.Contains(msg, "no such host") || strings.Contains(msg, "no A/AAAA") {
		return ErrKindResolution
	}
	return ErrKindEngine
}

func (r *ScanRun) emit(ev Event) {
	if r.events == nil {
		return
	}
	r.events.Event(ev)
}

// CollectingSink stores results for tests.
type CollectingSink struct {
	mu      sync.Mutex
	Results []TargetResult
}

func (s *CollectingSink) WriteResult(_ context.Context, result TargetResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Results = append(s.Results, result)
	return nil
}

// ConcurrentScanner is a test scanner that records in-flight peak.
type ConcurrentScanner struct {
	Delay time.Duration
	Fn    func(ctx context.Context, target string) (*engine.ScanResult, error)

	mu   sync.Mutex
	cur  int
	Peak int32
}

func (s *ConcurrentScanner) Scan(ctx context.Context, target string) (*engine.ScanResult, error) {
	s.mu.Lock()
	s.cur++
	if int32(s.cur) > s.Peak {
		atomic.StoreInt32(&s.Peak, int32(s.cur))
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.cur--
		s.mu.Unlock()
	}()
	if s.Delay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(s.Delay):
		}
	}
	if s.Fn != nil {
		return s.Fn(ctx, target)
	}
	return &engine.ScanResult{}, nil
}
