package scan

import (
	"context"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
)

// ScanOptions wraps engine.Options for the production scan entrypoint.
type ScanOptions struct {
	engine.Options
	Timeout         time.Duration
	UseLegacyRunner bool
}

// Scan runs the Engine pipeline for one target string.
func Scan(ctx context.Context, target string, opts ScanOptions) (*engine.ScanResult, error) {
	if opts.Registry == nil {
		opts.Registry = NewRegistry()
	}
	eng, err := engine.NewEngine(opts.Options)
	if err != nil {
		return nil, err
	}
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}
	return eng.ScanTarget(ctx, target)
}
