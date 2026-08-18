package scan

import (
	"context"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
)

// ScanOptions wraps engine.Options for the production scan entrypoint.
type ScanOptions struct {
	engine.Options
	Timeout time.Duration
	// UseLegacyRunner is ignored. scan.Scan always uses Session → Engine.
	UseLegacyRunner bool
}

// Scan runs the Engine pipeline for one target string via a one-shot Session.
func Scan(ctx context.Context, target string, opts ScanOptions) (*engine.ScanResult, error) {
	session, err := NewSession(ConfigFromScanOptions(opts))
	if err != nil {
		return nil, err
	}
	defer func() { _ = session.Close() }()
	return session.Scan(ctx, target)
}
