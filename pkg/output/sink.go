package output

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/SiriusScan/ping++/pkg/runner"
)

// Sink writes TargetResults as they complete. json buffers until Flush.
type Sink struct {
	W       io.Writer
	Format  string
	Profile string
	Verbose bool

	mu   sync.Mutex
	docs []Document
}

// WriteResult implements runner.ResultSink.
func (s *Sink) WriteResult(_ context.Context, tr runner.TargetResult) error {
	if s == nil || s.W == nil {
		return fmt.Errorf("nil output sink")
	}
	doc := NewDocument(s.Profile, tr)
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.Format {
	case "jsonl":
		return json.NewEncoder(s.W).Encode(doc)
	case "json":
		s.docs = append(s.docs, doc)
		return nil
	default:
		return WriteText(s.W, []Document{doc}, s.Verbose)
	}
}

// Flush writes a buffered JSON array (no-op for text/jsonl).
func (s *Sink) Flush() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Format != "json" {
		return nil
	}
	return WriteJSON(s.W, s.docs)
}
