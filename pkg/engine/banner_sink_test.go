package engine_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/fingerprint"
	"github.com/SiriusScan/ping++/pkg/metrics"
)

func TestUnmatchedBannerFileSink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unknown.jsonl")
	c := &metrics.Counters{}
	eng, err := engine.NewEngine(engine.Options{
		Registry:            engine.NewRegistry(),
		Metrics:             c,
		UnmatchedBannerFile: path,
		Fingerprints:        fingerprint.NewEngine(),
	})
	if err != nil {
		t.Fatal(err)
	}
	c.RecordUnmatchedBanner("SSH-2.0-mystery")
	if err := eng.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "SSH-2.0-mystery") {
		t.Fatalf("sink=%s", raw)
	}
}

func TestUnmatchedBannerFileCreatesParents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope", "nested", "unknown.jsonl")
	eng, err := engine.NewEngine(engine.Options{
		Registry:            engine.NewRegistry(),
		UnmatchedBannerFile: path,
		Fingerprints:        fingerprint.NewEngine(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = eng.Close() }()
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
