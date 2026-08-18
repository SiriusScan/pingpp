package scan_test

import (
	"testing"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/scan"
)

func TestScanOptionsWrapsEngineOptions(t *testing.T) {
	opts := scan.ScanOptions{
		Options: engine.Options{Profile: engine.ProfileQuick, SkipDiscovery: true},
	}
	if opts.Profile != engine.ProfileQuick {
		t.Fatalf("profile=%q", opts.Profile)
	}
	if opts.UseLegacyRunner {
		t.Fatal("legacy runner must be off by default")
	}
}
