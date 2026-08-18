package scan_test

import (
	"testing"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/scan"
)

func TestScanOptionsWrapsEngineOptions(t *testing.T) {
	opts := scan.ScanOptions{
		Options: engine.Options{Profile: engine.ProfileQuick, SkipICMP: true, ProbeTypes: []string{"icmp", "tcp"}},
	}
	if opts.SkipDiscovery {
		t.Fatal("SkipICMP must not imply SkipDiscovery")
	}
	if !opts.SkipICMP {
		t.Fatal("SkipICMP should be set")
	}
	if len(opts.ProbeTypes) != 2 {
		t.Fatalf("ProbeTypes=%v", opts.ProbeTypes)
	}
	if opts.Profile != engine.ProfileQuick {
		t.Fatalf("profile=%q", opts.Profile)
	}
	if opts.UseLegacyRunner {
		t.Fatal("legacy runner must be off by default")
	}
}
