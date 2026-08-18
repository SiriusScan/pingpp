package metrics_test

import (
	"testing"

	"github.com/SiriusScan/ping++/pkg/metrics"
)

func TestPrecisionAtTier(t *testing.T) {
	c := &metrics.Counters{}
	c.RecordClaimOutcome("exact", true)
	c.RecordClaimOutcome("exact", true)
	c.RecordClaimOutcome("exact", false)
	c.RecordUnknown(true)
	c.RecordUnknown(false)
	c.RecordEffort(4, 1024, true)
	snap := c.Snapshot()
	if snap["p_correct_exact"] < 0.66 || snap["p_correct_exact"] > 0.67 {
		t.Fatalf("%v", snap["p_correct_exact"])
	}
	if snap["unknown_rate"] != 0.5 {
		t.Fatalf("unknown=%v", snap["unknown_rate"])
	}
	if snap["mean_probes_per_resolved"] != 4 {
		t.Fatalf("probes=%v", snap["mean_probes_per_resolved"])
	}
}
