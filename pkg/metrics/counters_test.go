package metrics_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SiriusScan/ping++/pkg/metrics"
	"github.com/SiriusScan/ping++/pkg/metrics/eval"
)

func TestRuntimeCounters(t *testing.T) {
	c := &metrics.Counters{}
	c.RecordCollector("success")
	c.RecordCollector("timeout")
	c.RecordProtocolMatch()
	c.RecordBytes(1024)
	c.RecordUnknownEndpoint()
	c.RecordClaimTier("strong")
	c.RecordUnmatchedBanner("SSH-2.0-mystery")
	c.RecordConflict()
	snap := c.Snapshot()
	if snap["collectors_executed"] != 2 {
		t.Fatalf("%v", snap)
	}
	if snap["protocol_matches"] != 1 || snap["timeouts"] != 1 {
		t.Fatalf("%v", snap)
	}
	if snap["unmatched_banners"] != 1 {
		t.Fatalf("%v", snap)
	}
	dump := c.UnmatchedBannerDump()
	if len(dump) != 1 || dump[0] != "SSH-2.0-mystery" {
		t.Fatalf("%v", dump)
	}
}

func TestBannerSinkWritesJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unknown.jsonl")
	sink, err := metrics.OpenBannerSink(path)
	if err != nil {
		t.Fatal(err)
	}
	c := &metrics.Counters{}
	c.AttachBannerSink(sink)
	c.RecordUnmatchedBanner("SSH-2.0-mystery")
	c.RecordUnmatchedBanner("220 unknown\r\nftp")
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines=%d body=%s", len(lines), raw)
	}
	if !strings.Contains(lines[0], "SSH-2.0-mystery") {
		t.Fatalf("line0=%s", lines[0])
	}
	if strings.Contains(string(raw), "\r") {
		t.Fatal("sink must strip CR from banners")
	}
}

func TestEvalPrecisionAtTier(t *testing.T) {
	c := &eval.PrecisionCounters{}
	c.RecordClaimOutcome("exact", true)
	c.RecordClaimOutcome("exact", true)
	c.RecordClaimOutcome("exact", false)
	c.RecordUnknown(true)
	c.RecordUnknown(false)
	snap := c.Snapshot()
	if snap["p_correct_exact"] < 0.66 || snap["p_correct_exact"] > 0.67 {
		t.Fatalf("%v", snap["p_correct_exact"])
	}
	if snap["unknown_rate"] != 0.5 {
		t.Fatalf("unknown=%v", snap["unknown_rate"])
	}
}
