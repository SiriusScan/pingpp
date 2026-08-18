package cli_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/SiriusScan/ping++/internal/cli"
)

func TestVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "pingpp") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestScanUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"scan"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
}

func TestRejectsURL(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"scan", "https://example.com"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "URL") && !strings.Contains(stderr.String(), "unsupported") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestScanTESTNETFast(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{
		"scan",
		"--profile", "quick",
		"--skip-discovery",
		"--no-icmp",
		"--tcp-ports", "none",
		"--udp-ports", "none",
		"--target-timeout", "2s",
		"-t", "192.0.2.1",
		"--format", "jsonl",
	}, &stdout, &stderr)
	if code != 0 && code != 1 {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "pingpp.scan/v1") && !strings.Contains(stdout.String(), "192.0.2.1") {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}
