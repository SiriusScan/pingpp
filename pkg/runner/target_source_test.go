package runner

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHostnameIsNotResolved(t *testing.T) {
	src, err := NewTargetSource(WithTargets("grafana.example.invalid"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := CollectAll(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Kind != TargetHostname || got[0].Input != "grafana.example.invalid" {
		t.Fatalf("%+v", got)
	}
	if net.ParseIP(got[0].Input) != nil {
		t.Fatal("hostname was replaced with an IP")
	}
}

func TestIPv6Preserved(t *testing.T) {
	src, err := NewTargetSource(WithTargets("2001:db8::20"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := CollectAll(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Kind != TargetIPv6 || net.ParseIP(got[0].Input).To4() != nil {
		t.Fatalf("%+v", got)
	}
}

func TestDuplicateSourcesCollapse(t *testing.T) {
	src, err := NewTargetSource(WithTargets("10.0.0.1", "10.0.0.1", "example.com", "example.com"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := CollectAll(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("len=%d %+v", len(got), got)
	}
}

func TestCIDRLazyAndSafetyGate(t *testing.T) {
	src, err := NewTargetSource(WithTargets("10.0.0.0/30"), WithMaxTargets(16))
	if err != nil {
		t.Fatal(err)
	}
	got, err := CollectAll(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("len=%d", len(got))
	}
	_, err = NewTargetSource(WithTargets("10.0.0.0/8"), WithMaxTargets(1000))
	if err != nil {
		t.Fatal(err)
	}
	_, err = CollectAll(context.Background(), mustSource(t, WithTargets("10.0.0.0/8"), WithMaxTargets(1000)))
	if !errors.Is(err, ErrMaxTargets) {
		t.Fatalf("got %v want ErrMaxTargets", err)
	}
}

func TestIPv6CIDRBounded(t *testing.T) {
	src, err := NewTargetSource(WithTargets("2001:db8::/64"), WithMaxTargets(100000))
	if err != nil {
		t.Fatal(err)
	}
	_, err = CollectAll(context.Background(), src)
	if !errors.Is(err, ErrMaxTargets) {
		t.Fatalf("got %v", err)
	}
}

func TestExcludeIPAndCIDR(t *testing.T) {
	src, err := NewTargetSource(
		WithTargets("10.0.0.1", "10.0.0.2", "10.1.0.5"),
		WithExclude("10.0.0.1"),
		WithExclude("10.1.0.0/16"),
	)
	if err != nil {
		t.Fatal(err)
	}
	got, err := CollectAll(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Input != "10.0.0.2" {
		t.Fatalf("%+v", got)
	}
}

func TestFileCommentsAndStrictDiagnostics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	body := "\ufeff# comment\n\n10.0.0.1\n10.0.0.999\nexample.com\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := NewTargetSource(WithFile(path))
	if err != nil {
		t.Fatal(err)
	}
	got, err := CollectAll(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("non-strict len=%d %+v", len(got), got)
	}

	src, err = NewTargetSource(WithFile(path), WithStrictInput(true))
	if err != nil {
		t.Fatal(err)
	}
	_, err = CollectAll(context.Background(), src)
	if err == nil || !strings.Contains(err.Error(), "targets.txt:4:") {
		t.Fatalf("strict err=%v", err)
	}
}

func TestRejectURLAndHostPort(t *testing.T) {
	for _, in := range []string{"https://example.com:8443/admin", "example.com:443"} {
		_, err := NewTargetSource(WithTargets(in), WithStrictInput(true))
		if !errors.Is(err, ErrUnsupportedTarget) {
			t.Fatalf("%s: %v", in, err)
		}
	}
}

func TestStdinSource(t *testing.T) {
	src, err := NewTargetSource(WithStdin(strings.NewReader("10.0.0.9\n# x\n")))
	if err != nil {
		t.Fatal(err)
	}
	got, err := CollectAll(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Input != "10.0.0.9" || got[0].Source != SourceStdin {
		t.Fatalf("%+v", got)
	}
}

func TestCancelWhileReading(t *testing.T) {
	src, err := NewTargetSource(WithTargets("10.0.0.0/24"), WithMaxTargets(256))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = src.Next(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}

func TestCancelDuringCIDRWalk(t *testing.T) {
	src, err := NewTargetSource(WithTargets("10.0.0.0/24"), WithMaxTargets(256))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	var n int
	for {
		_, err := src.Next(ctx)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) {
				break
			}
			t.Fatal(err)
		}
		n++
	}
	if n > 256 {
		t.Fatalf("n=%d", n)
	}
}

func mustSource(t *testing.T, opts ...SourceOption) TargetSource {
	t.Helper()
	src, err := NewTargetSource(opts...)
	if err != nil {
		t.Fatal(err)
	}
	return src
}
