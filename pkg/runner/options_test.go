package runner

import (
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", opts.Timeout, DefaultTimeout)
	}

	if opts.Threads != DefaultThreads {
		t.Errorf("Threads = %d, want %d", opts.Threads, DefaultThreads)
	}

	if opts.Retries != DefaultRetries {
		t.Errorf("Retries = %d, want %d", opts.Retries, DefaultRetries)
	}

	if len(opts.ProbeTypes) != len(DefaultProbeTypes) {
		t.Errorf("ProbeTypes length = %d, want %d", len(opts.ProbeTypes), len(DefaultProbeTypes))
	}
}

func TestOptionsValidate(t *testing.T) {
	tests := []struct {
		name    string
		opts    *Options
		wantErr bool
	}{
		{
			name: "valid options",
			opts: &Options{
				Targets:    []string{"192.168.1.1"},
				ProbeTypes: []string{"icmp"},
				Timeout:    3 * time.Second,
				Threads:    50,
				Rate:       100,
			},
			wantErr: false,
		},
		{
			name: "no targets",
			opts: &Options{
				Targets:    []string{},
				ProbeTypes: []string{"icmp"},
				Timeout:    3 * time.Second,
				Threads:    50,
				Rate:       100,
			},
			wantErr: true,
		},
		{
			name: "no probe types",
			opts: &Options{
				Targets:    []string{"192.168.1.1"},
				ProbeTypes: []string{},
				Timeout:    3 * time.Second,
				Threads:    50,
				Rate:       100,
			},
			wantErr: true,
		},
		{
			name: "zero timeout",
			opts: &Options{
				Targets:    []string{"192.168.1.1"},
				ProbeTypes: []string{"icmp"},
				Timeout:    0,
				Threads:    50,
				Rate:       100,
			},
			wantErr: true,
		},
		{
			name: "zero threads",
			opts: &Options{
				Targets:    []string{"192.168.1.1"},
				ProbeTypes: []string{"icmp"},
				Timeout:    3 * time.Second,
				Threads:    0,
				Rate:       100,
			},
			wantErr: true,
		},
		{
			name: "target file instead of targets",
			opts: &Options{
				Targets:    []string{},
				TargetFile: "targets.txt",
				ProbeTypes: []string{"icmp"},
				Timeout:    3 * time.Second,
				Threads:    50,
				Rate:       100,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOptionsHasProbeType(t *testing.T) {
	opts := &Options{
		ProbeTypes: []string{"icmp", "tcp"},
	}

	if !opts.HasProbeType("icmp") {
		t.Error("HasProbeType(icmp) = false, want true")
	}

	if !opts.HasProbeType("tcp") {
		t.Error("HasProbeType(tcp) = false, want true")
	}

	if opts.HasProbeType("arp") {
		t.Error("HasProbeType(arp) = true, want false")
	}
}

func TestOptionsClone(t *testing.T) {
	opts := &Options{
		Targets:    []string{"192.168.1.1", "192.168.1.2"},
		ProbeTypes: []string{"icmp", "tcp"},
		TCPPorts:   []int{22, 80, 443},
		Timeout:    5 * time.Second,
	}

	clone := opts.Clone()

	// Modify original
	opts.Targets[0] = "10.0.0.1"
	opts.ProbeTypes[0] = "arp"
	opts.TCPPorts[0] = 8080

	// Clone should be unchanged
	if clone.Targets[0] != "192.168.1.1" {
		t.Error("Clone was affected by original modification")
	}

	if clone.ProbeTypes[0] != "icmp" {
		t.Error("Clone ProbeTypes was affected by original modification")
	}

	if clone.TCPPorts[0] != 22 {
		t.Error("Clone TCPPorts was affected by original modification")
	}
}
