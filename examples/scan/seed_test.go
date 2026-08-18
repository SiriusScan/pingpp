package main

import (
	"reflect"
	"testing"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"https://n8n.shimcounty.com/", "n8n.shimcounty.com"},
		{"http://n8n.shimcounty.com:443/login", "n8n.shimcounty.com"},
		{"n8n.shimcounty.com", "n8n.shimcounty.com"},
		{"54.84.197.231", "54.84.197.231"},
		{"[::1]:8443", "::1"},
	}
	for _, tt := range tests {
		if got := parseTarget(tt.in); got != tt.want {
			t.Errorf("parseTarget(%q)=%q want %q", tt.in, got, tt.want)
		}
	}
}

func TestExpandTargetsSeed(t *testing.T) {
	got := expandTargets([]string{"https://n8n.shimcounty.com/"}, true)
	want := []string{"n8n.shimcounty.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("subdomain seed=%v want %v", got, want)
	}

	got = expandTargets([]string{"shimcounty.com"}, true)
	want = []string{"shimcounty.com", "www.shimcounty.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("apex seed=%v want %v", got, want)
	}

	got = expandTargets([]string{"www.shimcounty.com"}, true)
	want = []string{"www.shimcounty.com", "shimcounty.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("www seed=%v want %v", got, want)
	}

	got = expandTargets([]string{"shimcounty.com"}, false)
	want = []string{"shimcounty.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("no-seed=%v want %v", got, want)
	}
}
