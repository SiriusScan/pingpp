package model

import "testing"

func TestMergeExecutionMonotonicTable(t *testing.T) {
	attempted := ExecutionAttempted
	timedOut := ExecutionTimedOut
	budget := ExecutionNotAttemptedBudget
	cancelled := ExecutionNotAttemptedCancelled

	tests := []struct {
		current, incoming, want EndpointExecution
	}{
		{"", attempted, attempted},
		{"", timedOut, timedOut},
		{"", budget, budget},
		{"", cancelled, cancelled},
		{attempted, cancelled, attempted},
		{attempted, budget, attempted},
		{attempted, timedOut, attempted},
		{timedOut, budget, timedOut},
		{timedOut, cancelled, timedOut},
		{timedOut, attempted, attempted},
		{budget, cancelled, budget},
		{cancelled, budget, cancelled},
		{budget, attempted, attempted},
		{cancelled, timedOut, timedOut},
		{attempted, "", attempted},
	}
	for _, tc := range tests {
		got := MergeExecution(tc.current, tc.incoming)
		if got != tc.want {
			t.Fatalf("MergeExecution(%q, %q)=%q want %q", tc.current, tc.incoming, got, tc.want)
		}
	}
}

func TestAddEndpointDoesNotDowngradeAttempted(t *testing.T) {
	a := NewAssetFromIP("192.0.2.1")
	ep := NewEndpoint("192.0.2.1", 80, TransportTCP, EndpointResponsive)
	ep.Execution = ExecutionAttempted
	a.AddEndpoint(ep)
	later := NewEndpoint("192.0.2.1", 80, TransportTCP, EndpointResponsive)
	later.Execution = ExecutionNotAttemptedCancelled
	a.AddEndpoint(later)
	if a.Endpoints[0].Execution != ExecutionAttempted {
		t.Fatalf("execution=%q", a.Endpoints[0].Execution)
	}
	if a.Endpoints[0].State != EndpointResponsive {
		t.Fatalf("state=%q", a.Endpoints[0].State)
	}
}
