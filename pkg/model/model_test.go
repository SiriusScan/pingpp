package model

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewAssetFromIP(t *testing.T) {
	a := NewAssetFromIP("192.0.2.10")
	if a.ID != "asset:192.0.2.10" {
		t.Fatalf("ID=%q", a.ID)
	}
	if len(a.Addresses) != 1 || a.Addresses[0].IP != "192.0.2.10" || a.Addresses[0].Version != 4 {
		t.Fatalf("Addresses=%v", a.Addresses)
	}
}

func TestNewAddressIPv6(t *testing.T) {
	a := NewAddress("2001:db8::1")
	if a.Version != 6 {
		t.Fatalf("Version=%d", a.Version)
	}
}

func TestEndpointStateAndTransportValid(t *testing.T) {
	for _, s := range []EndpointState{EndpointOpen, EndpointClosed, EndpointFiltered, EndpointResponsive, EndpointUnknown} {
		if !s.Valid() {
			t.Fatalf("%q should be valid", s)
		}
	}
	if EndpointState("bogus").Valid() {
		t.Fatal("bogus state should be invalid")
	}
	if !TransportTCP.Valid() || !TransportUDP.Valid() {
		t.Fatal("tcp/udp should be valid")
	}
	if Transport("sctp").Valid() {
		t.Fatal("sctp should be invalid for now")
	}
}

func TestEndpointNoBoolOpen(t *testing.T) {
	ep := NewEndpoint("192.0.2.10", 443, TransportTCP, EndpointOpen)
	if ep.State != EndpointOpen {
		t.Fatalf("State=%q", ep.State)
	}
	if ep.Key() != "192.0.2.10/tcp/443" {
		t.Fatalf("Key=%q", ep.Key())
	}
}

func TestAssetAddEndpointUpserts(t *testing.T) {
	a := NewAssetFromIP("192.0.2.10")
	a.AddEndpoint(NewEndpoint("192.0.2.10", 80, TransportTCP, EndpointFiltered))
	a.AddEndpoint(NewEndpoint("192.0.2.10", 80, TransportTCP, EndpointOpen))
	if len(a.Endpoints) != 1 {
		t.Fatalf("len=%d", len(a.Endpoints))
	}
	if a.Endpoints[0].State != EndpointOpen {
		t.Fatalf("State=%q", a.Endpoints[0].State)
	}
	a.AddEndpoint(NewEndpoint("192.0.2.10", 80, TransportTCP, EndpointResponsive))
	if a.Endpoints[0].State != EndpointOpen {
		t.Fatalf("Open must not downgrade to responsive, State=%q", a.Endpoints[0].State)
	}
}

func TestObservationPayloadRoundTrip(t *testing.T) {
	obs := ObservationRecord{
		ID:               "obs-1",
		ProbeID:          "http",
		ObservationType:  ObservationHTTP,
		AssetID:          "asset:192.0.2.10",
		Timestamp:        time.Unix(0, 0).UTC(),
		CorrelationGroup: "http-response:192.0.2.10:443:/",
	}
	payload := HTTPObservation{
		StatusCode: 200,
		Server:     "nginx",
		Title:      "Grafana",
		Headers:    map[string][]string{"Server": {"nginx"}},
	}
	if err := obs.SetPayload(payload); err != nil {
		t.Fatal(err)
	}
	var decoded HTTPObservation
	if err := obs.DecodePayload(&decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Server != "nginx" || decoded.Title != "Grafana" || decoded.StatusCode != 200 {
		t.Fatalf("decoded=%+v", decoded)
	}

	raw, err := json.Marshal(obs)
	if err != nil {
		t.Fatal(err)
	}
	var again ObservationRecord
	if err := json.Unmarshal(raw, &again); err != nil {
		t.Fatal(err)
	}
	if again.ObservationType != ObservationHTTP {
		t.Fatalf("type=%q", again.ObservationType)
	}
}

func TestClaimKindsAndConfidenceTiers(t *testing.T) {
	kinds := []ClaimKind{ClaimProtocol, ClaimService, ClaimProduct, ClaimApplication, ClaimOS, ClaimDevice, ClaimHardware, ClaimIdentity}
	for _, k := range kinds {
		if !k.Valid() {
			t.Fatalf("kind %q invalid", k)
		}
	}
	cases := []struct {
		score float64
		tier  ConfidenceTier
	}{
		{98, ConfidenceExact},
		{0.98, ConfidenceExact},
		{90, ConfidenceStrong},
		{75, ConfidenceProbable},
		{50, ConfidenceHint},
		{10, ConfidenceUnknown},
	}
	for _, tc := range cases {
		got := TierFromScore(tc.score)
		if got != tc.tier {
			t.Fatalf("TierFromScore(%v)=%q want %q", tc.score, got, tc.tier)
		}
	}
	c := NewClaim(ClaimProduct, "nginx", 90)
	if c.Confidence != ConfidenceStrong || c.Product != "nginx" {
		t.Fatalf("claim=%+v", c)
	}
}

func TestAssetJSONHasNoProtocolSpecificFields(t *testing.T) {
	a := NewAssetFromIP("192.0.2.10")
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"http_server", "ssh_banner", "smb_dialect", "HTTPServer", "SSHBanner"} {
		if _, ok := m[forbidden]; ok {
			t.Fatalf("Asset JSON must not contain %q", forbidden)
		}
	}
}

func TestReachabilityAndArtifact(t *testing.T) {
	r := Reachability{State: ReachabilityConfirmed, Reasons: []string{"icmp.echo"}}
	if !r.State.Valid() {
		t.Fatal("confirmed should be valid")
	}
	art := Artifact{ID: "a1", SHA256: "abc", Size: 10, MaxSize: DefaultArtifactMaxBytes}
	if art.MaxSize != DefaultArtifactMaxBytes {
		t.Fatal("default max size mismatch")
	}
}
