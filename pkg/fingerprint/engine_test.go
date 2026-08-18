package fingerprint

import (
	"testing"

	"github.com/SiriusScan/ping++/pkg/model"
)

func TestCorrelationGroupDoesNotInflate(t *testing.T) {
	// Three claims from the same HTTP response correlation group should not
	// combine like independent evidence.
	same := []model.Claim{
		{Kind: model.ClaimProduct, Product: "nginx", Score: 80, CorrelationGroup: "http-response:1", EvidenceIDs: []string{"a"}},
		{Kind: model.ClaimProduct, Product: "nginx", Score: 70, CorrelationGroup: "http-response:1", EvidenceIDs: []string{"b"}},
		{Kind: model.ClaimProduct, Product: "nginx", Score: 60, CorrelationGroup: "http-response:1", EvidenceIDs: []string{"c"}},
	}
	fused := Fuse(same)
	if len(fused) != 1 {
		t.Fatalf("fused=%d", len(fused))
	}
	// Only strongest (80) should contribute from the group.
	if fused[0].Score < 79 || fused[0].Score > 81 {
		t.Fatalf("score=%v want ~80 (no inflation)", fused[0].Score)
	}
}

func TestIndependentGroupsCombine(t *testing.T) {
	claims := []model.Claim{
		{Kind: model.ClaimDevice, Product: "Cisco", Vendor: "Cisco", Score: 80, CorrelationGroup: "ssh", EvidenceIDs: []string{"ssh1"}},
		{Kind: model.ClaimDevice, Product: "Cisco", Vendor: "Cisco", Score: 80, CorrelationGroup: "snmp", EvidenceIDs: []string{"snmp1"}},
	}
	fused := Fuse(claims)
	if len(fused) != 1 {
		t.Fatalf("fused=%d", len(fused))
	}
	// 1 - (1-0.8)*(1-0.8) = 0.96 → 96
	if fused[0].Score < 95 || fused[0].Score > 97 {
		t.Fatalf("score=%v want ~96", fused[0].Score)
	}
	if len(fused[0].EvidenceIDs) != 2 {
		t.Fatalf("evidence=%v", fused[0].EvidenceIDs)
	}
}

func TestRuleMatchHTTPNginx(t *testing.T) {
	e := NewEngine()
	err := e.LoadYAML([]byte(`
id: nginx-server-header
scope: service
correlation_group: http-response
inputs:
  observation_type: http
matches:
  - field: server
    regex: "(?i)nginx"
claims:
  - kind: product
    product: nginx
    certainty: strong
    score: 90
`))
	if err != nil {
		t.Fatal(err)
	}
	obs := model.ObservationRecord{
		ID:               "obs1",
		ObservationType:  model.ObservationHTTP,
		AssetID:          "asset:1",
		CorrelationGroup: "http-response",
	}
	_ = obs.SetPayload(model.HTTPObservation{Server: "nginx/1.24.0", StatusCode: 200})
	claims := e.Match([]model.ObservationRecord{obs})
	if len(claims) != 1 || claims[0].Product != "nginx" {
		t.Fatalf("claims=%+v", claims)
	}
	if claims[0].Confidence != model.ConfidenceStrong {
		t.Fatalf("confidence=%q", claims[0].Confidence)
	}
}
