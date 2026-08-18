package fingerprint

import (
	"strings"
	"testing"

	"github.com/SiriusScan/ping++/pkg/model"
)

func TestFuseDoesNotMergeAcrossEndpoints(t *testing.T) {
	claims := []model.Claim{
		{ID: "a", Kind: model.ClaimProduct, Product: "nginx", Score: 90, Subject: "10.0.0.1/tcp/80", CorrelationGroup: "http-80", EvidenceIDs: []string{"e80"}},
		{ID: "b", Kind: model.ClaimProduct, Product: "nginx", Score: 90, Subject: "10.0.0.1/tcp/443", CorrelationGroup: "http-443", EvidenceIDs: []string{"e443"}},
	}
	fused := Fuse(claims)
	if len(fused) != 2 {
		t.Fatalf("want 2 endpoint-scoped claims, got %d (%+v)", len(fused), fused)
	}
}

func TestFuseCombinesIndependentSignalsOnSameEndpoint(t *testing.T) {
	claims := []model.Claim{
		{ID: "h", Kind: model.ClaimProduct, Product: "nginx", Score: 80, Subject: "10.0.0.1/tcp/443", CorrelationGroup: "header", EvidenceIDs: []string{"hdr"}},
		{ID: "f", Kind: model.ClaimProduct, Product: "nginx", Score: 80, Subject: "10.0.0.1/tcp/443", CorrelationGroup: "favicon", EvidenceIDs: []string{"ico"}},
	}
	fused := Fuse(claims)
	if len(fused) != 1 {
		t.Fatalf("want 1 fused claim, got %d (%+v)", len(fused), fused)
	}
	if fused[0].Score < 95 || fused[0].Score > 97 {
		t.Fatalf("score=%v want ~96", fused[0].Score)
	}
	if len(fused[0].EvidenceIDs) != 2 {
		t.Fatalf("evidence=%v", fused[0].EvidenceIDs)
	}
}

func TestFuseKeepsConflictingVersionsSeparate(t *testing.T) {
	claims := []model.Claim{
		{ID: "v22", Kind: model.ClaimProduct, Product: "nginx", Version: "1.22", Score: 90, Subject: "10.0.0.1/tcp/443", CorrelationGroup: "a"},
		{ID: "v24", Kind: model.ClaimProduct, Product: "nginx", Version: "1.24", Score: 88, Subject: "10.0.0.1/tcp/443", CorrelationGroup: "b"},
	}
	fused := Fuse(claims)
	var product, v22, v24 bool
	for _, c := range fused {
		if c.Product == "nginx" && c.Version == "" && c.Attribute == "" {
			product = true
			if c.Confidence != model.ConfidenceStrong && c.Confidence != model.ConfidenceExact {
				t.Fatalf("product claim should be strong/exact: %+v", c)
			}
		}
		if c.Version == "1.22" {
			v22 = true
			if len(c.ContradictionIDs) == 0 {
				t.Fatalf("1.22 should be conflicted: %+v", c)
			}
		}
		if c.Version == "1.24" {
			v24 = true
			if len(c.ContradictionIDs) == 0 {
				t.Fatalf("1.24 should be conflicted: %+v", c)
			}
		}
	}
	if !product || !v22 || !v24 {
		t.Fatalf("want product + 1.22 + 1.24 candidates, got %+v", fused)
	}
}

func TestComposeDropsRawWeakLinuxAfterNormalization(t *testing.T) {
	raw := []model.Claim{{
		ID: "linux-raw", Kind: model.ClaimOS, Family: "linux", Product: "Linux", Score: 90,
		CorrelationGroup: "ssh_banner", RuleIDs: []string{"openssh-banner"},
	}}
	out := Compose(raw)
	if len(out) != 1 {
		t.Fatalf("want single OS claim, got %+v", out)
	}
	if out[0].Score >= 90 {
		t.Fatalf("raw score 90 must not survive OS normalization: %+v", out[0])
	}
	if out[0].Confidence == model.ConfidenceStrong || out[0].Confidence == model.ConfidenceExact {
		t.Fatalf("normalized OpenSSH Linux must not be strong: %+v", out[0])
	}
}

func TestComposeKeepsContradictoryOSVisible(t *testing.T) {
	raw := []model.Claim{
		{
			ID: "linux-http", Kind: model.ClaimOS, Family: "linux", Product: "Linux", Score: 80,
			Subject: "asset:10.0.0.1", CorrelationGroup: "http_apache", RuleIDs: []string{"http-apache-linux"},
		},
		{
			ID: "win-smb", Kind: model.ClaimOS, Family: "windows", Product: "Windows", Score: 92,
			Subject: "asset:10.0.0.1", CorrelationGroup: "smb_ntlm", RuleIDs: []string{"smb-ntlm-windows"},
		},
	}
	out := Compose(raw)
	var linux, windows *model.Claim
	for i := range out {
		switch strings.ToLower(out[i].Family) {
		case "linux":
			linux = &out[i]
		case "windows":
			windows = &out[i]
		}
	}
	if linux == nil || windows == nil {
		t.Fatalf("both OS families must remain visible: %+v", out)
	}
	if windows.Confidence != model.ConfidenceStrong && windows.Confidence != model.ConfidenceExact {
		t.Fatalf("SMB Windows should stay strong: %+v", windows)
	}
	if len(linux.ContradictionIDs) == 0 {
		t.Fatalf("Linux heuristic should be contradicted by SMB: %+v", linux)
	}
	if linux.Score > 55 {
		t.Fatalf("contradicted Linux should be downgraded: %+v", linux)
	}
}
