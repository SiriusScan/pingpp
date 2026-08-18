package fingerprint

import (
	"testing"

	"github.com/SiriusScan/ping++/pkg/model"
)

func BenchmarkFuseIndependentSignals(b *testing.B) {
	claims := []model.Claim{
		{ID: "h", Kind: model.ClaimProduct, Product: "nginx", Score: 80, Subject: "10.0.0.1/tcp/443", CorrelationGroup: "header", EvidenceIDs: []string{"hdr"}},
		{ID: "f", Kind: model.ClaimProduct, Product: "nginx", Score: 80, Subject: "10.0.0.1/tcp/443", CorrelationGroup: "favicon", EvidenceIDs: []string{"ico"}},
		{ID: "o", Kind: model.ClaimOS, Product: "Linux", Family: "linux", Score: 40, Subject: "asset:10.0.0.1", CorrelationGroup: "ttl"},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Compose(claims)
	}
}
