package fingerprint_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/fingerprint"
	"github.com/SiriusScan/ping++/pkg/model"
	"gopkg.in/yaml.v3"
)

func TestBuiltinCorpusMatchBudget(t *testing.T) {
	e := fingerprint.NewEngine()
	if err := e.LoadBuiltinPacks(); err != nil {
		t.Fatal(err)
	}
	fixtures := loadPositiveFixtures(t)
	if len(fixtures) == 0 {
		t.Fatal("no positive fixtures")
	}
	const rounds = 10
	start := time.Now()
	var first int
	for r := 0; r < rounds; r++ {
		n := 0
		for _, obs := range fixtures {
			n += len(e.Match([]model.ObservationRecord{obs}))
		}
		if r == 0 {
			first = n
			if first < len(fixtures) {
				t.Fatalf("claim count collapsed: %d claims for %d fixtures", first, len(fixtures))
			}
		} else if n != first {
			t.Fatalf("round %d claims=%d want %d", r, n, first)
		}
	}
	elapsed := time.Since(start)
	if elapsed > 15*time.Second {
		t.Fatalf("positive corpus match took %s (budget 15s, %d fixtures x %d rounds)", elapsed, len(fixtures), rounds)
	}
}

func BenchmarkLoadBuiltinPacks(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e := fingerprint.NewEngine()
		if err := e.LoadBuiltinPacks(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBuiltinCorpusMatch(b *testing.B) {
	e := fingerprint.NewEngine()
	if err := e.LoadBuiltinPacks(); err != nil {
		b.Fatal(err)
	}
	fixtures := loadPositiveFixtures(b)
	if len(fixtures) == 0 {
		b.Fatal("no positive fixtures")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, obs := range fixtures {
			_ = e.Match([]model.ObservationRecord{obs})
		}
	}
}

func loadPositiveFixtures(t testing.TB) []model.ObservationRecord {
	t.Helper()
	root := fixtureRoot(t)
	var out []model.ObservationRecord
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		if !strings.Contains(path, string(filepath.Separator)+"positive"+string(filepath.Separator)) {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var fx fixtureFile
		if err := yaml.Unmarshal(raw, &fx); err != nil {
			t.Errorf("%s: %v", path, err)
			return nil
		}
		obs := model.ObservationRecord{ID: path, ObservationType: fx.ObservationType, CorrelationGroup: path}
		if err := obs.SetPayload(fx.Payload); err != nil {
			t.Errorf("%s payload: %v", path, err)
			return nil
		}
		out = append(out, obs)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
