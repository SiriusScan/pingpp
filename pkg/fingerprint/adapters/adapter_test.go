package adapters_test

import (
	"testing"

	"github.com/SiriusScan/ping++/pkg/fingerprint/adapters"
	"github.com/SiriusScan/ping++/pkg/model"
)

func TestNativeWebTechGrafana(t *testing.T) {
	d := adapters.NewNativeWebTech()
	claims, err := d.Detect(model.HTTPObservation{Title: "Grafana", Server: "nginx"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range claims {
		if c.Product == "Grafana" && c.Kind == model.ClaimApplication {
			found = true
		}
	}
	if !found {
		t.Fatalf("claims=%+v", claims)
	}
}

func TestNativeRecogSSH(t *testing.T) {
	r, err := adapters.NewNativeRecogFromRules([]adapters.RecogRule{{
		ID:        "recog-openssh",
		Protocol:  "ssh",
		Field:     "banner",
		Pattern:   `(?i)OpenSSH_([\d.]+)`,
		Product:   "OpenSSH",
		Certainty: "strong",
	}})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := r.MatchField("ssh", "banner", "SSH-2.0-OpenSSH_9.6")
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 1 || claims[0].Product != "OpenSSH" {
		t.Fatalf("%+v", claims)
	}
}
