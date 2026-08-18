package output_test

import (
	"testing"

	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/output"
)

func TestToLegacyFromAsset(t *testing.T) {
	a := model.NewAssetFromIP("192.0.2.10")
	a.Hostnames = []string{"host.example"}
	a.AddEndpoint(model.NewEndpoint("192.0.2.10", 22, model.TransportTCP, model.EndpointOpen))
	a.AddEndpoint(model.NewEndpoint("192.0.2.10", 80, model.TransportTCP, model.EndpointOpen))
	obs := model.ObservationRecord{ObservationType: model.ObservationSSH}
	_ = obs.SetPayload(model.SSHObservation{Banner: "SSH-2.0-OpenSSH_9.6"})
	a.AddObservation(obs)
	httpObs := model.ObservationRecord{ObservationType: model.ObservationHTTP}
	_ = httpObs.SetPayload(model.HTTPObservation{Server: "nginx"})
	a.AddObservation(httpObs)
	a.AddClaim(model.NewClaim(model.ClaimOS, "Windows", 92))
	a.Claims[0].Family = "windows"

	lr := output.ToLegacy(a, true)
	if lr.IP != "192.0.2.10" || lr.Hostname != "host.example" {
		t.Fatalf("%+v", lr)
	}
	if lr.SSHBanner == "" || lr.HTTPServer != "nginx" {
		t.Fatalf("banners=%+v", lr)
	}
	if len(lr.OpenPorts) != 2 {
		t.Fatalf("ports=%v", lr.OpenPorts)
	}
	if lr.OSFamily != "windows" {
		t.Fatalf("os=%q", lr.OSFamily)
	}
	s := output.ToSiriusHost(a, true)
	if s["ip"] != "192.0.2.10" {
		t.Fatalf("%v", s)
	}
	if s["endpoints"] == nil || s["claims"] == nil {
		t.Fatal("expected richer endpoint/claim fields")
	}
}
