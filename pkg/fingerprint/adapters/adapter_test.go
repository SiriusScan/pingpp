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
	if len(claims) != 1 || claims[0].Product != "OpenSSH" || claims[0].Version != "9.6" {
		t.Fatalf("%+v", claims)
	}
}

func TestNativeRecogXMLOpenSSH(t *testing.T) {
	xml := []byte(`<fingerprints matches="ssh.banner">
  <fingerprint pattern="OpenSSH">
    <description>OpenSSH</description>
    <param pos="0" name="service.vendor">OpenBSD</param>
    <param pos="0" name="service.product">OpenSSH</param>
  </fingerprint>
</fingerprints>`)
	r, err := adapters.ParseRecogXML(xml)
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

func TestWappalyzerJSONNginx(t *testing.T) {
	raw := []byte(`{"nginx":{"cats":[22],"headers":{"Server":"nginx(?:/([\\d.]+))?"}}}`)
	w, err := adapters.ParseWappalyzerJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := w.Detect(model.HTTPObservation{Server: "nginx/1.24"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range claims {
		if c.Product == "nginx" {
			found = true
		}
	}
	if !found {
		t.Fatalf("claims=%+v", claims)
	}
}

func TestRecogParamValueAttribute(t *testing.T) {
	xml := []byte(`<fingerprints matches="ssh.banner">
  <fingerprint pattern="OpenSSH">
    <description>OpenSSH</description>
    <param pos="0" name="service.vendor" value="OpenBSD"/>
    <param pos="0" name="service.product" value="OpenSSH"/>
  </fingerprint>
</fingerprints>`)
	r, err := adapters.ParseRecogXML(xml)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := r.MatchField("ssh", "banner", "SSH-2.0-OpenSSH_9.6")
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 1 || claims[0].Product != "OpenSSH" || claims[0].Vendor != "OpenBSD" {
		t.Fatalf("%+v", claims)
	}
}

func TestRecogSeparatesServiceAndOSWithCaptures(t *testing.T) {
	xml := []byte(`<fingerprints matches="ssh.banner">
  <fingerprint pattern="^OpenSSH_([\d.]+) green@FreeBSD.org">
    <description>OpenSSH on FreeBSD 4.3</description>
    <param pos="1" name="service.version"/>
    <param pos="0" name="service.vendor" value="OpenBSD"/>
    <param pos="0" name="service.product" value="OpenSSH"/>
    <param pos="0" name="service.cpe23" value="cpe:/a:openbsd:openssh:{service.version}"/>
    <param pos="0" name="os.vendor" value="FreeBSD"/>
    <param pos="0" name="os.product" value="FreeBSD"/>
    <param pos="0" name="os.family" value="FreeBSD"/>
    <param pos="0" name="os.version" value="4.3"/>
    <param pos="0" name="hw.vendor" value="Dell"/>
    <param pos="0" name="hw.device" value="Server"/>
  </fingerprint>
</fingerprints>`)
	r, err := adapters.ParseRecogXML(xml)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := r.MatchField("ssh", "banner", "OpenSSH_2.3.0 green@FreeBSD.org")
	if err != nil {
		t.Fatal(err)
	}
	var product, os, hw *model.Claim
	for i := range claims {
		c := &claims[i]
		switch c.Kind {
		case model.ClaimProduct:
			product = c
		case model.ClaimOS:
			os = c
		case model.ClaimDevice:
			hw = c
		}
	}
	if product == nil || product.Product != "OpenSSH" || product.Version != "2.3.0" || product.Vendor != "OpenBSD" {
		t.Fatalf("product=%+v", product)
	}
	if product.CPE != "cpe:/a:openbsd:openssh:2.3.0" {
		t.Fatalf("cpe=%q", product.CPE)
	}
	if os == nil || os.Product != "FreeBSD" || os.Version != "4.3" || os.Vendor != "FreeBSD" {
		t.Fatalf("os=%+v", os)
	}
	if hw == nil || hw.Vendor != "Dell" || hw.DeviceType != "Server" {
		t.Fatalf("hw=%+v", hw)
	}
}

func TestRecogClaimsKeepEndpointSubject(t *testing.T) {
	xml := []byte(`<fingerprints matches="ssh.banner">
  <fingerprint pattern="OpenSSH">
    <param pos="0" name="service.product" value="OpenSSH"/>
  </fingerprint>
</fingerprints>`)
	r, err := adapters.ParseRecogXML(xml)
	if err != nil {
		t.Fatal(err)
	}
	obs22 := model.ObservationRecord{ID: "s22", ObservationType: model.ObservationSSH, Endpoint: &model.EndpointRef{Address: "10.0.0.1", Port: 22, Transport: model.TransportTCP}}
	_ = obs22.SetPayload(model.SSHObservation{Banner: "SSH-2.0-OpenSSH_9.6"})
	obs2222 := model.ObservationRecord{ID: "s2222", ObservationType: model.ObservationSSH, Endpoint: &model.EndpointRef{Address: "10.0.0.1", Port: 2222, Transport: model.TransportTCP}}
	_ = obs2222.SetPayload(model.SSHObservation{Banner: "SSH-2.0-OpenSSH_9.6"})
	claims, err := r.Match([]model.ObservationRecord{obs22, obs2222})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, c := range claims {
		if c.Subject == "" {
			t.Fatalf("empty subject: %+v", c)
		}
		seen[c.Subject]++
	}
	if seen["10.0.0.1/tcp/22"] == 0 || seen["10.0.0.1/tcp/2222"] == 0 {
		t.Fatalf("subjects=%v", seen)
	}
}

func TestRecogHTTPHeaderServerMapping(t *testing.T) {
	xml := []byte(`<fingerprints matches="http_header.server">
  <fingerprint pattern="^nginx">
    <param pos="0" name="service.product" value="nginx"/>
  </fingerprint>
</fingerprints>`)
	r, err := adapters.ParseRecogXML(xml)
	if err != nil {
		t.Fatal(err)
	}
	obs := model.ObservationRecord{ID: "h1", ObservationType: model.ObservationHTTP, Endpoint: &model.EndpointRef{Address: "10.0.0.1", Port: 80, Transport: model.TransportTCP}}
	_ = obs.SetPayload(model.HTTPObservation{Server: "nginx/1.24"})
	claims, err := r.Match([]model.ObservationRecord{obs})
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 1 || claims[0].Product != "nginx" {
		t.Fatalf("%+v", claims)
	}
	if claims[0].Subject != "10.0.0.1/tcp/80" {
		t.Fatalf("subject=%q", claims[0].Subject)
	}
	if claims[0].Subject != "10.0.0.1/tcp/80" {
		t.Fatalf("subject=%q", claims[0].Subject)
	}
}

func TestRecogSkipsNonRE2(t *testing.T) {
	xml := []byte(`<fingerprints matches="ssh.banner">
  <fingerprint pattern="(?&lt;=foo)bar">
    <param pos="0" name="service.product" value="Bad"/>
  </fingerprint>
  <fingerprint pattern="OpenSSH">
    <param pos="0" name="service.product" value="OpenSSH"/>
  </fingerprint>
</fingerprints>`)
	r, err := adapters.ParseRecogXML(xml)
	if err != nil {
		t.Fatal(err)
	}
	if r.RuleCount() != 1 {
		t.Fatalf("rule count=%d want 1 (skip lookbehind)", r.RuleCount())
	}
}

func TestRecogMatchesSSHSoftwareIdent(t *testing.T) {
	xml := []byte(`<fingerprints matches="ssh.banner">
  <fingerprint pattern="^OpenSSH_">
    <param pos="0" name="service.product" value="OpenSSH"/>
  </fingerprint>
</fingerprints>`)
	r, err := adapters.ParseRecogXML(xml)
	if err != nil {
		t.Fatal(err)
	}
	obs := model.ObservationRecord{ID: "s1", ObservationType: model.ObservationSSH}
	_ = obs.SetPayload(model.SSHObservation{Banner: "SSH-2.0-OpenSSH_9.6"})
	claims, err := r.Match([]model.ObservationRecord{obs})
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 1 || claims[0].Product != "OpenSSH" {
		t.Fatalf("%+v", claims)
	}
}
