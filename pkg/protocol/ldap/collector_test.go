package ldap_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/protocol/ldap"
)

func TestLDAPRootDSEAttributes(t *testing.T) {
	entry := ldap.EncodeSearchResultEntry(map[string][]string{
		"vendorName":              {"OpenLDAP"},
		"vendorVersion":           {"2.6"},
		"namingContexts":          {"dc=example,dc=com"},
		"defaultNamingContext":    {"dc=example,dc=com"},
		"rootDomainNamingContext": {"dc=example,dc=com"},
		"dnsHostName":             {"dc1.example.com"},
		"supportedCapabilities":   {"1.2.840.113556.1.4.800"},
		"supportedLDAPVersion":    {"3"},
		"supportedSASLMechanisms": {"GSSAPI", "PLAIN"},
	})
	ln := serveLDAP(t, entry, false)
	defer func() { _ = ln.Close() }()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	col, _ := ldap.New(engine.Config{Timeout: time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := col.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != engine.OutcomeSuccess {
		t.Fatalf("outcome=%q", res.Outcome)
	}
	var payload struct {
		VendorName              string   `json:"vendor_name"`
		VendorVersion           string   `json:"vendor_version"`
		NamingContexts          []string `json:"naming_contexts"`
		DefaultNamingContext    string   `json:"default_naming_context"`
		RootDomainNamingContext string   `json:"root_domain_naming_context"`
		DNSHostName             string   `json:"dns_host_name"`
		SupportedCapabilities   []string `json:"supported_capabilities"`
		SupportedLDAPVersion    []string `json:"supported_ldap_version"`
		SupportedSASLMechanisms []string `json:"supported_sasl_mechanisms"`
	}
	if err := json.Unmarshal(res.Observations[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.VendorName != "OpenLDAP" || payload.DNSHostName != "dc1.example.com" {
		t.Fatalf("payload=%+v", payload)
	}
	if len(payload.NamingContexts) != 1 || payload.NamingContexts[0] != "dc=example,dc=com" {
		t.Fatalf("namingContexts=%v", payload.NamingContexts)
	}
	if len(payload.SupportedSASLMechanisms) != 2 {
		t.Fatalf("sasl=%v", payload.SupportedSASLMechanisms)
	}
}

func TestLDAPRejectsBareBERSequence(t *testing.T) {
	ln := serveLDAP(t, []byte{0x30, 0x03, 0x02, 0x01, 0x01}, false)
	defer func() { _ = ln.Close() }()
	assertOutcome(t, ln, nil, engine.OutcomeNoMatch)
}

func TestLDAPRejectsHTTPLookalike(t *testing.T) {
	ln := serveLDAP(t, []byte("HTTP/1.1 200 OK\r\n"), false)
	defer func() { _ = ln.Close() }()
	assertOutcome(t, ln, nil, engine.OutcomeNoMatch)
}

func TestLDAPSOnTLS(t *testing.T) {
	entry := ldap.EncodeSearchResultEntry(map[string][]string{
		"vendorName": {"OpenLDAP"},
	})
	ln := serveLDAP(t, entry, true)
	defer func() { _ = ln.Close() }()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	col, _ := ldap.New(engine.Config{Timeout: 2 * time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := col.RunResult(context.Background(), engine.CollectorInput{
		Endpoint: &ep,
		Extra:    map[string]string{"tls": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != engine.OutcomeSuccess {
		t.Fatalf("ldaps outcome=%q", res.Outcome)
	}
	var payload struct {
		LDAPS      bool   `json:"ldaps"`
		VendorName string `json:"vendor_name"`
	}
	_ = json.Unmarshal(res.Observations[0].Payload, &payload)
	if !payload.LDAPS || payload.VendorName != "OpenLDAP" {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestLDAPPort636Advertised(t *testing.T) {
	col, _ := ldap.New(engine.Config{})
	md := col.Metadata()
	found := false
	for _, p := range md.DefaultPorts {
		if p == 636 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected port 636 in metadata, got %v", md.DefaultPorts)
	}
}

func assertOutcome(t *testing.T, ln net.Listener, extra map[string]string, want engine.ProbeOutcome) {
	t.Helper()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	col, _ := ldap.New(engine.Config{Timeout: time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := col.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep, Extra: extra})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != want {
		t.Fatalf("outcome=%q want %q", res.Outcome, want)
	}
}

func serveLDAP(t *testing.T, reply []byte, useTLS bool) net.Listener {
	t.Helper()
	var ln net.Listener
	var err error
	if useTLS {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{testCert(t)}})
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		if tc, ok := c.(*tls.Conn); ok {
			_ = tc.Handshake()
		}
		buf := make([]byte, 1024)
		_, _ = c.Read(buf)
		_, _ = c.Write(reply)
	}()
	return ln
}

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ldap-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
