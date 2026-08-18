package httpcol_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	httpcol "github.com/SiriusScan/ping++/pkg/protocol/http"
)

// pin-test.invalid is a reserved TLD and must not resolve. If DialContext is
// not pinned to Endpoint.Address, these probes fail with a DNS error and
// would also be free to land on a different A/AAAA than the selected IP.

func TestHTTPCollectorPinsTransportIPAndHostHeader(t *testing.T) {
	const logical = "pin-test.invalid"
	var gotHost atomic.Value
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost.Store(r.Host)
		w.Header().Set("Server", "pin-httpd")
		_, _ = w.Write([]byte("<title>pinned</title>"))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close(); _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	c, err := httpcol.New(engine.Config{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := c.RunResult(context.Background(), engine.CollectorInput{
		Endpoint: &ep,
		Target:   &model.Target{Hostname: logical},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != engine.OutcomeSuccess {
		t.Fatalf("outcome=%q obs=%+v", res.Outcome, res.Observations)
	}
	var p model.HTTPObservation
	if err := res.Observations[0].DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	host, _ := gotHost.Load().(string)
	if !strings.Contains(host, logical) {
		t.Fatalf("Host header=%q want logical host %q", host, logical)
	}
	if p.LogicalHost != logical {
		t.Fatalf("logical_host=%q", p.LogicalHost)
	}
	if p.TransportIP != "127.0.0.1" {
		t.Fatalf("transport_ip=%q", p.TransportIP)
	}
	if res.Observations[0].Endpoint == nil || res.Observations[0].Endpoint.Address != "127.0.0.1" {
		t.Fatalf("evidence attributed to %+v", res.Observations[0].Endpoint)
	}
	if !strings.Contains(p.URL, logical) {
		t.Fatalf("url=%q", p.URL)
	}
}

func TestHTTPCollectorPinsTLSSNIToLogicalHost(t *testing.T) {
	const logical = "pin-test.invalid"
	certPEM, keyPEM := mustSelfSignedHTTP(t, logical)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	var sawSNI atomic.Value
	var sawHost atomic.Value
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sawSNI.Store(hello.ServerName)
			return nil, nil
		},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		TLSConfig: tlsCfg,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sawHost.Store(r.Host)
			_, _ = w.Write([]byte("<title>tls-pinned</title>"))
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close(); _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	c, err := httpcol.New(engine.Config{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := c.RunResult(context.Background(), engine.CollectorInput{
		Endpoint: &ep,
		Target:   &model.Target{Hostname: logical},
		Extra:    map[string]string{"tls": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != engine.OutcomeSuccess {
		t.Fatalf("outcome=%q obs=%+v", res.Outcome, res.Observations)
	}
	var p model.HTTPObservation
	if err := res.Observations[0].DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	sni, _ := sawSNI.Load().(string)
	if sni != logical {
		t.Fatalf("SNI=%q want %q", sni, logical)
	}
	host, _ := sawHost.Load().(string)
	if !strings.Contains(host, logical) {
		t.Fatalf("Host=%q", host)
	}
	if p.TLSServerName != logical {
		t.Fatalf("tls_server_name=%q", p.TLSServerName)
	}
	if p.TransportIP != "127.0.0.1" {
		t.Fatalf("transport_ip=%q", p.TransportIP)
	}
}

func TestHTTPSameHostRedirectStaysOnPinnedIP(t *testing.T) {
	const logical = "pin-test.invalid"
	var hits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "/next", http.StatusFound)
	})
	mux.HandleFunc("/next", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("<title>stayed</title>"))
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close(); _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	c, _ := httpcol.New(engine.Config{Timeout: time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := c.RunResult(context.Background(), engine.CollectorInput{
		Endpoint: &ep,
		Target:   &model.Target{Hostname: logical},
	})
	if err != nil {
		t.Fatal(err)
	}
	var p model.HTTPObservation
	_ = res.Observations[0].DecodePayload(&p)
	if p.Title != "stayed" {
		t.Fatalf("title=%q chain=%+v hits=%d", p.Title, p.RedirectChain, hits.Load())
	}
	if p.TransportIP != "127.0.0.1" {
		t.Fatalf("transport_ip=%q", p.TransportIP)
	}
	if hits.Load() < 2 {
		t.Fatalf("redirect did not stay on pinned listener, hits=%d", hits.Load())
	}
}

func mustSelfSignedHTTP(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{cn},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}
