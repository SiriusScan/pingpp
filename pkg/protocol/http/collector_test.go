package httpcol_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/artifact"
	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	httpcol "github.com/SiriusScan/ping++/pkg/protocol/http"
)

func TestHTTPCollectorGETObservation(t *testing.T) {
	body := []byte(`<html><head><title>Grafana</title><meta name="generator" content="Grafana"><link rel="icon" href="/favicon.ico"></head><body>ok</body></html>`)
	ln := startHTTP(t, body)
	defer func() { _ = ln.Close() }()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	c, err := httpcol.New(engine.Config{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	obs, err := c.Run(context.Background(), engine.CollectorInput{
		Asset:    model.NewAssetFromIP("127.0.0.1"),
		Endpoint: &ep,
		Target:   &model.Target{Hostname: "grafana.local"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || obs[0].Error != "" {
		t.Fatalf("obs=%+v", obs)
	}
	var p model.HTTPObservation
	if err := obs[0].DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if p.StatusCode != 200 {
		t.Fatalf("status=%d", p.StatusCode)
	}
	if p.Title != "Grafana" {
		t.Fatalf("title=%q", p.Title)
	}
	if p.MetaGenerator != "Grafana" {
		t.Fatalf("generator=%q", p.MetaGenerator)
	}
	if p.Server != "test-httpd" {
		t.Fatalf("server=%q", p.Server)
	}
	sum := sha256.Sum256(body)
	if p.RawBodySHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("raw hash mismatch")
	}
	if p.NormalizedSHA256 == "" || p.SimHash == 0 {
		t.Fatal("expected normalized hash and simhash")
	}
	if p.Favicon == nil || p.Favicon.URL != "/favicon.ico" {
		t.Fatalf("favicon=%+v", p.Favicon)
	}
	if obs[0].ObservationType != model.ObservationHTTP {
		t.Fatal("wrong type")
	}
}

func TestHTTPSameHostRedirectAndCrossHostStop(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/next", http.StatusFound)
	})
	mux.HandleFunc("/next", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://evil.example/steal")
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte("<title>stopped</title>"))
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
	res, err := c.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	var p model.HTTPObservation
	_ = res.Observations[0].DecodePayload(&p)
	if p.Title != "stopped" {
		t.Fatalf("title=%q chain=%+v", p.Title, p.RedirectChain)
	}
	if p.Location != "https://evil.example/steal" {
		t.Fatalf("cross-host Location=%q", p.Location)
	}
}

func TestHTTPBodyArtifactAndTruncation(t *testing.T) {
	body := make([]byte, 70*1024)
	for i := range body {
		body[i] = 'A'
	}
	ln := startHTTP(t, body)
	defer func() { _ = ln.Close() }()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	store := artifact.NewMemoryStore(256 * 1024)
	c, _ := httpcol.New(engine.Config{Timeout: time.Second})
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	res, err := c.RunResult(context.Background(), engine.CollectorInput{
		Endpoint:  &ep,
		Artifacts: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	var p model.HTTPObservation
	_ = res.Observations[0].DecodePayload(&p)
	if !p.Truncated {
		t.Fatal("expected truncated body")
	}
	if len(res.Observations[0].ArtifactIDs) == 0 {
		t.Fatal("expected body artifact id")
	}
}

func TestHTTPFaviconHashes(t *testing.T) {
	icon := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<link rel="icon" href="/favicon.ico">`))
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		_, _ = w.Write(icon)
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
	res, err := c.RunResult(context.Background(), engine.CollectorInput{Endpoint: &ep})
	if err != nil {
		t.Fatal(err)
	}
	var p model.HTTPObservation
	_ = res.Observations[0].DecodePayload(&p)
	if p.Favicon == nil || p.Favicon.SHA256 == "" {
		t.Fatalf("favicon hashes missing: %+v", p.Favicon)
	}
	sum := sha256.Sum256(icon)
	if p.Favicon.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha=%s", p.Favicon.SHA256)
	}
}

func startHTTP(t *testing.T, body []byte) net.Listener {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Server", "test-httpd")
		w.Header().Set("X-Powered-By", "Go")
		w.Header().Set("Set-Cookie", "sid=abc; Path=/")
		_, _ = w.Write(body)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln
}
