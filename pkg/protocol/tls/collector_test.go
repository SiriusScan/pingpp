package tlscol_test

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
	"testing"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/model"
	tlscol "github.com/SiriusScan/ping++/pkg/protocol/tls"
)

func TestTLSCollectorCapturesCert(t *testing.T) {
	ln, conf := startTLSServer(t)
	defer func() { _ = ln.Close() }()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	c, err := tlscol.New(engine.Config{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ep := model.NewEndpoint("127.0.0.1", port, model.TransportTCP, model.EndpointOpen)
	obs, err := c.Run(context.Background(), engine.CollectorInput{
		Asset:    model.NewAssetFromIP("127.0.0.1"),
		Endpoint: &ep,
		Target:   &model.Target{Hostname: "localhost"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || obs[0].Error != "" {
		t.Fatalf("obs=%+v", obs)
	}
	var payload model.TLSObservation
	if err := obs[0].DecodePayload(&payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Certificates) == 0 {
		t.Fatal("expected certificates")
	}
	if payload.Certificates[0].SubjectCN != "localhost" {
		t.Fatalf("cn=%q", payload.Certificates[0].SubjectCN)
	}
	if payload.Certificates[0].SHA256 == "" || payload.Certificates[0].SPKISHA256 == "" {
		t.Fatal("expected cert hashes")
	}
	_ = conf
}

func startTLSServer(t *testing.T) (net.Listener, *tls.Config) {
	t.Helper()
	certPEM, keyPEM := mustSelfSigned(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			_ = c.Close()
		}
	}()
	return ln, cfg
}

func mustSelfSigned(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
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
