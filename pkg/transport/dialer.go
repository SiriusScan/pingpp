// Package transport provides shared dialing helpers for protocol collectors.
package transport

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// DialTCP dials a TCP endpoint with timeout.
func DialTCP(ctx context.Context, address string, port uint16, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(address, itoa(port)))
}

// DialTLS performs a TLS handshake over TCP.
// Successful TLS does not imply HTTPS — callers decide application protocol.
func DialTLS(ctx context.Context, address string, port uint16, serverName string, timeout time.Duration) (*tls.Conn, error) {
	raw, err := DialTCP(ctx, address, port, timeout)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		InsecureSkipVerify: true, // fingerprinting, not trust validation
		MinVersion:         tls.VersionTLS10,
		ServerName:         serverName,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	conn := tls.Client(raw, cfg)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

func itoa(u uint16) string {
	// small local helper to avoid strconv import churn in hot paths of tests
	var b [6]byte
	i := len(b)
	if u == 0 {
		return "0"
	}
	n := int(u)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
