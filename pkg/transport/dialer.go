// Package transport provides shared dialing helpers for protocol collectors.
package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// DialTCP dials a TCP endpoint with timeout and records a network operation.
func DialTCP(ctx context.Context, address string, port uint16, timeout time.Duration) (net.Conn, error) {
	return dial(ctx, "tcp", address, port, timeout)
}

// DialUDP dials a UDP endpoint and records a network operation.
func DialUDP(ctx context.Context, address string, port uint16, timeout time.Duration) (net.Conn, error) {
	return dial(ctx, "udp", address, port, timeout)
}

func dial(ctx context.Context, network, address string, port uint16, timeout time.Duration) (net.Conn, error) {
	release, err := acquireHost(ctx)
	if err != nil {
		return nil, err
	}
	held := true
	defer func() {
		if held {
			release()
		}
	}()
	if err := recordDial(ctx); err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, network, net.JoinHostPort(address, itoa(port)))
	if err != nil {
		return nil, err
	}
	held = false
	return wrapRelease(WrapConn(ctx, conn), release), nil
}

func recordDial(ctx context.Context) error {
	if l := ContextLimiter(ctx); l != nil {
		if err := l.Wait(ctx); err != nil {
			return err
		}
	}
	if m := ContextMeter(ctx); m != nil {
		return m.AddDial()
	}
	return nil
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

// UpgradeTLS handshakes TLS on an existing connection (STARTTLS). It does not
// count another dial: the inner conn is already metered. Application protocols
// must not advertise HTTP ALPN here.
func UpgradeTLS(ctx context.Context, raw net.Conn, serverName string, timeout time.Duration) (*tls.Conn, error) {
	if raw == nil {
		return nil, fmt.Errorf("tls upgrade: nil connection")
	}
	cfg := &tls.Config{
		InsecureSkipVerify: true, // fingerprinting, not trust validation
		MinVersion:         tls.VersionTLS10,
		ServerName:         serverName,
	}
	conn := tls.Client(raw, cfg)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return conn, nil
}

func itoa(u uint16) string {
	return fmt.Sprintf("%d", u)
}
