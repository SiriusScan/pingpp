package transport

import (
	"context"
	"errors"
	"sync"
)

type meterKey struct{}

// ErrBudgetExceeded is returned when a dial would exceed MaxNetworkOps.
var ErrBudgetExceeded = errors.New("network operation budget exceeded")

// Meter counts network operations for a scan. Collectors should not
// increment budget counters themselves; dial helpers do it here.
type Meter struct {
	mu            sync.Mutex
	NetworkOps    int
	Connections   int
	BytesRead     int64
	BytesSent     int64
	MaxNetworkOps int
}

// WithMeter stores m on ctx.
func WithMeter(ctx context.Context, m *Meter) context.Context {
	if m == nil {
		return ctx
	}
	return context.WithValue(ctx, meterKey{}, m)
}

// ContextMeter returns the scan meter, or nil.
func ContextMeter(ctx context.Context) *Meter {
	m, _ := ctx.Value(meterKey{}).(*Meter)
	return m
}

// AddDial records a connection/packet operation.
func (m *Meter) AddDial() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.MaxNetworkOps > 0 && m.NetworkOps >= m.MaxNetworkOps {
		return ErrBudgetExceeded
	}
	m.NetworkOps++
	m.Connections++
	return nil
}

// AddBytes records payload volume.
func (m *Meter) AddBytes(read, sent int64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.BytesRead += read
	m.BytesSent += sent
	m.mu.Unlock()
}

// Snapshot copies counters.
func (m *Meter) Snapshot() (ops, conns int, read, sent int64) {
	if m == nil {
		return 0, 0, 0, 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.NetworkOps, m.Connections, m.BytesRead, m.BytesSent
}
