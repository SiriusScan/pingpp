package transport

import (
	"context"
	"sync"
)

type hostLimiterKey struct{}

// HostLimiter bounds in-flight network operations for one logical scan
// (hostname with every A/AAAA). It is not a global rate limiter.
type HostLimiter struct {
	sem chan struct{}
}

// NewHostLimiter creates a permit pool of size n. n <= 0 defaults to 4.
func NewHostLimiter(n int) *HostLimiter {
	if n <= 0 {
		n = 4
	}
	return &HostLimiter{sem: make(chan struct{}, n)}
}

// WithHostLimiter stores l on ctx. Nil is a no-op.
func WithHostLimiter(ctx context.Context, l *HostLimiter) context.Context {
	if l == nil {
		return ctx
	}
	return context.WithValue(ctx, hostLimiterKey{}, l)
}

// ContextHostLimiter returns the per-scan host limiter, or nil.
func ContextHostLimiter(ctx context.Context) *HostLimiter {
	l, _ := ctx.Value(hostLimiterKey{}).(*HostLimiter)
	return l
}

// Acquire waits for one permit. The returned release function is idempotent.
// Acquiring a permit does not count as a network operation.
func (l *HostLimiter) Acquire(ctx context.Context) (func(), error) {
	if l == nil {
		return func() {}, nil
	}
	select {
	case <-ctx.Done():
		return func() {}, ctx.Err()
	case l.sem <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() { <-l.sem })
		}, nil
	}
}

func acquireHost(ctx context.Context) (func(), error) {
	return ContextHostLimiter(ctx).Acquire(ctx)
}

// AcquireHost waits for the per-scan host-concurrency permit, if any.
func AcquireHost(ctx context.Context) (func(), error) {
	return acquireHost(ctx)
}
