package transport

import (
	"context"
	"sync"
	"time"
)

type limiterKey struct{}

// Limiter is a token-bucket cap on network operations per second for a run.
// Wait is called from DialTCP/DialUDP/CountDial, not from collector scheduling.
type Limiter struct {
	rate   float64
	burst  float64
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// NewLimiter creates a limiter for rate operations/second. Rate <= 0 means
// unlimited (returns nil).
func NewLimiter(ratePerSecond int) *Limiter {
	if ratePerSecond <= 0 {
		return nil
	}
	r := float64(ratePerSecond)
	return &Limiter{
		rate:   r,
		burst:  r,
		tokens: r,
		last:   time.Now(),
	}
}

// WithLimiter stores l on ctx. A nil limiter is a no-op.
func WithLimiter(ctx context.Context, l *Limiter) context.Context {
	if l == nil {
		return ctx
	}
	return context.WithValue(ctx, limiterKey{}, l)
}

// ContextLimiter returns the run limiter, or nil.
func ContextLimiter(ctx context.Context) *Limiter {
	l, _ := ctx.Value(limiterKey{}).(*Limiter)
	return l
}

// Wait blocks until one network-op token is available or ctx is done.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		l.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(l.last).Seconds()
		if elapsed > 0 {
			l.tokens += elapsed * l.rate
			if l.tokens > l.burst {
				l.tokens = l.burst
			}
			l.last = now
		}
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		wait := time.Duration((1-l.tokens)/l.rate*float64(time.Second)) + time.Millisecond
		l.mu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
