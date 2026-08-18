package engine

import "time"

// RegisterFunc is the signature every collector package exports.
type RegisterFunc func(*Registry)

// DefaultTimeout used when Config.Timeout is unset.
const DefaultTimeout = 3 * time.Second

// EffectiveTimeout returns cfg.Timeout or DefaultTimeout.
func EffectiveTimeout(cfg Config) time.Duration {
	if cfg.Timeout > 0 {
		return cfg.Timeout
	}
	return DefaultTimeout
}
