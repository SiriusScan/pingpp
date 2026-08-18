package fingerprint

import (
	"path/filepath"
	"runtime"
)

// LoadBuiltinPacks loads YAML fingerprint packs from the repo fingerprints/ tree.
//
// TODO: do not swallow LoadDir errors. NewEngine treats a nil return as
// success, so bad YAML / invalid regex / unreadable dirs currently vanish.
// Missing optional subdirectories can stay non-fatal; everything else must
// fail closed. Replace runtime.Caller loading with go:embed.
func (e *Engine) LoadBuiltinPacks(root string) error {
	dirs := []string{
		filepath.Join(root, "http"),
		filepath.Join(root, "ssh"),
		filepath.Join(root, "devices"),
		filepath.Join(root, "os"),
		filepath.Join(root, "services"),
		filepath.Join(root, "recog"),
	}
	for _, d := range dirs {
		_ = e.LoadDir(d) // missing dirs are fine
	}
	return nil
}

// RepoFingerprintsRoot returns the fingerprints/ directory relative to this package.
func RepoFingerprintsRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "fingerprints"
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "fingerprints"))
}
