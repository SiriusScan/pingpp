package fingerprint

import (
	"path/filepath"
	"runtime"
)

// LoadBuiltinPacks loads YAML fingerprint packs from the repo fingerprints/ tree.
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
