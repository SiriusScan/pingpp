package fingerprint

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/SiriusScan/ping++/pkg/fingerprint/adapters"
)

// LoadBuiltinPacks loads YAML fingerprint packs and Recog/Wappalyzer corpora.
// Missing optional directories are ignored; parse errors fail closed.
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
		if err := e.LoadDir(d); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if rec, err := adapters.LoadRecogXML(filepath.Join(root, "recog", "ssh.xml")); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else {
		e.AddAdapter(rec)
	}
	if w, err := adapters.LoadWappalyzerJSON(filepath.Join(root, "wappalyzer", "technologies.json")); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else {
		e.AddAdapter(w)
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
