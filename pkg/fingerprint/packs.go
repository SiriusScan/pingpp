package fingerprint

import (
	"errors"
	"fmt"
	"io/fs"
	"sync/atomic"

	"github.com/SiriusScan/ping++/fingerprints"
	"github.com/SiriusScan/ping++/pkg/fingerprint/adapters"
)

var builtinLoadCount atomic.Int64

// BuiltinLoadCount is the number of times LoadBuiltinPacks has run in this
// process. Session tests use it to prove the corpus loads once per Session.
func BuiltinLoadCount() int64 {
	return builtinLoadCount.Load()
}

// LoadBuiltinPacks loads YAML packs and Recog/Wappalyzer corpora from the
// embedded filesystem. A released binary does not need the source tree.
func (e *Engine) LoadBuiltinPacks() error {
	builtinLoadCount.Add(1)
	return e.LoadFS(fingerprints.FS)
}

// LoadFS loads YAML, Recog XML, and Wappalyzer JSON from an fs.FS.
// Parse errors fail closed. Individual Recog regexes that are not RE2 are skipped by the XML parser.
func (e *Engine) LoadFS(fsys fs.FS) error {
	if e == nil {
		return fmt.Errorf("nil engine")
	}
	yamlGlobs := []string{
		"http/*.yaml", "http/*.yml",
		"ssh/*.yaml", "ssh/*.yml",
		"devices/*.yaml", "devices/*.yml",
		"os/*.yaml", "os/*.yml",
		"services/*.yaml", "services/*.yml",
	}
	for _, g := range yamlGlobs {
		matches, err := fs.Glob(fsys, g)
		if err != nil {
			return err
		}
		for _, p := range matches {
			data, err := fs.ReadFile(fsys, p)
			if err != nil {
				return err
			}
			if err := e.LoadYAML(data); err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
		}
	}
	xmlMatches, err := fs.Glob(fsys, "recog/*.xml")
	if err != nil {
		return err
	}
	for _, p := range xmlMatches {
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		rec, err := adapters.ParseRecogXML(data)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		e.AddAdapter(rec)
	}
	data, err := fs.ReadFile(fsys, "wappalyzer/technologies.json")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	w, err := adapters.ParseWappalyzerJSON(data)
	if err != nil {
		return fmt.Errorf("wappalyzer/technologies.json: %w", err)
	}
	e.AddAdapter(w)
	return nil
}
