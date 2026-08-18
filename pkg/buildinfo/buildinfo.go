// Package buildinfo records binary provenance for pingpp.scan/v1 documents.
package buildinfo

import (
	"runtime"
)

// Set via -ldflags at release time.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// FingerprintCorpusID is a stable label for the embedded YAML/Recog/Wappalyzer
// packs. A content digest is a later hardening step.
const FingerprintCorpusID = "builtin"

// Info is the tool object on machine documents.
type Info struct {
	Name                string `json:"name"`
	Version             string `json:"version"`
	Commit              string `json:"commit"`
	BuildDate           string `json:"build_date,omitempty"`
	GoVersion           string `json:"go_version"`
	FingerprintCorpusID string `json:"fingerprint_corpus_id"`
}

// Current returns process provenance.
func Current() Info {
	return Info{
		Name:                "pingpp",
		Version:             Version,
		Commit:              Commit,
		BuildDate:           Date,
		GoVersion:           runtime.Version(),
		FingerprintCorpusID: FingerprintCorpusID,
	}
}
