package fingerprints

import "embed"

// FS is the built-in fingerprint corpus shipped with the binary.
//
//go:embed http/*.yaml ssh/*.yaml devices/*.yaml os/*.yaml wappalyzer/technologies.json recog/*.xml
var FS embed.FS
