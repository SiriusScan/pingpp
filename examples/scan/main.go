// Enumeration scan example: resolve → discover → enumerate → classify → fingerprint.
//
// Default stdout is a complete diagnostic dump (every endpoint, observation
// payload, and claim — nothing truncated). Use -json when another tool
// should consume the same document.
//
//	go run ./examples/scan n8n.example.com
//	go run ./examples/scan -json -o scan.json n8n.example.com
//	go run ./examples/scan -seed example.com
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/fingerprint"
	"github.com/SiriusScan/ping++/pkg/scan"
)

func main() {
	var targets multiFlag
	profileName := flag.String("profile", "default", "scan profile: quick, default, or deep")
	seed := flag.Bool("seed", false, "also try apex and www for a registrable domain")
	asJSON := flag.Bool("json", false, "print the full scan document as JSON")
	outPath := flag.String("o", "", "write output to a file (default stdout)")
	timeout := flag.Duration("timeout", 4*time.Minute, "overall scan deadline")
	rate := flag.Int("rate", 200, "max collector tasks per second")
	flag.Var(&targets, "t", "target hostname, IP, or URL (repeatable)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: go run ./examples/scan [flags] <target> [<target>...]\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	for _, arg := range flag.Args() {
		targets = append(targets, arg)
	}
	if len(targets) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	profile, err := parseProfile(*profileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(2)
	}

	hosts := expandTargets(targets, *seed)
	if len(hosts) == 0 {
		fmt.Fprintf(os.Stderr, "no usable hosts in %v\n", []string(targets))
		os.Exit(2)
	}

	eng, err := engine.NewEngine(engine.Options{
		Profile:       profile,
		RatePerSecond: *rate,
		Registry:      scan.NewRegistry(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "engine: %v\n", err)
		os.Exit(1)
	}

	fp := fingerprint.NewEngine()
	_ = fp.LoadBuiltinPacks(fingerprint.RepoFingerprintsRoot())

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	fmt.Fprintf(os.Stderr, "enumerating %s (profile=%s)\n", strings.Join(hosts, ", "), profile)

	var docs []ScanDocument
	for _, host := range hosts {
		started := time.Now()
		fmt.Fprintf(os.Stderr, "  %s\n", host)
		res, err := eng.ScanTarget(ctx, host)
		if err != nil {
			fmt.Fprintf(os.Stderr, "    skip: %v\n", err)
			continue
		}
		claims := fp.Match(res.Asset.Observations)
		claims = append(claims, fingerprint.FuseOS(claims)...)
		for _, c := range claims {
			res.Asset.AddClaim(c)
		}
		docs = append(docs, buildDocument(host, profile, res, time.Since(started)))
	}
	if len(docs) == 0 {
		fmt.Fprintf(os.Stderr, "no resolvable targets\n")
		os.Exit(1)
	}

	out := io.Writer(os.Stdout)
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", *outPath, err)
			os.Exit(1)
		}
		defer func() { _ = f.Close() }()
		out = f
	}

	if *asJSON {
		if err := writeJSON(out, docs); err != nil {
			fmt.Fprintf(os.Stderr, "json: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := writeText(out, docs); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}
}

func parseProfile(name string) (engine.ProfileName, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "default":
		return engine.ProfileDefault, nil
	case "quick":
		return engine.ProfileQuick, nil
	case "deep":
		return engine.ProfileDeep, nil
	default:
		return "", fmt.Errorf("unknown profile %q (quick, default, deep)", name)
	}
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	*m = append(*m, v)
	return nil
}
