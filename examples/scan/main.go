// Full-pipeline scanner: discovery → enumerate → classify → fingerprint.
//
//	go run ./examples/scan shimcounty.com
//	go run ./examples/scan -profile quick shimcounty.com
//	go run ./examples/scan -json -profile default shimcounty.com
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/fingerprint"
	"github.com/SiriusScan/ping++/pkg/model"
	"github.com/SiriusScan/ping++/pkg/output"
	"github.com/SiriusScan/ping++/pkg/scan"
)

func main() {
	profileName := flag.String("profile", "default", "scan profile: quick, default, or deep")
	asJSON := flag.Bool("json", false, "print canonical asset JSON")
	timeout := flag.Duration("timeout", 4*time.Minute, "overall scan deadline")
	flag.Parse()

	target := "shimcounty.com"
	if flag.NArg() > 0 {
		target = flag.Arg(0)
	}

	var profile engine.ProfileName
	switch strings.ToLower(*profileName) {
	case "quick":
		profile = engine.ProfileQuick
	case "deep":
		profile = engine.ProfileDeep
	default:
		profile = engine.ProfileDefault
	}

	eng, err := engine.NewEngine(engine.Options{
		Profile:       profile,
		RatePerSecond: 200,
		Registry:      scan.NewRegistry(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "engine: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	fmt.Fprintf(os.Stderr, "scanning %s (profile=%s)\n", target, profile)
	res, err := eng.ScanTarget(ctx, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan: %v\n", err)
		os.Exit(1)
	}

	fp := fingerprint.NewEngine()
	_ = fp.LoadBuiltinPacks(fingerprint.RepoFingerprintsRoot())
	claims := fp.Match(res.Asset.Observations)
	claims = append(claims, fingerprint.FuseOS(claims)...)
	for _, c := range claims {
		res.Asset.AddClaim(c)
	}

	alive := res.State.Reachability.State == model.ReachabilityConfirmed ||
		res.State.Reachability.State == model.ReachabilityProbable

	if *asJSON {
		data, err := json.MarshalIndent(res.Asset, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "json: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
		return
	}

	printReport(target, profile, res, alive)
}

func printReport(input string, profile engine.ProfileName, res *engine.ScanResult, alive bool) {
	legacy := output.ToLegacy(res.Asset, alive)
	fmt.Printf("target:        %s\n", input)
	fmt.Printf("profile:       %s\n", profile)
	fmt.Printf("asset:         %s\n", res.Asset.ID)
	if len(res.Asset.Hostnames) > 0 {
		fmt.Printf("hostname:      %s\n", strings.Join(res.Asset.Hostnames, ", "))
	}
	if len(res.Asset.Addresses) > 0 {
		fmt.Printf("address:       %s\n", res.Asset.Addresses[0].IP)
	}
	fmt.Printf("alive:         %t\n", alive)
	fmt.Printf("reachability:  %s (%s)\n", res.State.Reachability.State, strings.Join(res.State.Reachability.Reasons, ", "))
	fmt.Printf("os:            %s", legacy.OSFamily)
	if legacy.OSVersion != "" {
		fmt.Printf(" %s", legacy.OSVersion)
	}
	if legacy.OSConfidence > 0 {
		fmt.Printf(" (%.0f%%)", legacy.OSConfidence*100)
	}
	fmt.Println()
	fmt.Printf("open ports:    %v\n", legacy.OpenPorts)
	if legacy.HTTPServer != "" {
		fmt.Printf("http server:   %s\n", legacy.HTTPServer)
	}
	if legacy.SSHBanner != "" {
		fmt.Printf("ssh banner:    %s\n", legacy.SSHBanner)
	}
	fmt.Printf("probes used:   %d / %d\n", res.State.Budget.ProbesUsed, res.State.Budget.MaxProbesPerHost)
	fmt.Printf("observations:  %d\n", len(res.Asset.Observations))
	fmt.Printf("claims:        %d\n", len(res.Asset.Claims))

	fmt.Println("\nendpoints:")
	for _, ep := range res.Asset.Endpoints {
		if ep.State != model.EndpointOpen {
			continue
		}
		fmt.Printf("  %s/%d %s\n", ep.Transport, ep.Port, ep.State)
	}

	if len(res.Asset.Claims) > 0 {
		fmt.Println("\nclaims:")
		for _, c := range res.Asset.Claims {
			fmt.Printf("  %-12s %-16s %-20s score=%.0f %s\n", c.Kind, c.Family, firstNonEmpty(c.Product, c.Value), c.Score, c.Confidence)
		}
	}

	fmt.Println("\nobservations:")
	for _, o := range res.Asset.Observations {
		if o.ObservationType == model.ObservationTCPEndpoint {
			var p model.TCPEndpointObservation
			_ = o.DecodePayload(&p)
			if p.State != model.EndpointOpen {
				continue
			}
		}
		port := 0
		if o.Endpoint != nil {
			port = int(o.Endpoint.Port)
		}
		err := ""
		if o.Error != "" {
			err = " err=" + o.Error
		}
		fmt.Printf("  %-16s port=%-5d %s%s\n", o.ObservationType, port, o.ProbeID, err)
		printObservationDetail(o)
	}
}

func printObservationDetail(o model.ObservationRecord) {
	switch o.ObservationType {
	case model.ObservationHTTP:
		var p model.HTTPObservation
		_ = o.DecodePayload(&p)
		if p.StatusCode != 0 {
			fmt.Printf("    status=%d server=%q title=%q\n", p.StatusCode, p.Server, p.Title)
		}
	case model.ObservationTLS:
		var p model.TLSObservation
		_ = o.DecodePayload(&p)
		if len(p.Certificates) > 0 {
			c := p.Certificates[0]
			fmt.Printf("    cn=%q issuer=%q sans=%v\n", c.SubjectCN, c.IssuerCN, c.SANs)
		}
	case model.ObservationSSH:
		var p model.SSHObservation
		_ = o.DecodePayload(&p)
		if p.Banner != "" {
			fmt.Printf("    banner=%q\n", p.Banner)
		}
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
