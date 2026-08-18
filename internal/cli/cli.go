package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/SiriusScan/ping++/pkg/buildinfo"
	"github.com/SiriusScan/ping++/pkg/engine"
	"github.com/SiriusScan/ping++/pkg/output"
	"github.com/SiriusScan/ping++/pkg/runner"
	"github.com/SiriusScan/ping++/pkg/scan"
)

const usage = `pingpp — adaptive host scanner

Usage:
  pingpp scan [flags] [target ...]
  pingpp version
  pingpp collectors
  pingpp profiles
  pingpp info

Targets are IPv4, IPv6, hostname, or CIDR. URLs and host:port are rejected.

Common flags:
  -t, --target              target (repeatable)
  -l, --list                file of targets (one per line)
      --stdin               read targets from stdin
      --profile             quick|default|deep|full (default default)
      --no-icmp             disable ICMP discovery only
      --skip-discovery      skip the discovery stage
      --tcp-ports           profile|none|list (e.g. 80,443)
      --udp-ports           profile|none|list
      --host-concurrency    max concurrent targets (default 50)
      --rate                max network ops per second
      --target-timeout      per-target deadline
      --run-timeout         whole-run deadline
      --fail-fast           stop after the first operational target failure
      --format              text|json|jsonl (default text)
  -v, --verbose             full diagnostic dump
  -o, --output              write results to a file
      --artifact-dir        persist artifacts on disk
      --unmatched-banners   append unmatched banners as JSONL
`

// Run is the process entrypoint. args should not include the program name.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version":
		return runVersion(args[1:], stdout, stderr)
	case "collectors":
		return runCollectors(stdout, stderr)
	case "profiles":
		return runProfiles(stdout, stderr)
	case "info":
		return runInfo(stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "scan":
		return runScan(args[1:], stdout, stderr)
	default:
		return runScan(args, stdout, stderr)
	}
}

func runVersion(_ []string, stdout, stderr io.Writer) int {
	info := buildinfo.Current()
	if _, err := fmt.Fprintf(stdout, "pingpp %s commit=%s corpus=%s %s\n", info.Version, info.Commit, info.FingerprintCorpusID, info.GoVersion); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	return 0
}

func runCollectors(stdout, stderr io.Writer) int {
	reg := scan.NewRegistry()
	for _, md := range reg.Metadata() {
		if _, err := fmt.Fprintf(stdout, "%s\tstage=%s\tprio=%d\tcost=%d\n", md.ID, md.Stage, md.Priority, md.Cost); err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return 1
		}
	}
	return 0
}

func runProfiles(stdout, stderr io.Writer) int {
	for _, name := range []engine.ProfileName{engine.ProfileQuick, engine.ProfileDefault, engine.ProfileDeep, engine.ProfileFull} {
		p := engine.ProfileFor(name)
		note := ""
		if name == engine.ProfileFull {
			note = " (not a default; requires C16 stress evidence)"
		}
		if _, err := fmt.Fprintf(stdout, "%s\ttcp=%d\tudp=%d\tmax_probes=%d%s\n", p.Name, len(p.TCPPorts), len(p.UDPPorts), p.Budget.MaxProbesPerHost, note); err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return 1
		}
	}
	return 0
}

func runInfo(stdout, stderr io.Writer) int {
	info := buildinfo.Current()
	if _, err := fmt.Fprintf(stdout, "name=%s version=%s commit=%s go=%s corpus=%s\n", info.Name, info.Version, info.Commit, info.GoVersion, info.FingerprintCorpusID); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	if _, err := fmt.Fprintf(stdout, "architecture=cmd/pingpp -> internal/cli -> pkg/runner.ScanRun -> pkg/scan.Session -> pkg/engine\n"); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	if _, err := fmt.Fprintf(stdout, "formats=text,json,jsonl\nprofiles=quick,default,deep,full\n"); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	return 0
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

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var targets multiFlag
	fs.Var(&targets, "t", "target (repeatable)")
	fs.Var(&targets, "target", "target (repeatable)")
	list := fs.String("l", "", "target file")
	fs.StringVar(list, "list", "", "target file")
	useStdin := fs.Bool("stdin", false, "read targets from stdin")
	profileName := fs.String("profile", "default", "quick|default|deep|full")
	noICMP := fs.Bool("no-icmp", false, "disable ICMP discovery")
	skipDiscovery := fs.Bool("skip-discovery", false, "skip discovery stage")
	tcpPorts := fs.String("tcp-ports", "profile", "profile|none|list")
	udpPorts := fs.String("udp-ports", "profile", "profile|none|list")
	hostConc := fs.Int("host-concurrency", 50, "max concurrent targets")
	rate := fs.Int("rate", 0, "max network ops per second")
	targetTimeout := fs.Duration("target-timeout", 0, "per-target deadline")
	runTimeout := fs.Duration("run-timeout", 0, "whole-run deadline")
	failFast := fs.Bool("fail-fast", false, "stop on first operational failure")
	format := fs.String("format", "text", "text|json|jsonl")
	verbose := fs.Bool("v", false, "verbose")
	fs.BoolVar(verbose, "verbose", false, "verbose")
	outPath := fs.String("o", "", "write results to a file")
	fs.StringVar(outPath, "output", "", "write results to a file")
	artifactDir := fs.String("artifact-dir", "", "persist artifacts")
	unmatched := fs.String("unmatched-banners", "", "unmatched banner JSONL path")
	strict := fs.Bool("strict-input", false, "malformed file lines are fatal")

	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stdout, usage) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	for _, a := range fs.Args() {
		targets = append(targets, a)
	}

	profile, err := parseProfile(*profileName)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	tcpSel, err := parsePortFlag(*tcpPorts)
	if err != nil {
		fmt.Fprintf(stderr, "tcp-ports: %v\n", err)
		return 2
	}
	udpSel, err := parsePortFlag(*udpPorts)
	if err != nil {
		fmt.Fprintf(stderr, "udp-ports: %v\n", err)
		return 2
	}
	switch strings.ToLower(*format) {
	case "text", "json", "jsonl":
	default:
		fmt.Fprintf(stderr, "unknown format %q\n", *format)
		return 2
	}

	srcOpts := []runner.SourceOption{runner.WithTargets(targets...), runner.WithStrictInput(*strict)}
	if *list != "" {
		srcOpts = append(srcOpts, runner.WithFile(*list))
	}
	if *useStdin {
		srcOpts = append(srcOpts, runner.WithStdin(os.Stdin))
	}
	src, err := runner.NewTargetSource(srcOpts...)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}

	cfg := scan.DefaultConfig()
	cfg.Profile.Name = profile
	cfg.Discovery.DisableICMP = *noICMP
	cfg.Discovery.SkipDiscovery = *skipDiscovery
	cfg.Ports.TCP = tcpSel
	cfg.Ports.UDP = udpSel
	cfg.Limits.HostConcurrency = *hostConc
	cfg.Limits.RatePerSecond = *rate
	cfg.Limits.TargetTimeout = *targetTimeout
	cfg.Artifacts.Dir = *artifactDir
	cfg.Unknowns.BannerFile = *unmatched

	session, err := scan.NewSession(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "session: %v\n", err)
		if errors.Is(err, scan.ErrInvalidConfig) {
			return 2
		}
		return 1
	}
	defer func() { _ = session.Close() }()

	out := stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintf(stderr, "output: %v\n", err)
			return 1
		}
		defer func() { _ = f.Close() }()
		out = f
	}

	sink := &output.Sink{W: out, Format: strings.ToLower(*format), Profile: string(profile), Verbose: *verbose}
	events := &stderrEvents{w: stderr}

	run, err := runner.NewScanRun(runner.ScanRunOptions{
		Scanner:         session,
		Targets:         src,
		HostConcurrency: *hostConc,
		FailFast:        *failFast,
		Sink:            sink,
		Events:          events,
	})
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *runTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *runTimeout)
		defer cancel()
	}

	summary, err := run.Run(ctx)
	if flushErr := sink.Flush(); flushErr != nil && err == nil {
		err = flushErr
	}
	fmt.Fprintf(stderr, "summary targets=%d completed=%d failed=%d cancelled=%d\n", summary.Targets, summary.Completed, summary.Failed, summary.Cancelled)
	return exitStatus(ctx, err, summary, stderr)
}

func exitStatus(ctx context.Context, err error, summary runner.Summary, stderr io.Writer) int {
	var runErr *runner.RunError
	if errors.As(err, &runErr) && runErr.Kind == runner.ErrKindInput {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	if errors.Is(err, scan.ErrInvalidConfig) {
		return 2
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		if err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
		}
		return 1
	}
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return 130
	}
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	if summary.Failed > 0 {
		return 1
	}
	return 0
}

type stderrEvents struct{ w io.Writer }

func (e *stderrEvents) Event(ev runner.Event) {
	if e == nil || e.w == nil {
		return
	}
	switch ev.Kind {
	case "target_started":
		fmt.Fprintf(e.w, "scanning %s\n", ev.Target.Input)
	case "target_failed":
		fmt.Fprintf(e.w, "  %s: %s\n", ev.Target.Input, ev.Message)
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
	case "full":
		return engine.ProfileFull, nil
	default:
		return "", fmt.Errorf("unknown profile %q (quick, default, deep, full)", name)
	}
}

func parsePortFlag(raw string) (scan.PortSelection, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" || raw == "profile" {
		return scan.PortSelection{}, nil
	}
	if raw == "none" {
		return scan.PortSelection{Override: true}, nil
	}
	var ports []uint16
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			var lo, hi int
			if _, err := fmt.Sscanf(part, "%d-%d", &lo, &hi); err != nil || lo <= 0 || hi <= 0 || hi > 65535 || lo > hi {
				return scan.PortSelection{}, fmt.Errorf("invalid range %q", part)
			}
			for p := lo; p <= hi; p++ {
				ports = append(ports, uint16(p))
			}
			continue
		}
		var n int
		if _, err := fmt.Sscanf(part, "%d", &n); err != nil || n <= 0 || n > 65535 {
			return scan.PortSelection{}, fmt.Errorf("invalid port %q", part)
		}
		ports = append(ports, uint16(n))
	}
	if len(ports) == 0 {
		return scan.PortSelection{}, fmt.Errorf("empty port list")
	}
	return scan.PortSelection{Override: true, Ports: ports}, nil
}
