# ping++

Evidence-first adaptive network fingerprinting engine. ping++ discovers
what is on a host, collects protocol observations, and infers products from
data-driven fingerprint rules. It does not perform vulnerability discovery.

Production execution:

```text
cmd/pingpp → internal/cli → pkg/runner.ScanRun → pkg/scan.Session → pkg/engine
```

Sirius consumes ping++ only through `integration/appscanner`. That adapter
translates Engine results into the existing host/inventory shape. ping++ does
not own Sirius UI, auth, tRPC, or persistence.

## Install

```bash
go install github.com/SiriusScan/ping++/cmd/pingpp@latest
```

From source:

```bash
git clone https://github.com/SiriusScan/ping++
cd ping++
go build -o pingpp ./cmd/pingpp
```

## CLI

```bash
pingpp version
pingpp collectors
pingpp profiles
pingpp info

pingpp scan --profile quick --no-icmp -t 192.0.2.1 --format jsonl
pingpp scan --profile default --tcp-ports 80,443 -t example.com
pingpp scan --skip-discovery --tcp-ports none --udp-ports none -l targets.txt
```

Targets are IPv4, IPv6, hostname, or CIDR. URLs and `host:port` are rejected.
`--profile full` enumerates TCP 1–65535 and is not a default.

Formats: `text` (default), `json`, `jsonl` (`pingpp.scan/v1`).

`-probes` from the legacy runner is not accepted. Use profiles, port
selections, and `--no-icmp` / `--skip-discovery`.

## Invariants

- Ports are priors, never protocol identity.
- Collectors return observations; fingerprint rules infer products.
- Protocol detection is port-agnostic. Unknown is valid.
- All A/AAAA addresses are considered; evidence is attributed to the address
  that was actually observed.
- HTTP connects to the selected IP while Host and TLS SNI use the logical
  hostname. `example.com` and `www.example.com` are different hosts.
- Cancellation records a terminal disposition for every scheduled task.
- Host-wide transport concurrency is `MaxConcurrentPerHost` around real I/O.

## Sirius adapter

```go
import "github.com/SiriusScan/ping++/integration/appscanner"

strategy := appscanner.NewStrategy() // Engine/Session path
result, err := strategy.Fingerprint("192.168.1.100")
```

`ProbeTypes` and `DisableICMP` map into `scan.Config` / `engine.Options`.
The result `Asset` map is `output.ToSiriusHost`. `UseLegacyRunner` is a
temporary rollback flag and is not the supported path.

## Architecture

See [docs/architecture.md](docs/architecture.md). Collectors produce facts.
Fingerprints infer products. The planner schedules. `scan.Session` owns one
prepared runtime. Runner V2 multiplexes targets. The Sirius adapter translates
only.

## Tests

```bash
go test ./...
go test -race ./pkg/engine ./pkg/transport ./pkg/protocol/... ./pkg/scan ./pkg/runner ./pkg/model ./pkg/output ./integration/appscanner
go vet ./...
```

Fingerprint corpora (YAML, Recog XML, Wappalyzer JSON subset) are embedded in
the binary. Third-party notices are in [NOTICE](NOTICE).

## License

MIT — see [LICENSE](LICENSE) if present in this tree; otherwise the module
license in `go.mod` / repository metadata.
