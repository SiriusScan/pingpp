# ping++ architecture

Ownership boundaries for production scans. This is not a Sirius application
design.

```text
collectors → observations/facts
fingerprints → product/OS claims
planner → scheduled collector tasks
scan.Session → prepared runtime (registry, corpus, artifacts, global rate)
pkg/engine → one logical target (all A/AAAA, host-wide I/O limiter)
pkg/runner.ScanRun → many targets, host concurrency, sinks, exit status
internal/cli / cmd/pingpp → flags, signals, formats
integration/appscanner → Sirius inventory translation only
```

## Collectors

Collectors live under `pkg/discovery/*` and `pkg/protocol/*`. They dial,
read banners/handshakes/headers, and emit typed observation payloads. They
do not infer products and do not embed fingerprint regexes.

Network I/O goes through `pkg/transport` (`DialTCP` / `DialUDP` / `DialTLS` /
`CountDial`). That layer meters dials and bytes, applies the run-wide rate
limiter, and acquires the per-logical-target host-concurrency permit.

## Fingerprints

`pkg/fingerprint` matches data-driven YAML / Recog / Wappalyzer rules against
observations. A normalization pass canonicalizes aliases, versions, and
whitespace for matching only. Raw evidence on the asset is unchanged.
Contradictory products remain visible. Unknown is a valid result.

## Planner and Engine

`pkg/engine` owns one hostname or IP: resolve every A/AAAA, discover,
enumerate, plan, collect, fingerprint, re-plan, enrich. Multi-address scans
share one logical budget and one host-concurrency limiter. Endpoint `State`
is what the network showed. Endpoint `Execution` is whether the scan asked
(monotonic: attempted > timed_out > not-attempted reasons).

## Session and Runner

`pkg/scan.Session` loads the registry and fingerprint corpus once. Each
`Session.Scan` builds a per-target Engine that shares those resources.

`pkg/runner.ScanRun` streams targets, bounds cross-host concurrency, writes
`pingpp.scan/v1` via `pkg/output`, and maps cancellation/timeouts to exit
codes. It does not contain a protocol switch.

The legacy `pkg/runner` probe loop is rollback-only (`UseLegacyRunner` on the
Sirius adapter). Do not add features there.

## Sirius

`integration/appscanner` maps `ProbeTypes` / `DisableICMP` into Engine options
and maps the resulting `Asset` through `output.ToSiriusHost`. Missing Sirius
contracts are reported, not invented in ping++.
