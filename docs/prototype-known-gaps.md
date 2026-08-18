# Ping++ rebuild contract

Living status for `cursor/ping-correctness-and-hygiene-d7fc`. Update this file
**in the same commit as each R-stage** so it never describes a previous tree.

This is not a production-readiness claim and not a historical freeze snapshot.

## How to update

After each R-stage commit, edit that stage in place:

```text
R<n> <title>
Status: COMPLETE | PARTIAL | NOT STARTED
Commit: <short sha> <subject>
Acceptance tests:
- <TestName> — what it actually proves
Known debt:
- <remaining semantic hole, or "none">
```

Do not leave completed work described as missing. Do not mark COMPLETE while
listed known debt still violates the stage's acceptance bar.

## Freeze policy

- **Do not reset to `master`.**
- **Do not remove protocol coverage** merely because collectors are incomplete.
- **Do not add more protocols** until classification, planner, fusion, and
  Engine composition are aligned.
- Ports are priors, never identity.
- Product fingerprints stay outside collectors.
- Protocol-specific data belongs in typed observation payloads, not asset fields.
- Unknown is valid. Receiving bytes is not a protocol match.

Reviewed prototype commit: `bfef5cb`.

## Current head

This commit (`12526b0`) — ProbeTypes compatibility, stage-fair multi-address scans,
endpoint execution completeness, C13 typed exit codes, and responsive
unclassified findings in default text.

Canonical path:

```text
resolve → discover → enumerate → plan → collect → fingerprint → re-plan → enrich → Asset
```

R11–R14 are no longer “framework done.” The acceptance items below now have collector-level and fixture tests.

---

## R1 Freeze / CI

Status: COMPLETE

Commit: `07d45cd` freeze chassis, CI gate, this document; `db41113` run CI on `cursor/**`

Acceptance tests:
- CI workflow `.github/workflows/ci.yml` — `go test -race`, `go vet`, golangci-lint v2.12.2
- `go test ./...` must pass on the branch

Known debt:
- none for the freeze bar

---

## R2 Subject-aware fusion

Status: COMPLETE

Commit: `c39c565` subject-aware claim fusion with version and OS composition

Acceptance tests:
- `TestFuseDoesNotMergeAcrossEndpoints` — nginx on `:80` and `:443` stay distinct
- `TestFuseKeepsConflictingVersionsSeparate` — `1.22` vs `1.24` do not collapse
- `TestFuseCombinesIndependentSignalsOnSameEndpoint` — independent groups combine
- `TestComposeDropsRawWeakLinuxAfterNormalization` — weak Linux does not leak
- `TestCorrelationGroupDoesNotInflate` — same HTTP response does not score-inflate

Known debt:
- none for the fusion bar

---

## R3 Engine owns fingerprinting

Status: COMPLETE

Commit: `73491a3` Engine owns fingerprinting, artifacts, and final claims

Acceptance tests:
- `TestEngineOwnsFingerprints` — `ScanTarget` attaches matcher claims
- `TestNoProductClaimsInCollectorOutput` — collectors do not emit product claims

Known debt:
- Sirius adapter still has a legacy runner path behind `UseLegacyRunner` (R16)

---

## R4 Adaptive planner

Status: COMPLETE

Commit: `b9ac12b` iterative planner loop; `fd633e4` plan from `ProbeOutcome`, not Completeness

Acceptance tests:
- `TestPlannerTLSSuccessReplansHTTP` — TLS Success schedules HTTP with `tls=1`
- `TestPlannerSSHSuccessStopsIrrelevantCollectors` — exclusive match stops spray
- `TestPlannerNoMatchIsNotRetried` — NoMatch rules the protocol out
- `TestPlannerTerminatesDeterministically` — idle after a finished scan
- `TestPlannerSchedulesEnrichmentForWeakHTTP` — weak product evidence enriches once

Known debt:
- none for the adaptive-planner bar. Port-prior fallback is R6/R7.

---

## R5 Metering / scheduler / budgets

Status: COMPLETE

Commit: `a244346` count network ops and enumerate TCP concurrently; `2beeda5` meter HTTP/DNS/SNMP and Read/Write bytes

Acceptance tests:
- `TestMeterCountsDialsAndRespectsBudget` — `MaxNetworkOps` stops extra dials
- `TestMeterCountsConnBytes` — connection Read/Write increment byte counters
- `TestWrapUDPKeepsPacketConn` — UDP wrappers stay datagram sockets (DNS framing)
- `TestHTTPCollectorUsesMeteredTransport` / `TestHTTPCollectorRespectsNetworkBudget`
- `TestDNSCollectorUsesMeteredTransport`
- `TestSNMPCollectorCountsDial`
- `TestEnumerateStopsAtNetworkBudget` / `TestNetworkBudgetStopsLaterCollectors`
- `TestMeterRespectsByteBudget` — `MaxBytesPerHost` / meter `MaxBytes` blocks further dials

Known debt:
- SNMP still self-dials inside `gosnmp.Connect`; the scan meter reserves the op with `CountDial` and wraps the resulting conn for bytes. The library socket is not `DialUDP`.
- ICMP discovery uses `CountDial`, not wrapped pinger I/O, so ICMP payload bytes are not counted.
- Legacy `pkg/probes/*` still dial on their own (not on the Engine path).
- Unregistered `collect.tcpstack` still uses `net.Dialer`.
- SMB now dials through the scan meter via `ProxyDialer`; the go-smb library still owns the protocol framing.

---

## R6 Registry priors + banner

Status: COMPLETE

Commit: `49d9650` derive collector priors from registry metadata; `2beeda5` continue into general fallback after port priors miss

Acceptance tests:
- `TestPlannerPortPriorsNotIdentity` — open port 22 does not schedule HTTP as a prior
- `TestPlannerUnknownPortUsesBannerThenTLS` — unknown TCP starts banner → TLS
- `TestPlannerFallbackAfterPortPriorsNoMatch` — HTTP on 22 after SSH NoMatch
- `TestPlannerRedisOnMySQLPortAfterPriorNoMatch` — Redis on 3306 after MySQL NoMatch
- `TestBannerReadsBytesWithoutProtocolClaim` — banner is not exclusive
- `TestNewRegistryHasSSHAndSMB` — production registry includes `collect.banner`, excludes `collect.tcpstack`

Known debt:
- none for the prior/fallback bar

---

## R7 Protocol claims + classification

Status: COMPLETE

Commit: `903b24a` emit protocol claims from `ResultCollector` outcomes; `2beeda5` fallback sequence

Acceptance tests:
- `TestProtocolConfirmPromotesEndpointOpen` — Success, not Completeness, opens the endpoint
- `TestPlannerTLSSuccessReplansHTTP` — HTTP scheme follows TLS, not port 443
- `TestClassificationPassesHostnameTarget` — hostname survives into collectors for SNI/Host

Known debt:
- Unregistered `collect.tcpstack` is still `Run()`-only and is not on the production registry.

---

## R8 UDP pipeline + DNS

Status: COMPLETE

Commit: `41bd3ea` enumerate UDP and speak DNS to the target; `2beeda5` silence is unknown, still classified

Acceptance tests:
- `TestEnumerateUDPReportsResponsivePort` — a real UDP reply is responsive
- `TestEnumerateUDPSilenceIsUnknown` / `TestClassifyUDPSilenceIsUnknown` — timeout is unknown, still emitted
- `TestPlannerUnknownUDPStillSchedulesProtocolCollectors` — unknown UDP/53 schedules `collect.dns`
- `TestPlannerClosedUDPIsNotClassified` — ICMP port-unreachable / closed is excluded
- `TestDNSCollectorSpeaksDNSNotOSResolver` — query hits the endpoint, not `net.LookupHost`
- `TestDNSCollectorNoMatchOnGarbage` — echoed garbage is not DNS

Known debt:
- enumeration still sends a one-byte datagram to surface ICMP unreachable. That probe must not be required for scheduling (it is not). NTP/IKE/SSDP have no protocol collectors yet — do not add them until later.

---

## R9 SNMP

Status: COMPLETE

Commit: `da8308d` rebuild SNMP collection on gosnmp

Acceptance tests:
- `TestSNMPObservationOmitsCommunity` — community never appears in JSON
- `TestSNMPNoMatchOnGarbageUDP` — echoed garbage is not SNMP

Known debt:
- same metering note as R5: `gosnmp` owns the dial

---

## R10 HTTP / TLS / artifacts

Status: COMPLETE

Commit: `4557bd6` HTTP scheme, redirects, body artifacts, favicon hashes; this commit raises the body cap to 256 KiB

Acceptance tests:
- `TestHTTPSameHostRedirectAndCrossHostStop` — same-host follows; cross-host records `Location` and stops
- `TestHTTPBodyArtifactAndTruncation` — truncated flag + artifact id (270 KiB body vs 256 KiB cap)
- `TestHTTPFaviconHashes` — SHA-256 (and MMH3) on favicon bytes
- `TestTLSCollectorCapturesCert` / `TestTLSCollectorNoMatchOnPlaintext`

Known debt:
- extra same-host URLs beyond favicon/robots are enrichment (`collect.http.enrich`), not the default GET
- `www.` and apex hostnames are treated as the same host for redirect following; a dedicated canonical-host fixture is not in testdata

---

## R11 Recog / Wappalyzer

Status: COMPLETE for bundled-corpus semantics (not the entire Recog git tree)

Commit: `d6dd7c3` adapters; `9403a4d` corpus import; this commit preserves Recog param structure

R11a adapter support: COMPLETE  
R11b real corpus import / coverage: COMPLETE at bundled scale, with structured claims

Acceptance tests:
- `TestNativeRecogXMLOpenSSH` / `TestRecogParamValueAttribute` — Recog XML, including `value=""` attributes
- `TestRecogSeparatesServiceAndOSWithCaptures` — `service.*` vs `os.*` vs `hw.*`; `pos=N` versions; CPE `{service.version}`
- `TestRecogClaimsKeepEndpointSubject` / `TestRecogClaimsFromDistinctPortsDoNotFuse` — `:22` and `:2222` stay distinct
- `TestRecogHTTPHeaderServerMapping` — `http_header.server` → HTTP `server`
- `TestRecogSkipsNonRE2` / `TestRecogMatchesSSHSoftwareIdent` — skip PCRE; match `SSH-x.x-` ident
- `TestWappalyzerJSONNginx` — technologies.json Server header
- `TestBuiltinCorpusScale` — Recog SSH/HTTP XML are hundreds of fingerprints; Wappalyzer ≥ 20 techs

Known debt:
- Bundled Recog is two XML databases (`ssh_banners.xml` ~153 prints, `http_servers.xml` ~458 prints), not the full Rapid7 Recog tree.
- Individual Recog regexes that are not RE2 are skipped (fail closed only on XML/JSON parse errors).
- `NativeWebTech` remains a test fixture only.
- Wappalyzer JSON is a curated non-GPL subset, not the GPL Wappalyzer project.

---

## R12 Text protocols

Status: COMPLETE for FTP/SMTP native replies, implicit TLS, and explicit STARTTLS

Commit: `ef6bed4` shared helper; `9403a4d` pos/neg tests; this commit upgrades SMTP/IMAP/POP3 after a protocol match

Acceptance tests:
- `TestFTPAcceptsFTP` / `TestFTPAcceptsGenericGreetingWithFEAT` / `TestFTPRejectsGenericGreetingWithoutFEAT`
- `TestFTPRejectsSMTP` / `TestFTPRejectsHTTPLookalike`
- `TestSMTPAcceptsSMTP` / `TestSMTPAcceptsGenericGreetingWithEHLO` / `TestSMTPRejectsFTP`
- `TestSMTPStartTLSUpgrade` / `TestSMTPStartTLSRejectKeepsPlaintextMatch` / `TestSMTPSkipsStartTLSWhenNotAdvertised`
- `TestPOP3AcceptsOK` / `TestIMAPAcceptsGreeting` plus advertised 995/993
- `TestIMAPStartTLSUpgrade` / `TestPOP3STLSUpgrade` plus reject-keeps-plaintext
- `TestPlannerTLSSuccessReplansIMAPOn993` — TLS success schedules IMAP with `tls=1`
- `TestUseTLSImplicitPorts` — 465/993/995 and Extra `tls=1`
- `TestUpgradeTLSDoesNotCountDial` — STARTTLS handshake is not a second network op

Known debt:
- Telnet match requires IAC, login/password, or the word telnet — not a full option parser.

---

## R13 DB / middleware

Status: COMPLETE for in-tree DB collectors plus MQTT/AMQP/VNC/SOCKS ResultCollector conversion

Commit: `ef6bed4` MySQL/Postgres; `9403a4d` Mongo/MSSQL/Memcached; this commit converts MQTT/AMQP/VNC/SOCKS to `RunResult`

Acceptance tests:
- `TestPostgresMatchSN` / `TestPostgresRejectsHTTP`
- `TestMySQLHandshakeSuccess` / `TestMySQLRejectsShortGarbage`
- `TestMongoOPReplySuccess` / `TestMongoRejectsHTTPLookalike` / `TestMongoRejectsWrongOpcode`
- `TestMSSQLPreloginVersionSuccess` / `TestMSSQLRejectsHTTPLookalike` / `TestMSSQLRejectsResponseWithoutVersion`
- `TestMemcachedAcceptsVersion` / `TestMemcachedRejectsHTTPLookalike` / `TestMemcachedRejectsRedisPong`
- `TestRedisAcceptsPong` / `TestRedisRejectsHTTPLookalike` / `TestRedisRejectsMemcachedVersion`
- `TestMQTTAcceptsCONNACK` / `TestMQTTRejectsHTTPLookalike`
- `TestAMQPAcceptsHeader` / `TestAMQPRejectsHTTPLookalike`
- `TestVNCAcceptsRFB` / `TestVNCRejectsHTTPLookalike`
- `TestSOCKSAcceptsMethodResponse` / `TestSOCKSRejectsHTTPLookalike`

Known debt:
- Mongo success is framed `OP_REPLY`/`OP_MSG`, not a decoded isMaster document.

---

## R14 LDAP / RDP / SSH / SMB

Status: COMPLETE for the stated acceptance items, with live SMB vendor tests still out of process

Commit: this commit — LDAPS/RootDSE, X.224/RDP negotiation, SSH ignore/debug skip, SMB lookalike + auth evidence

Acceptance tests:
- `TestLDAPRootDSEAttributes` — vendorName, namingContexts, dnsHostName, SASL, versions
- `TestLDAPRootDSEFragmented` — BER tag+length then `ReadFull` of the envelope
- `TestLDAPRejectsBareBERSequence` — first BER byte `0x30` is not a match
- `TestLDAPSOnTLS` — Extra `tls=1` (port 636 uses the same DialTLS path)
- `TestRDPNegotiationHybrid` / `TestRDPNegotiationSSL` / `TestRDPRejectsTPKTWithoutConfirm`
- `TestSSHFramedKEXINITAfterIgnore` — IGNORE then length-prefixed KEXINIT
- `TestSMBRejectsHTTPLookalike` / `TestSMBAuthDeniedIsProtocolEvidence`

Known debt:
- Live Windows vs Samba session fixtures are not in this tree (would need a real SMB endpoint). Auth-denied and signing-required are classified from library errors.
- LDAP still does not implement a full LDAP client; it decodes RootDSE attributes from SearchResultEntry.

---

## R15 Fingerprint packs + embed + R11b corpus

Status: COMPLETE

Commit: this commit — `go:embed`, KnownFields fail-closed, title-only recalibration, fixture corpus, Recog/Wappalyzer import, HTTP 256 KiB

Acceptance tests:
- `TestBuiltinCorpusScale` — embed FS has real Recog/Wappalyzer scale
- `TestLoadYAMLUnknownFieldFailsClosed` — unknown YAML fields fail closed
- `TestFixtureCorpus` — `testdata/fingerprints/<product>/{positive,negative}/`
- `TestStrongExactYAMLRulesHaveNegativeFixtures` — strong/exact YAML claims need a negative tied to rule id or product+observation type (vendor-only is not enough)
- `TestHTTPBodyArtifactAndTruncation` — 256 KiB cap
- `TestHTTPApplicationPack` — title-only Grafana/Jenkins still match (now hint); server headers remain strong/exact

Known debt:
- Title-only rules are hints; distinctive favicon+title combined rules are still sparse.
- Recog import is two databases, not every Recog XML file upstream.

---

## R16 Sirius adapter / ScanOptions

Status: COMPLETE for Engine-path option semantics

Commit: `9403a4d` ScanOptions; this commit maps `DisableICMP` → `SkipICMP` and honors `ProbeTypes`

Acceptance tests:
- `TestScanOptionsWrapsEngineOptions` — one options type wrapping `engine.Options`; `SkipICMP` does not imply `SkipDiscovery`; `ProbeTypes` is carried
- `TestSkipICMPKeepsTCPDiscovery` — ICMP off leaves `discovery.tcp`
- `TestProbeTypesFilterCollectors` — `icmp,tcp` does not enable `collect.ssh`/`collect.http`

Known debt:
- `fingerprintLegacyRunner` remains behind `UseLegacyRunner` only.
- `runner.Options` / `engine.Options` / Profile remain separate vocabularies.
- Sirius `ProbeTypes` stay a private `scan.Config` compatibility field; they are
  not part of the public Config API. Profiles are the supported selector.

---

## R17 IPv6 / multi-address

Status: COMPLETE for shared logical-scan budget, merged protocol state, and
stage-fair multi-address execution

Commit: `12526b0` D0/D1 across all addresses, then round-robin classify/enrich;
logical `State.AssetID` is no longer overwritten by per-IP IDs

Acceptance tests:
- `TestScanResolvedAllAddresses` — two resolved IPs both appear; hostname preserved; per-address complete keys
- `TestScanResolvedSharesNetworkBudget` — two addresses share one `MaxNetworkOps`
- `TestScanResolvedStageFairnessAndLogicalAssetID` — both addresses get enumeration before adaptive probes can exhaust the shared budget; `AssetID` stays `asset:<hostname>`
- `TestClassificationPassesHostnameTarget` — hostname survives into collectors for SNI/Host
- `TestConfigFromScanOptionsPreservesProbeTypes` — Sirius `icmp,tcp` still filters protocol collectors through `scan.Config`

Known debt:
- HTTP still dials the resolved IP in the request URL and rewrites the observation hostname (redirect/SNI follow-up).
- True target-wide `MaxConcurrentPerHost` at transport I/O is still scheduler-task scoped.
- IPv6 filtered vs budget-starved vs no-route still needs a dedicated matrix beyond the fairness unit test.

---

## R18 Metrics, unknowns, hardening

Status: COMPLETE for STARTTLS-era remaining R18 bars (sink + corpus timings); packaging NOTICE and R5 byte metering stay debt

Commit: `9403a4d` runtime counters; prior commit repaired metric semantics; this commit adds a JSONL unmatched-banner sink and a builtin-corpus timing suite

Acceptance tests:
- `TestRuntimeCounters` — collectors, protocol matches (via `RecordProtocolMatch`), timeouts, bytes, unknown endpoints, claim tiers, unmatched dump
- `TestBannerSinkWritesJSONL` / `TestUnmatchedBannerFileSink` — durable file sink plus Engine close
- `TestEvalPrecisionAtTier` — `ExactCorrect`/`StrongCorrect` live in eval tooling, not `metrics.Counters`
- `TestCollectorPanicIsInternalError` — collector panic becomes `internal_error` and does not abort the scan
- `TestMeterRespectsByteBudget` — `MaxBytes` blocks further dials
- `BenchmarkFuseIndependentSignals` — fusion microbenchmark exists
- `TestBuiltinCorpusMatchBudget` / `BenchmarkBuiltinCorpusMatch` / `BenchmarkLoadBuiltinPacks` — live Recog/Wappalyzer/YAML corpus timings, claim counts must not collapse

Known debt:
- Embedded Recog/Wappalyzer license notices live under `fingerprints/`; a packaging NOTICE aggregation is not automated.
- SNMP/ICMP payload bytes remain incompletely metered (R5).

---

## Production runner (separate track)

Engine R1–R18 stays the scanning intelligence. Production `cmd/pingpp` is a
thin CLI over Runner V2 (`pkg/runner.ScanRun`) → `scan.Session` → engine.
C9–C12 landed on this branch (`scan`, `version`, text/json/jsonl). Do not
grow legacy `pkg/runner.Result`. C13 exit-code/run-error work landed with
this commit; C14–C16 (introspection commands, README rewrite, full-profile
stress) remain.

Endpoint `Execution` distinguishes attempted vs `not_attempted_budget` /
`not_attempted_cancelled` / `timed_out` so a budget stop is not network
`unknown`. Default text now prints responsive unclassified endpoints.

---

## Standing rules

- After port-associated collectors return NoMatch, continue the general fallback sequence.
- Exclusive protocol Success still stops irrelevant collectors.
- UDP silence is unknown. ICMP port-unreachable may mark closed.
- Network budgets must describe real activity (dials **and** payload bytes).
- Fingerprint pack loading may never silently ignore malformed built-ins.
- Runtime built-in fingerprints must ship with the binary.
- Do not build complete protocol clients.

## CI

```text
go test ./...
go test -race ./...
go vet ./...
golangci-lint run ./...   # v2.12.2
```
