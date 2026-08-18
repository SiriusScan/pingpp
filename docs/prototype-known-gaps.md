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

This commit (`9403a4d`) — R11b–R18: honest R11–R14 completion plus embed/corpus, ScanOptions, multi-address, runtime metrics.

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

Known debt:
- SNMP still self-dials inside `gosnmp.Connect`; the scan meter reserves the op with `CountDial` and wraps the resulting conn for bytes. The library socket is not `DialUDP`.
- ICMP discovery uses `CountDial`, not wrapped pinger I/O, so ICMP payload bytes are not counted.
- Legacy `pkg/probes/*` still dial on their own (not on the Engine path).
- Unregistered `collect.tcpstack` still uses `net.Dialer`.

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
- some remaining collectors are still legacy `Run()`-only; Engine does not treat their Completeness as a match

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

---

## R11 Recog / Wappalyzer

Status: COMPLETE (R11a adapters + R11b corpus import)

Commit: `d6dd7c3` adapters; this commit imports Rapid7 Recog XML and expands Wappalyzer JSON

R11a adapter support: COMPLETE  
R11b real corpus import / coverage: COMPLETE at bundled scale (not the entire Recog git tree)

Acceptance tests:
- `TestNativeRecogXMLOpenSSH` / `TestRecogParamValueAttribute` — Recog XML, including `value=""` attributes
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

Status: COMPLETE

Commit: `ef6bed4` shared helper; this commit adds collector-level pos/neg tests and tightens predicates

Acceptance tests:
- `TestFTPAcceptsFTP` / `TestFTPRejectsSMTP` / `TestFTPRejectsHTTPLookalike`
- `TestSMTPAcceptsSMTP` / `TestSMTPRejectsFTP` / `TestSMTPRejectsHTTPLookalike`
- `TestPOP3AcceptsOK` / `TestPOP3RejectsRandomBanner`
- `TestIMAPAcceptsGreeting` / `TestIMAPRejectsRandomBanner`
- `TestTelnetAcceptsLoginPrompt` / `TestTelnetRejectsSSH` / `TestTelnetRejectsHTTP`

Known debt:
- FTP vs SMTP still uses banner keywords (`SMTP`/`ESMTP`/`FTP`), not a full state machine.
- Telnet match requires IAC, login/password, or the word telnet — not a full option parser.

---

## R13 DB / middleware

Status: COMPLETE for in-tree DB collectors (MySQL, PostgreSQL, MSSQL, Redis, MongoDB, Memcached)

Commit: `ef6bed4` MySQL/Postgres; this commit hardens Mongo/MSSQL/Memcached and adds framing tests

Acceptance tests:
- `TestPostgresMatchSN` / `TestPostgresRejectsHTTP`
- `TestMySQLHandshakeSuccess` / `TestMySQLRejectsShortGarbage`
- `TestMongoOPReplySuccess` / `TestMongoRejectsHTTPLookalike` / `TestMongoRejectsWrongOpcode`
- `TestMSSQLPreloginVersionSuccess` / `TestMSSQLRejectsHTTPLookalike` / `TestMSSQLRejectsResponseWithoutVersion`
- `TestMemcachedAcceptsVersion` / `TestMemcachedRejectsHTTPLookalike` / `TestMemcachedRejectsRedisPong`
- `TestRedisAcceptsPong` / `TestRedisRejectsHTTPLookalike` / `TestRedisRejectsMemcachedVersion`

Known debt:
- MQTT/AMQP/VNC/SOCKS were not in the R13 hardening pass (do not add protocols; they remain weaker collectors).
- Mongo success is framed `OP_REPLY`/`OP_MSG`, not a decoded isMaster document.

---

## R14 LDAP / RDP / SSH / SMB

Status: COMPLETE for the stated acceptance items, with live SMB vendor tests still out of process

Commit: this commit — LDAPS/RootDSE, X.224/RDP negotiation, SSH ignore/debug skip, SMB lookalike + auth evidence

Acceptance tests:
- `TestLDAPRootDSEAttributes` — vendorName, namingContexts, dnsHostName, SASL, versions
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
- `TestStrongExactYAMLRulesHaveNegativeFixtures` — every strong/exact YAML claim has a negative fixture
- `TestHTTPBodyArtifactAndTruncation` — 256 KiB cap
- `TestHTTPApplicationPack` — title-only Grafana/Jenkins still match (now hint); server headers remain strong/exact

Known debt:
- Title-only rules are hints; distinctive favicon+title combined rules are still sparse.
- Recog import is two databases, not every Recog XML file upstream.

---

## R16 Sirius adapter / ScanOptions

Status: COMPLETE

Commit: this commit — `scan.ScanOptions` + `scan.Scan`; appscanner is Engine → Scan → `output.ToSiriusHost`

Acceptance tests:
- `TestScanOptionsWrapsEngineOptions` — one options type wrapping `engine.Options`; legacy off by default

Known debt:
- `fingerprintLegacyRunner` remains behind `UseLegacyRunner` only.
- `runner.Options` / `engine.Options` / Profile remain separate vocabularies.

---

## R17 IPv6 / multi-address

Status: COMPLETE

Commit: this commit — `ScanResolved` walks every A/AAAA; hostname kept; discovery/enum complete keys are per-address

Acceptance tests:
- `TestScanResolvedAllAddresses` — two resolved IPs both appear on the Asset; hostname preserved
- `TestClassificationPassesHostnameTarget` — hostname survives into collectors for SNI/Host

Known debt:
- none for the multi-address bar. `net.JoinHostPort` on IPv6 literals was already true in `pkg/transport`.

---

## R18 Metrics, unknowns, hardening

Status: COMPLETE

Commit: this commit — runtime counters; precision-at-tier moved to `pkg/metrics/eval`; unmatched banner dump; adapter/flatten panic recovery

Acceptance tests:
- `TestRuntimeCounters` — collectors, matches, timeouts, bytes, unknown endpoints, claim tiers, unmatched dump
- `TestEvalPrecisionAtTier` — `ExactCorrect`/`StrongCorrect` live in eval tooling, not `metrics.Counters`

Known debt:
- SNMP/ICMP payload bytes remain incompletely metered (R5).
- Unmatched banner dump is in-memory (64 entries), not a file sink.

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
