# Changelog

All notable changes to **tspu-probe** are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [2.1.1] — 2026-07-10

### Fixed
- **DoT probe (§2)** — removed a broken nested `bash -c` quoting construct that
  emitted a shell error (`unexpected EOF while looking for matching quote`) and
  mangled the DNS-over-TLS line. The DoT check now runs cleanly (assigns to a
  variable, then logs).

## [2.1.0] — 2026-07-10

### Fixed
- **DNS-robust control plane** — DoH now resolves via resolver IPs (1.1.1.1 / 8.8.8.8 / 9.9.9.9),
  and every control-plane request pins the resolved IP (`curlr`). Vantage, control, HTTP and the
  freeze-control no longer break when `systemd-resolved` still points at a dead tunnel resolver
  after the tunnels are torn down (root cause of the empty vantage/control seen in field runs).
- **hop-distance** — treat RST-on-send (`BrokenPipeError`) as RST, fixing all-`ERR` traces on
  fast RST-injecting targets; connect- and send-timeouts are now distinguished.
- **RST-TTL capture** — bind the raw socket to the egress interface, fire 4× with a capture-ready
  delay, and annotate zero-capture (target in drop-mode).
- **Throughput endpoints** — replaced unreliable hosts; added `speedtest.tele2.net` and
  `thinkbroadband` for dependable large-transfer / throttle measurement.

## [2.0.0] — 2026-07-09

### Added
- **Desync strategy matrix** — each canary is probed with `normal`, `split@1`,
  `split@4`, `split@SNI` and **TLS-record fragmentation**, each repeated x3 with
  majority voting, so the report directly answers *which desync bypass works here*.
- **DPI hop-distance localisation** — an `IP_TTL` sweep finds the smallest TTL that
  still triggers an injected RST, estimating how many hops away the censor is
  (input for tuning fake-packet TTLs in zapret/byedpi). No root required.
- **DNS answer-injection detection** — captures *all* responses to a single query
  to reveal race-injected fake answers; plus **DNS-over-TCP:53** and extra resolvers.
- **Throughput / throttle quantification** alongside the mobile ~16 KB TCP-freeze test.
- **Domain-fronting probe** (TLS-SNI = allowed, HTTP-Host = blocked).
- **CLI flags**: `--quick`, `--no-freeze`, `--json`, `--out DIR`, `--timeout N`,
  `--targets FILE`, `-h/--help`.
- **JSON output** (`--json`), a per-run **verdict/summary**, dynamic egress-interface
  detection and IPv6 vantage reporting.

### Changed
- **Re-licensed to Apache-2.0** (from MIT) and added a `NOTICE` file — stronger,
  explicit attribution to the original author, plus a patent grant.
- More robust DoH resolution (three providers with fallback); improved large-transfer
  endpoints; removed the `bc` dependency; stage 11 (behavioural freeze) is now opt-outable.

### Notes
- `v1.0.0` remains available under the MIT License (immutable release/tag).

## [1.0.0] — 2026-07-09

### Added
- Initial release (MIT). Single-run, 11-stage ТСПУ/DPI probe: vantage, control,
  DNS, IP reachability, SNI filtering (split@1/split@SNI), SNI-vs-IP isolation,
  HTTP host-blocking + RKN stub, ECH, UDP/QUIC profile, mobile 16 KB freeze,
  RST-injection TTL fingerprint, behavioural freeze.
