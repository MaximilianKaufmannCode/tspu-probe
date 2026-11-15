# Changelog

All notable changes to **tspu-probe** are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **DNS transport comparison (§2)** — the same `whoami.akamai.net` query goes to 8.8.8.8 and
  1.1.1.1 over UDP/53 and TCP/53 (`dnsxport`). The verdict gains a `dns_transport` entry per
  resolver: `udp-diverted` when only the UDP answer comes from `193.232.*` (MSK-IX/NSDI, the
  TSPU DNAT described in net4people/bbs#657), else `same`, `differs` or `inconclusive`.

## [2.1.2] — 2026-10-22

Hotfix release: the verdict could report a bypass that never happened, and several
inputs/edge cases failed silently. No new probes; one probe removed.

### Fixed
- **Verdict (§SUMMARY)** — "desync that bypassed at least one block" grepped `=OK` across *all*
  domains, so a strategy that merely succeeded on unblocked hosts was reported as a bypass. The
  verdict is now computed by the engine from the report's own `sni` lines: a mode counts only on
  domains whose normal ClientHello was blocked; `MIXED`/`ERR` results are inconclusive; strategies
  that fail on unblocked domains are flagged; with no blocking the verdict is "n/a". The JSON
  report gains a structured `verdict` object, `version` and `vantage_valid`.
- **Majority vote** — a 3-way tie (`OK TIMEOUT RST`) used to report the first-seen status as
  `OK(1/3)`. Votes need a strict majority, otherwise `MIXED(a/b/c)`. Voting moved into the engine
  (`tls3`), replacing ~400 Python launches per run.
- **DNS over TCP (§2)** — the 2-byte length prefix often arrives as its own segment, so a single
  `recv()` yielded `ips: []` every time. The reply is now read by exact length; EOF is reported.
- **DoH chain** — `9.9.9.9` answered HTTP 400 (it needs RFC 8484 wire format), so only 1.1.1.1 and
  8.8.8.8 are used. Failed lookups are cached negatively; each lookup's provider is logged as a
  `[doh]` line.
- **IPv6 vantage** — the `-6` request carried an IPv4 `--resolve` pin and silently fell back to system
  DNS; it now checks for an IPv6 route and reports `no-ipv6-route` / `unreachable` distinctly.
- **STUN** — the label said `3478` while probing Google on `19302`; it now probes
  `stun.l.google.com:19302` and `stun.cloudflare.com:3478` and labels both correctly. STUN/NTP honour `--timeout`.
- **ECH** — queried the HTTPS RR via `dns.google` (system DNS); now `8.8.8.8` directly. Removed a dead
  `|| echo none`.
- **Residual window (§10)** — labels showed the sleep step, not elapsed time; now real seconds after the trigger.
- **Freeze (§11)** — control failures printed time glued to `FREEZE`; the "repeat first freezing
  level" step always ran N=16 — it now repeats the first level that actually froze (or is skipped);
  duration is wall-clock instead of `polls*3/2`.
- **`--quick` + `--targets`** — `--quick` silently replaced a user-supplied target list.
- Sorted throughput output; `/etc/resolv.conf` resolver instead of a hard-coded `127.0.0.53`;
  `tr '\n' ' | '` idiom; `[ ] && … ||` idioms (shellcheck-clean at style level).

### Security
- Temp files live in a private `mktemp -d` (mode 0700) instead of predictable `/tmp/tspu_*` names, and the
  report files are 0600 (handed to `$SUDO_USER` when run under sudo). All Python runs with `-I`, so a stray
  `json.py` / `ssl.py` next to the script (or `PYTHON*` variables) cannot execute as root.
- `--targets` entries are validated against a hostname charset; `--timeout` must be an integer 1–600.

### Changed
- **Fail fast with exit 2** on bash < 4 (macOS `/bin/bash` aborted mid-run on `declare -A`), missing
  `python3`/`curl`, Python < 3.8, non-Linux or missing `dig`/`openssl`/`ip`/`timeout`. `--force` downgrades
  the platform/tool checks to warnings.
- **Vantage gate** — outside Russia the run now aborts with exit 3 (use `--force` to override); an
  undetermined country continues with a warning and `vantage.valid=unknown`.
- Errors go to stderr; `-h` prints a real usage text (the old one dumped the whole file header); new `--version`
  and `--force` flags; options requiring a value now error when it is missing. `--timeout` scales every
  curl/dig/DoT limit, not only the Python probes.
- Report header logs curl/python/openssl/dig versions.
- `--quick` skips the hop-scan as before; the README no longer promises a "transport viability" verdict
  (see §8/§9 for UDP and throughput).

### Removed
- **Domain-fronting probe (§6)** — `x.com` sits on Cloudflare, so `Host: x.com` against a Cloudflare IP
  returns 403 regardless of censorship; the probe could not produce a positive signal.

### Added
- `tests/` (stdlib `unittest`, no dependencies): vote/verdict fixtures, a loopback TLS server exercising all
  five desync modes and a DPI simulator, DNS parser/injection/TCP tests, CLI validation tests and a
  stubbed end-to-end `--quick` run. `.github/workflows/ci.yml` runs shellcheck, ruff and the tests on Linux
  and macOS.

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
