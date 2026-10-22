# tspu-probe

**A comprehensive, single-run diagnostic that fingerprints ТСПУ / DPI censorship behaviour on Russian ISP and mobile networks.**

`tspu-probe` is a self-contained Bash + Python tool that characterises how a network path filters traffic and — new in 2.0 — tells you **which circumvention techniques actually work on that path**. It measures DNS interference (including race-injected fake answers), SNI/TLS blocking, RST injection with DPI localisation, a desynchronisation-bypass strategy matrix, HTTP host-blocking, ECH, UDP/QUIC suppression, throttling, mobile TCP-freezes and behavioural connection-freeze thresholds — and writes one structured, timestamped report (plus optional JSON).

> **RU:** Одноразовый диагностический скрипт, снимающий поведение ТСПУ/DPI на конкретном сетевом пути и определяющий, **какие техники обхода на нём работают**. За один прогон: вмешательство в DNS (вкл. инъекцию поддельных ответов гонкой), SNI/TLS-блокировки, инъекцию RST с локализацией DPI, матрицу desync-обходов, HTTP-блокировки, ECH, подавление UDP/QUIC, троттлинг, мобильные TCP-заморозки и порог поведенческого freeze. Результат — единый отчёт (+ опционально JSON).

---

## ⚠️ Scope, ethics & legal

- A **measurement / research** tool. It characterises the *censor's* behaviour on a network you are **authorised to test** (typically your own connection). It is **not** a circumvention client and ships **no** proxy/VPN.
- Run it **only on connections you own or are explicitly permitted to measure.**
- The behavioural-freeze stage is **deliberately adversarial** and briefly stalls the local link — disable it with `--no-freeze` (or `--quick`).
- **Read-only with respect to the host**: it changes no system state and removes its temporary files on exit.

## Requirements

- Linux, **`bash` ≥ 4** (macOS `/bin/bash` 3.2 is not supported), `python3` (3.8+, standard library only)
- `curl` (a build with **HTTP/3** and **`--ech`** unlocks the QUIC and Encrypted-ClientHello stages), `dig`, `openssl`, `ip` (iproute2), `timeout` (coreutils)
- **root** recommended — enables the raw-socket RST-injection TTL analysis; everything else runs without it.

Missing prerequisites abort with exit code 2 before any traffic is sent (`--force` downgrades the platform/tool checks to warnings).

## Usage

Disable **all** local VPN/proxy tunnels first — the host must egress directly over the network you want to characterise. If the detected egress country is not Russia the run **aborts with exit 3** (override with `--force`; results are then not representative of ТСПУ).

```bash
sudo bash tspu-probe.sh                 # full run
sudo bash tspu-probe.sh --quick         # faster, skips slow/adversarial stages
sudo bash tspu-probe.sh --no-freeze     # full run without the disruptive freeze stage
sudo bash tspu-probe.sh --json --out ./reports
```

| Flag | Effect |
|------|--------|
| `--quick` | trims canary list, skips hop-scan and behavioural freeze |
| `--no-freeze` | runs everything except the adversarial freeze stage |
| `--json` | also writes a machine-readable `tspu-report-<ts>.json` |
| `--out DIR` | output directory (default `.`) |
| `--timeout N` | per-probe timeout, integer 1–600 s (default 10); scales curl/dig/DoT/STUN/NTP limits too |
| `--targets FILE` | custom canary list (one host per line, `#` comments allowed; not trimmed by `--quick`) |
| `--force` | continue despite a non-RU vantage, non-Linux OS or missing tools |
| `--version` | print the version and exit |
| `-h`, `--help` | short usage |

Output → `<out>/tspu-report-<timestamp>.txt` (~3–6 MB traffic, ~10–15 min full run), mode 0600 (owned by `$SUDO_USER` under `sudo`).
Exit codes: `0` ok · `2` usage / missing prerequisites · `3` vantage gate.

## Privacy: what leaves your machine

The probe contacts third parties; your public IP is visible to all of them. Do not run it if that is unacceptable.

| Purpose | Hosts |
|---------|-------|
| Vantage (IP / ASN / country) | `ip-api.com` (plain HTTP), `api64.ipify.org` |
| DoH bootstrap | `1.1.1.1`, `8.8.8.8` |
| Control / HTTP / throughput | `ya.ru`, `mirror.yandex.ru`, `cachefly.cachefly.net`, `*.thinkbroadband.com`, `speedtest.tele2.net`, `www.google.com` |
| UDP profile | `stun.l.google.com:19302`, `stun.cloudflare.com:3478`, `time.google.com:123`, `cloudflare-quic.com` |
| ECH | `crypto.cloudflare.com` |
| Canary domains | the list in the script (or your `--targets`) |

The report itself contains your public IP, ASN and resolver addresses — review it before sharing.

## What it measures

| # | Stage | Detects |
|---|-------|---------|
| 0 | Vantage | egress IP / ASN / country / mobile flag, IPv6, MTU; guards against a still-active tunnel |
| 1 | Control | baseline reachability & latency |
| 2 | DNS | poisoning / refusal, **answer injection**, DoT, **DNS-over-TCP**, multiple resolvers |
| 3 | IP reachability | TCP SYN to `:443`/`:80` — isolates IP-blocks from SNI-blocks |
| 4 | SNI + **desync matrix** | `normal` / `split@1` / `split@4` / `split@SNI` / **TLS-record frag**, ×3 with majority vote |
| 5 | SNI-vs-IP | benign / empty SNI to a blocked IP |
| 6 | HTTP `:80` | Host-header blocking, RKN stub-page |
| 7 | ECH | Encrypted-ClientHello capability + DoH-bootstrapped live test |
| 8 | UDP profile | DNS `:53` / NTP `:123` / STUN `:19302` (Google) + `:3478` (Cloudflare) / QUIC `:443` |
| 9 | Throughput | throttle quantification + mobile ~16 KB TCP-freeze |
| 10 | DPI fingerprint | injected-RST TTL, **hop-distance localisation**, residual censorship window |
| 11 | Behavioural freeze | parallel-TLS burst sweep — onset / duration / scope (opt-out) |
| — | Verdict | which desync modes bypassed a block that the normal ClientHello hit; DPI hop → fake-TTL hint |

## How it works

- **TLS probing** builds and emits the `ClientHello` directly via `ssl.MemoryBIO`, so the exact on-wire framing is controlled — enabling `split@1` / `split@4` / `split@SNI` TCP-segmentation *and* TLS-record fragmentation without external tooling.
- **DPI localisation** raises `IP_TTL` on the ClientHello until an injected RST appears; the crossover TTL estimates the censor's hop distance (useful for tuning fake-packet desync in zapret/byedpi).
- **DNS injection** is caught by collecting *every* UDP response to a single query and comparing them.
- **RST-injection detection** compares the TTL of RST packets against genuine SYN/ACKs via a raw socket (root).
- **DoH** resolution (Cloudflare and Google, by IP) keeps canary IPs correct even when plain DNS is interfered with; every lookup is logged as a `[doh]` line.

## Output & verdict

Plain-text report (one line per probe) plus an optional JSON file (`version`, `vantage_valid`, `verdict`, and the collected probe data) and a closing **verdict**.

The verdict is computed from the report's own SNI matrix: a desync mode is reported as a bypass only for domains whose *normal* ClientHello was blocked (`RST`/`TIMEOUT`/`EOF`/`DATA`); modes that fail on unblocked domains are flagged; `MIXED`/`ERR` results are inconclusive; with no blocking observed the verdict is `n/a`. It also gives the estimated DPI hop distance as a fake-TTL hint. UDP/QUIC and throughput findings are in §8/§9 — the verdict does not summarise them.

## Tests

```bash
python3 -m unittest discover -s tests -v     # stdlib only
TSPU_BASH=/opt/homebrew/bin/bash python3 -m unittest discover -s tests   # run CLI smoke tests with bash >= 4
TSPU_OFFLINE=1 python3 -m unittest discover -s tests                      # skip tests that touch the network
```

The tests exercise the embedded engine against a loopback TLS server with a DPI simulator, plus CLI validation and a stubbed end-to-end `--quick` run (`tests/stubs/`). They cannot reproduce real ТСПУ behaviour.

## Limitations

- Results are **specific to the vantage** (operator, region, time) — mobile and fixed-line paths differ; re-run per network.
- Censorship is often intermittent; the desync matrix votes over 3 tries but a single run is still a snapshot.
- Hop-distance and freeze thresholds can be noisy under residual/stateful censorship — the report flags likely contamination.

## License

**[Apache License 2.0](LICENSE)** — free to use, modify and redistribute (including commercially), **with mandatory attribution**: retain the copyright, license and `NOTICE` notices, and state significant changes. See [`NOTICE`](NOTICE).

> `v1.0.0` was released under MIT; from **v2.0.0** the project is licensed under Apache-2.0.

**Author:** Maximilian Kaufmann · © 2026 · https://github.com/MaximilianKaufmannCode
