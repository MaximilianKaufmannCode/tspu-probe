# tspu-probe

**A single-run diagnostic probe for characterising ТСПУ / DPI censorship behaviour on Russian ISP and mobile networks.**

`tspu-probe` is a self-contained Bash + Python measurement tool that fingerprints how a network path filters traffic: SNI-based TLS blocking, RST injection, DNS interference, HTTP host-blocking, UDP/QUIC suppression, mobile large-transfer freezes, behavioural connection-freeze thresholds, and ClientHello desynchronisation (fragmentation) bypasses. It produces one structured, timestamped report intended as empirical input for censorship-circumvention research and protocol design.

> **RU:** Одноразовый диагностический скрипт для снятия поведения ТСПУ/DPI на конкретном сетевом пути (фиксированный ШПД или мобильный оператор). За один прогон характеризует SNI-фильтрацию, инъекцию RST, вмешательство в DNS, HTTP-блокировки, подавление UDP/QUIC, мобильные «заморозки» крупных передач, порог поведенческого freeze и обход через фрагментацию ClientHello. Результат — единый структурированный отчёт.

---

## ⚠️ Scope, ethics & legal

- This is a **measurement / research** tool. It characterises the *censor's* behaviour on a network you are **authorised to test** (typically your own connection). It is **not** a circumvention client and ships **no** proxy/VPN.
- Run it **only on connections you own or are explicitly permitted to measure.**
- Section 11 (behavioural freeze) is **deliberately adversarial**: it briefly triggers throttling on the local path to measure the freeze threshold and recovery. Expect short connectivity stalls during that section.
- The tool is **read-only with respect to the host**: it changes no system state and removes its temporary files on exit.

## Requirements

- Linux, `bash`, `python3` (3.8+)
- `curl` (a build with **HTTP/3** and **`--ech`** unlocks the QUIC and Encrypted-ClientHello tests), `dig`, `openssl`
- **root** recommended — enables the raw-socket RST-injection TTL analysis (Section 10); without root that one test is skipped and everything else still runs.

## Usage

Disable **all** local VPN/proxy tunnels first — the host must egress directly over the network you want to characterise (the script aborts-with-warning if it detects a non-target egress country).

```bash
sudo bash tspu-probe.sh
```

Output is written to `./tspu-report-<timestamp>.txt` (and streamed to stdout). Typical run: **~3–5 MB** of traffic, **~10–13 min**.

## What it measures

| # | Section | Detects |
|---|---------|---------|
| 0 | Vantage | Egress IP / ASN / country / mobile flag; guards against a still-active tunnel |
| 1 | Control | Baseline reachability & latency to allowed sites |
| 2 | DNS | Poisoning / refusal — system vs foreign-UDP vs RU-UDP vs DoH |
| 3 | IP reachability | TCP SYN to `:443`/`:80` of blocked hosts — isolates IP-blocks from SNI-blocks |
| 4 | SNI filtering | Normal vs `split@1` vs `split@SNI` ClientHello — RST/DROP behaviour and desync bypass |
| 5 | SNI-vs-IP | Benign / empty SNI to a blocked IP — is the block keyed on the name or the address? |
| 6 | HTTP `:80` | Host-header blocking and RKN stub-page (blockpage) detection |
| 7 | ECH | Encrypted-ClientHello capability + DoH-bootstrapped live test |
| 8 | UDP profile | DNS `:53`, NTP `:123`, STUN `:3478`, QUIC `:443` — all-UDP suppression vs QUIC-specific |
| 9 | Large transfer | Range-capped downloads — detects the mobile ~16 KB TCP freeze on foreign paths |
| 10 | RST fingerprint | TTL of injected RST vs genuine server packets (root); residual/stateful censorship window |
| 11 | Behavioural freeze | Parallel-TLS burst sweep — freeze onset, duration and scope |

## How it works

- **TLS probing** uses Python's `ssl.MemoryBIO` to build and emit a `ClientHello` directly, so the exact on-wire framing is controlled — enabling `split@1` and `split@SNI` TCP-segmentation (desync) tests without external tooling.
- **Block classification** reads the first response bytes: a `0x16 0x03…` record (ServerHello) means *not blocked*; a reset means *RST injection*; silence means *DROP*.
- **RST-injection detection** sniffs inbound packets via an `AF_PACKET` raw socket and compares the TTL of RST packets against genuine SYN/ACKs — a TTL delta reveals a middlebox-injected reset.
- **DNS resolution** for blocked names is done over **DoH**, so canary IPs are obtained even when plain DNS is interfered with.

## Output & interpretation

The report is plain text with one line per probe and a machine-readable summary. Key legends are printed inline per section (e.g. `OK` = ServerHello received, `RST` = injected reset, `TIMEOUT` = silent drop).

## Limitations

- Results are **specific to the vantage** (operator, region, time) — mobile and fixed-line paths differ; re-run per network.
- Censorship is often intermittent and time-of-day dependent; a single run is a snapshot, not a verdict.
- The behavioural-freeze threshold is inherently noisy; the script repeats the first freezing level, but pinning exact thresholds needs several runs.

## License

[MIT](LICENSE) — free to use, modify and redistribute, **with attribution** (the copyright and licence notice must be retained).

**Author:** Maximilian Kaufmann · © 2026
