# openxos-ghost

> Low-noise, evasion-aware security probe — part of the [Openxos](https://github.com/Openxosdev) toolkit.

[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](./LICENSE)
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange?style=flat-square)](https://rustlang.org)
[![Authorized use only](https://img.shields.io/badge/use-authorized%20targets%20only-red?style=flat-square)]()

---

## What it does

Standard scanners get blocked by WAFs and IDS systems before they find anything.
`openxos-ghost` operates below detection thresholds — randomized timing, header rotation,
path encoding variants — to surface findings that noisy scanners miss entirely.

Every finding includes a **detection gap report**: what technique worked, which layer
failed, and why a standard tool would have missed it.

---

## Modes

**Web mode** — probes web applications through WAF/security controls
- WAF detection and fingerprinting
- Header-based bypass techniques
- Path encoding and normalization bypass
- User-agent and request timing evasion

**Net mode** — probes infrastructure through IDS/firewall
- Randomized port order (avoids sequential scan signatures)
- Low-rate probing with jitter
- Configurable timing profiles

---

## Install

```bash
git clone https://github.com/Openxosdev/openxos-ghost
cd openxos-ghost
cargo build --release
# Binary at: ./target/release/ghost
```

---

## Usage

```bash
# Web probe — slow profile (maximum stealth)
ghost web --target https://example.com --authorized --profile slow

# Web probe — specific path, markdown output
ghost web --target https://example.com --path /admin --authorized --profile medium --format markdown --output report.md

# Net probe — top 100 ports
ghost net --target 192.168.1.1 --authorized --profile slow

# Net probe — custom port range, JSON output
ghost net --target 192.168.1.1 --ports 1-1024 --authorized --profile medium --output scan.json
```

---

## Profiles

| Profile | Delay | Concurrency | Use case |
|---|---|---|---|
| `slow` | 3–8s + jitter | 1 | High-security targets |
| `medium` | 0.5–2s + jitter | 3 | Standard authorized testing |
| `aggressive` | 100–400ms | 10 | Speed over stealth |

---

## Output

Every scan produces a structured report with:
- Findings with severity rating
- Evasion technique that surfaced each finding
- Detection gap explanation
- Reproducible `curl` command per finding
- Full evasion summary

Formats: `json` (default), `markdown`, `both`

---

## Authorization

The `--authorized` flag is **mandatory**. It is not optional or bypassable.

This tool is for:
- Your own infrastructure
- Bug bounty program scope (explicitly listed targets)
- Authorized penetration testing engagements

Unauthorized use is illegal. The `--authorized` flag documents your intent at the command level.

---

## Support

**Monero (XMR):**
```
49DDzakQJoKKq5caPdeZMH1JoC1GERzbnTw7RFx5Zq4xFLiXgkNgxuEau4rXH3f5V29cbXPB4bxk1dy1YKxAiwZ9LvkaUCv
```

---

## License

MIT — see [LICENSE](./LICENSE)
