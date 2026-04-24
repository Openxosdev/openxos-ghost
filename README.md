# openxos-ghost

> Low-noise, evasion-aware security probe for authorized testing

[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](./LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-1.70+-orange?style=flat-square)](https://rustlang.org)
[![CI](https://img.shields.io/github/actions/workflow/status/Openxosdev/openxos-ghost/ci.yml?label=CI&style=flat-square)](https://github.com/Openxosdev/openxos-ghost/actions)
[![Crates.io](https://img.shields.io/crates/v/openxos-ghost?style=flat-square)](https://crates.io/crates/openxos-ghost)
[![Authorized use only](https://img.shields.io/badge/use-authorized%20targets%20only-red?style=flat-square)](https://github.com/Openxosdev/openxos-ghost#authorization)

---

## What it does

Standard scanners get blocked by WAFs and IDS systems before they find anything.
`openxos-ghost` operates below detection thresholds — randomized timing, header rotation,
path encoding variants — to surface findings that noisy scanners miss entirely.

Every finding includes a **detection gap report**: what technique worked, which layer
failed, and why a standard tool would have missed it.

### Key Features

- **Dual-mode scanning**: Web (HTTP/HTTPS) and Net (TCP ports)
- **WAF detection & fingerprinting**: Identify Cloudflare, Akamai, Imperva, AWS, Azure
- **Evasion techniques**: Header injection, path encoding, user-agent rotation
- **Configurable profiles**: Slow, medium, or aggressive scanning speeds
- **Output formats**: JSON for automation, Markdown for reports

---

## Installation

### From Crates.io

```bash
cargo install openxos-ghost
```

### From Source

```bash
git clone https://github.com/Openxosdev/openxos-ghost
cd openxos-ghost
cargo build --release
# Binary at: ./target/release/ghost
```

### Build from Source (Benchmarks)

```bash
cargo build --release --bench
```

---

## Quick Start

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

### Global Flags

| Flag | Description |
|------|-------------|
| `--authorized` | **Required**: Confirm you have explicit authorization |
| `--profile` | Evasion profile: `slow`, `medium`, `aggressive` (default: `slow`) |
| `--format` | Output format: `json`, `markdown`, `md`, `both` (default: `json`) |
| `--output` | Output file path (default: stdout) |

### Web Mode Flags

| Flag | Description |
|------|-------------|
| `--target` | Target URL (e.g., `https://example.com`) |
| `--path` | Specific path to probe (e.g., `/admin`) |

### Net Mode Flags

| Flag | Description |
|------|-------------|
| `--target` | Target IP or hostname |
| `--ports` | Port spec: `top100`, `80,443`, or `1-1024` (default: `top100`) |

---

## Profiles

| Profile | Delay | Concurrency | Use Case |
|---------|-------|-------------|----------|
| `slow` | 3–8s + jitter | 1 | High-security targets, stealth operations |
| `medium` | 0.5–2s + jitter | 3 | Standard authorized testing |
| `aggressive` | 100–400ms | 10 | Speed over stealth |

### Custom YAML Profiles

Create a custom profile:

```yaml
name: my-profile
delay_min_ms: 1000
delay_max_ms: 3000
concurrency: 2
ua_rotate_every: 2
jitter: 0.7
timeout_ms: 10000
```

Load it with: `ghost web --target https://example.com --profile /path/to/custom.yaml`

---

## Output Format

Every scan produces a structured report with:

- **Findings** with severity rating (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- **Evasion technique** that surfaced each finding
- **Detection gap** explanation
- **Reproducible** `curl` command per finding
- **Full evasion summary**

### Example JSON Output

```json
{
  "mode": "Web",
  "target": "https://example.com",
  "findings": [
    {
      "severity": "MEDIUM",
      "title": "Security control bypass via request headers",
      "description": "...",
      "evasion_technique": "Header bypass variant 1",
      "detection_gap": "...",
      "evidence": {
        "request": "GET / HTTP/1.1",
        "response_code": 200,
        "curl_repro": "curl -s -o /dev/null -w '%{http_code}' 'https://example.com' ..."
      }
    }
  ]
}
```

---

## Authorization

The `--authorized` flag is **mandatory**. It is not optional or bypassable.

This tool is for:
- Your own infrastructure
- Bug bounty program scope (explicitly listed targets)
- Authorized penetration testing engagements

Unauthorized use is illegal. The `--authorized` flag documents your intent at the command level.

### Why Authorization Matters

- Legal protection under responsible disclosure guidelines
- Clear scope definition for bug bounty programs
- Ethical security research practice
- Documentation requirement for professional engagements

---

## WAF Detection

The tool automatically detects and fingerprints the following WAF/security providers:

| Provider | Detection Method |
|----------|------------------|
| Cloudflare | Server header, Cloudflare-specific responses |
| AWS WAF/ELB | `awselb`, `X-Amzn-Requestid` headers |
| Akamai | `X-Cache: HIT from akamai` |
| Imperva/Incapsula | `X-Iinfo`, `X-Cdn: imperva` headers |
| Sucuri | `X-Sucuri-Id` header |
| Azure Front Door | `X-Azure-Ref` header |
| Generic WAF | 403 responses with security-related body text |

---

## Output Formats

### JSON (`--format json`)
Structured output for automation and integration with other tools.

### Markdown (`--format markdown`)
Human-readable report suitable for documentation and sharing.

### Both (`--format both`)
Generates both JSON and Markdown files with the same base name.

---

## Troubleshooting

### Connection Timeouts
Increase the timeout in your profile:
```yaml
timeout_ms: 15000  # 15 seconds
```

### False Positive WAF Detection
Some sites return 403 for non-WAF reasons. Use the `--authorized` flag and verify with a known-good tool like `curl`.

### Port Scan Not Finding Open Ports
- Ensure the target is reachable (`ping`, `traceroute`)
- Try `--profile aggressive` for faster, more aggressive scanning
- Check firewall rules on both ends

---

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

### Development Setup

```bash
git clone https://github.com/Openxosdev/openxos-ghost
cd openxos-ghost
cargo build
cargo test
```

### Code Style

- Format: `cargo fmt --all`
- Lint: `cargo clippy --all-targets -- -D warnings`

---

## Support

**Monero (XMR):**
```
49DDzakQJoKKq5caPdeZMH1JoC1GERzbnTw7RFx5Zq4xFLiXgkNgxuEau4rXH3f5V29cbXPB4bxk1dy1YKxAiwZ9LvkaUCv
```

---

## License

MIT — see [LICENSE](./LICENSE)

---

*openxos-ghost v0.1.2 — Authorized testing only*
