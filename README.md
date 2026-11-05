# HookPhalanx 🛡️

[![CI](https://github.com/Scempyyy/HookPhalanx/actions/workflows/ci.yml/badge.svg)](https://github.com/Scempyyy/HookPhalanx/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.8+](https://img.shields.io/badge/python-3.8+-brightgreen.svg)](https://python.org)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-success.svg)](#)

> **Zero-Trust Phishing Link Sandbox & Heuristic Threat Inspector.**  
> Safely detonate, trace redirection hops, audit homoglyphs, and detect credential-harvesting mechanisms without leaking your identity or browser footprint.

---

## ⚡ Highlights

- **Zero Third-Party Dependencies:** 100% written using the Python Standard Library (`urllib`, `socket`, `ssl`, `html.parser`, `http.server`).
- **Homoglyph & Punycode Defense:** Dissects internationalized domain names (IDN / `xn--`) used in spoofing attacks.
- **Brand Impersonation Detection:** Flags deceptive subdomains imitating protected services (PayPal, Google, Apple, Microsoft, Steam, etc.).
- **Redirection Chain Tracer:** Traverses multi-hop 301/302/307 redirections and meta-refresh triggers without executing malicious client payloads.
- **Credential Form Auditor:** Detects hidden forms, password inputs over unencrypted HTTP, and financial exfiltration patterns.
- **Dual Interface:** Full terminal CLI for automated scanning pipelines and modern dark-mode web console for SOC analysts.

---

## 🚀 Quick Start

### 1. Run Directly (No Install Needed)
```bash
git clone https://github.com/Scempyyy/HookPhalanx.git
cd HookPhalanx
./hookphalanx.py scan "https://paypal.urgent-security-verify.xyz/auth"
```

### 2. Launch the Web Studio
```bash
./hookphalanx.py serve --port 7088
```
Open [http://localhost:7088](http://localhost:7088) in your browser.

---

## 💻 CLI Usage

```bash
# Scan a suspicious URL with full network detonation
python3 hookphalanx.py scan https://example.com

# Static heuristic analysis without making any outbound requests
python3 hookphalanx.py scan https://suspicious-target.xyz --no-fetch

# Output results as structured JSON for automation & SIEM ingestion
python3 hookphalanx.py scan https://suspicious-target.xyz --json

# Launch web server on custom port
python3 hookphalanx.py serve --port 8080 --host 0.0.0.0
```

---

## 🧪 Threat Heuristics Matrix

| Threat Category | Weight | Description |
|---|---|---|
| **Homoglyph / Punycode** | 35 pts | Evaluates IDN / Punycode spoofing (`xn--`) |
| **Brand Keyword Implantation** | 45 pts | Detects brand names in subdomains or deceptive path prefixes |
| **Direct IP Hostname** | 30 pts | Flags raw IP addresses used in place of registered domain records |
| **High-Abuse TLD** | 20 pts | Detects statistically elevated phishing TLDs (`.xyz`, `.top`, `.tk`, etc.) |
| **SSRF / Internal Subnet Guard** | 90 pts | Blocks internal loopbacks, RFC1918 addresses, and link-local ranges |
| **Cleartext Password Input** | 35 pts | Catches password forms transmitted over unencrypted HTTP |
| **Social Engineering Urgency** | 10-25 pts | Identifies coercive phrasing ("Account suspended", "Verify within 24h") |

---

## 🔬 Testing

HookPhalanx comes with a self-contained unit test suite:
```bash
python3 -m unittest discover tests -v
```

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details. Built by [Scempyyy](https://github.com/Scempyyy).
