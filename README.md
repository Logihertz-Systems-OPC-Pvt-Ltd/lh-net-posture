# lh-net-posture

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-net-posture/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-net-posture/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise network interface & socket posture developed by **Logihertz Systems (OPC) Private Limited**.

Inspects listening socket tables (ss/netstat), routing tables, ARP caches, VLAN trunks, and network interface configurations to flag cleartext protocols (Telnet/FTP), 0.0.0.0 management bindings, and IP forwarding risks.

---

## Key Features

- **Listening Socket & Port Auditing**: Audits active TCP/UDP sockets against an approved baseline manifest to flag rogue services.
- **Firewall Configuration Verification**: Evaluates `nftables` and UFW rulesets for missing default-deny policies and overly permissive inbound rules.
- **Wildcard Binding Detection**: Flags critical services bound to `0.0.0.0` or `::` instead of internal management interfaces.
- **TLS Certificate Expiration & Strength**: Checks remote endpoints and local PEM files for expiration countdowns, weak keys, and deprecated ciphers.
- **Multi-Format Reporting**: Outputs rich terminal tables, machine-readable JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `RULE-SOCK-UNAPPROVED` | `CRITICAL` | Unapproved listening network socket detected outside approved baseline |
| `RULE-SOCK-BASELINE-DRIFT` | `HIGH` | Listening socket address binding drifted from baseline specification |
| `RULE-SOCK-WILDCARD` | `HIGH` | Service bound to wildcard address 0.0.0.0 or :: exposing interface |
| `RULE-FW-DEFAULT-POLICY` | `CRITICAL` | Missing default-deny inbound policy in firewall ruleset (nftables/UFW) |
| `RULE-FW-OVERPERMISSIVE` | `HIGH` | Management port (SSH, RDP, DB) exposed to unrestricted source IP |
| `RULE-FW-BLANKET-ALLOW` | `CRITICAL` | Blanket inbound allow rule permitting all traffic without restriction |
| `RULE-TLS-EXPIRED` | `CRITICAL` | Endpoint TLS/SSL certificate has expired |
| `RULE-TLS-EXPIRING-SOON` | `HIGH` | TLS/SSL certificate expiring within configured warning threshold |
| `RULE-TLS-WEAK-KEY` | `HIGH` | Insufficient RSA key length (< 2048 bits) or ECC curve size (< 224 bits) |
| `RULE-TLS-WEAK-HASH` | `CRITICAL` | Insecure signature hash algorithm detected (MD5, SHA-1) |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-net-posture.git
cd lh-net-posture

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-net` (also accessible via `lh-net`).

```bash
# Audit listening sockets against an approved port baseline
lh-net audit-sockets --baseline ports.json

# Audit an nftables firewall configuration file
lh-net audit-firewall /etc/nftables.conf

# Inspect a live TLS endpoint for certificate expiration
lh-net check-tls api.example.com:443 --format json

# Export findings to OASIS SARIF v2.1.0
lh-net audit-sockets --format sarif --output net-results.sarif
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
