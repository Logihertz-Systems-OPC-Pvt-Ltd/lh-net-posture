# lh-net-posture

[![CI](https://github.com/logihertz/lh-net-posture/actions/workflows/ci.yml/badge.svg)](https://github.com/logihertz/lh-net-posture/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An asynchronous local and edge-node network exposure auditor by **Logihertz Systems OPC Pvt Ltd** that inspects active listening sockets, evaluates firewall policy drift (UFW / nftables), and checks TLS certificate expiration.

---

## Features

- **Linux Hex Socket Parser (`/proc/net`)**: Clean-room parser for Linux `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, and `/proc/net/udp6` socket tables. Decodes little-endian hexadecimal network addresses and ports without kernel dependencies to detect unexpected listening services and wildcard (`0.0.0.0` or `::`) bindings against an approved baseline.
- **Firewall Policy Auditor (UFW & nftables)**: Analyzes UFW rules (`/etc/default/ufw`, `user.rules`, `ufw status`) and nftables (`nftables.conf`) configurations for missing default-deny input policies, blanket allow rules, and exposed sensitive management ports (SSH 22, RDP 3389, databases, container daemon sockets).
- **TLS Certificate Inspector**: Evaluates local PEM files or remote TLS endpoints for upcoming expiration thresholds, weak cryptographic key sizes (e.g. RSA < 2048-bit, ECC < 224-bit), self-signed issuers, and deprecated signature algorithms (MD5, SHA-1).
- **Flexible Multi-Format Exporters**: Outputs rich interactive terminal tables via `rich`, machine-readable JSON reports, or OASIS SARIF v2.1.0 documents for seamless CI/CD and security scanner integration.

---

## Installation

`lh-net-posture` requires Python 3.11 or higher. We recommend using [uv](https://docs.astral.sh/uv/) for fast, deterministic environment management.

```bash
# Clone the repository
git clone https://github.com/logihertz/lh-net-posture.git
cd lh-net-posture

# Create and activate a virtual environment with uv
uv venv
source .venv/bin/activate

# Install with development dependencies
uv pip install -e ".[dev]"
```

---

## CLI Interface (`lh-net`)

The tool exposes the `lh-net` CLI entry point with three primary auditing commands:

### 1. Audit Listening Sockets

Inspect active listening sockets parsed from Linux `/proc/net` tables against an approved baseline:

```bash
# Audit active sockets against approved baseline with rich terminal table output
lh-net audit-sockets --baseline baselines/ports.json

# Export findings to JSON
lh-net audit-sockets --baseline baselines/ports.json --format json --output socket-report.json

# Export findings to SARIF v2.1.0 for GitHub Advanced Security / CI
lh-net audit-sockets --baseline baselines/ports.json --format sarif --output socket-findings.sarif
```

#### Baseline File Format (`ports.json`)

The baseline file supports several flexible schemas:

```json
{
  "approved_ports": [22, 80, 443],
  "approved_bindings": [
    {
      "port": 22,
      "protocol": "tcp",
      "address": "127.0.0.1",
      "description": "SSH restricted to localhost"
    },
    {
      "port": 443,
      "protocol": "tcp",
      "address": "0.0.0.0",
      "description": "Public HTTPS"
    }
  ]
}
```

Or a simple list of approved port numbers:

```json
[80, 443, 8080]
```

### 2. Audit Firewall Configurations

Audit UFW and nftables configuration files or status output for overly permissive rules and missing default-deny policies:

```bash
# Audit an nftables configuration file
lh-net audit-firewall /etc/nftables.conf

# Audit a UFW user rules file
lh-net audit-firewall /etc/ufw/user.rules --format table

# Output firewall audit report as SARIF v2.1.0
lh-net audit-firewall /etc/nftables.conf --format sarif --output firewall-findings.sarif
```

### 3. Check TLS Certificates

Inspect local PEM certificates or connect directly to a remote TLS endpoint:

```bash
# Inspect a remote endpoint with default 30-day expiration threshold
lh-net check-tls example.com:443

# Inspect a local PEM certificate file with custom warning threshold (e.g., 60 days)
lh-net check-tls /etc/ssl/certs/server.pem --warn-days 60

# Output findings in JSON format
lh-net check-tls api.internal.node:8443 --format json
```

---

## Exit Codes

`lh-net` conforms to standard automated security scanner exit code conventions:

| Exit Code | Meaning |
|:---------:|:--------|
| `0` | Audit completed with no high or critical severity violations. |
| `1` | One or more **CRITICAL** or **HIGH** severity exposure findings detected. |
| `2` | Execution error (e.g. invalid arguments, missing input file). |

---

## Development & Testing

Ensure quality, style, and security posture during local development:

```bash
# Run Ruff linting and formatting verification
ruff check .
ruff format --check .

# Run Bandit security scanner
bandit -r src/

# Run the complete test suite with coverage
pytest
```

---

## Architecture & Design

```
src/lh_net_posture/
├── __init__.py
├── __version__.py
├── models.py             # Data models: Severity, Finding, SocketInfo, AuditReport
├── cli.py                # Typer CLI application (entrypoint: lh-net)
├── sockets/
│   ├── parser.py         # Clean-room /proc/net hex socket table parser
│   └── auditor.py        # Baseline matcher and wildcard binding auditor
├── firewall/
│   ├── ufw.py            # UFW parser (/etc/default/ufw, user.rules, status)
│   ├── nftables.py       # nftables.conf parser and rule analyzer
│   └── auditor.py        # Unified firewall entrypoint dispatcher
├── tls/
│   └── inspector.py      # Local PEM & remote TLS endpoint cryptographic auditor
└── exporters/
    ├── rich_table.py     # Rich terminal presentation renderer
    ├── json_export.py    # Structured JSON report generator
    ├── sarif_export.py   # OASIS SARIF v2.1.0 report generator
    └── dispatcher.py     # Output router and file writer
```

---

## License

This software is licensed under the [MIT License](LICENSE).
Copyright &copy; 2026 Logihertz Systems OPC Pvt Ltd.
