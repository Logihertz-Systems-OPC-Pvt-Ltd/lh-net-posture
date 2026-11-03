# Security Policy

Logihertz Systems OPC Pvt Ltd is committed to ensuring the security and integrity of our software and network posture auditing tools.

## Supported Versions

Only the latest active major/minor release is actively supported with security updates.

| Version | Supported          |
|:-------:|:------------------:|
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability or exposure risk in `lh-net-posture`, please report it responsibly rather than opening a public issue on GitHub.

1. **Email Details**: Send a description of the issue to [security@logihertz.com](mailto:security@logihertz.com).
2. **Include in Report**:
   - A description of the vulnerability and potential impact.
   - Step-by-step instructions or minimal reproducer code to trigger the issue.
   - Operating system and Python version.
   - Any remediation suggestions if known.
3. **Response Timeline**:
   - We will acknowledge receipt of your report within 48 business hours.
   - A technical assessment and remediation plan will be provided within 5 business days.
   - A security patch will be released promptly following verification.

## Clean-Room Cryptography Notice

`lh-net-posture` performs read-only inspections of certificates, socket tables, and firewall configurations. It does not perform active exploitation, network tampering, or credential harvesting.

