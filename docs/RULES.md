# Security Rules Reference: lh-net-posture

An enterprise network exposure & firewall posture auditor developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-net-posture`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `RULE-SOCK-UNAPPROVED` | `CRITICAL` | Socket Exposure | Unapproved Listening Network Socket Detected |
| `RULE-SOCK-BASELINE-DRIFT` | `HIGH` | Socket Exposure | Listening Socket Address Binding Drifted from Baseline |
| `RULE-SOCK-WILDCARD` | `HIGH` | Socket Exposure | Service Bound to Wildcard Address (0.0.0.0 or ::) |
| `RULE-FW-DEFAULT-POLICY` | `CRITICAL` | Firewall Policy | Missing Default-Deny Inbound Policy in Firewall Ruleset |
| `RULE-FW-OVERPERMISSIVE` | `HIGH` | Firewall Policy | Management Port Exposed to Unrestricted Source IP |
| `RULE-FW-BLANKET-ALLOW` | `CRITICAL` | Firewall Policy | Blanket Inbound Allow Rule Permitting All Traffic |
| `RULE-TLS-EXPIRED` | `CRITICAL` | TLS Security | Endpoint TLS/SSL Certificate Has Expired |
| `RULE-TLS-EXPIRING-SOON` | `HIGH` | TLS Security | TLS/SSL Certificate Expiring Within Warning Threshold |
| `RULE-TLS-WEAK-KEY` | `HIGH` | Cryptography | Insufficient RSA Key Length or ECC Curve Size |
| `RULE-TLS-WEAK-HASH` | `CRITICAL` | Cryptography | Insecure Signature Hash Algorithm Detected (MD5, SHA-1) |

---

## Granular Rule Specifications

### `RULE-SOCK-UNAPPROVED`: Unapproved Listening Network Socket Detected

- **Severity**: `CRITICAL`
- **Category**: `Socket Exposure`
- **Description**: Listening network service detected on a port not listed in approved port baseline.
- **Remediation**: Terminate unapproved service and remove startup daemon configuration.

---

### `RULE-SOCK-BASELINE-DRIFT`: Listening Socket Address Binding Drifted from Baseline

- **Severity**: `HIGH`
- **Category**: `Socket Exposure`
- **Description**: Socket bound to address other than its approved baseline specification.
- **Remediation**: Reconfigure listening service to bind strictly to approved interface address.

---

### `RULE-SOCK-WILDCARD`: Service Bound to Wildcard Address (0.0.0.0 or ::)

- **Severity**: `HIGH`
- **Category**: `Socket Exposure`
- **Description**: Service bound to wildcard address 0.0.0.0 or :: exposing it on all network interfaces.
- **Remediation**: Rebind service strictly to internal private IP or 127.0.0.1.

---

### `RULE-FW-DEFAULT-POLICY`: Missing Default-Deny Inbound Policy in Firewall Ruleset

- **Severity**: `CRITICAL`
- **Category**: `Firewall Policy`
- **Description**: Firewall ruleset lacks default DROP or REJECT policy for inbound traffic.
- **Remediation**: Set default inbound policy to drop in nftables or ufw default deny incoming.

---

### `RULE-FW-OVERPERMISSIVE`: Management Port Exposed to Unrestricted Source IP

- **Severity**: `HIGH`
- **Category**: `Firewall Policy`
- **Description**: Management port (SSH, RDP, database) open to 0.0.0.0/0 without source restrictions.
- **Remediation**: Restrict access to management ports to designated administrator bastion IPs.

---

### `RULE-FW-BLANKET-ALLOW`: Blanket Inbound Allow Rule Permitting All Traffic

- **Severity**: `CRITICAL`
- **Category**: `Firewall Policy`
- **Description**: Firewall rule permits all incoming traffic without port or protocol restriction.
- **Remediation**: Remove blanket allow rule and implement specific port/service allowlist rules.

---

### `RULE-TLS-EXPIRED`: Endpoint TLS/SSL Certificate Has Expired

- **Severity**: `CRITICAL`
- **Category**: `TLS Security`
- **Description**: Live TLS service presents an expired X.509 certificate.
- **Remediation**: Renew and deploy updated TLS certificate immediately to restore trust.

---

### `RULE-TLS-EXPIRING-SOON`: TLS/SSL Certificate Expiring Within Warning Threshold

- **Severity**: `HIGH`
- **Category**: `TLS Security`
- **Description**: TLS certificate validity expires within configured warning threshold (< 30 days).
- **Remediation**: Initiate certificate renewal workflow before expiration deadline.

---

### `RULE-TLS-WEAK-KEY`: Insufficient RSA Key Length or ECC Curve Size

- **Severity**: `HIGH`
- **Category**: `Cryptography`
- **Description**: TLS certificate uses RSA key length < 2048-bit or ECC curve < 224-bit.
- **Remediation**: Reissue certificate with RSA 3072-bit+ or ECDSA P-256 / P-384 key.

---

### `RULE-TLS-WEAK-HASH`: Insecure Signature Hash Algorithm Detected (MD5, SHA-1)

- **Severity**: `CRITICAL`
- **Category**: `Cryptography`
- **Description**: Certificate signed using deprecated MD5 or SHA-1 hash algorithm.
- **Remediation**: Replace certificate with one signed using SHA-256 or stronger digest.

---
