# ==============================================================================
# Product:       lh-net-posture (lh-net)
# Module:        src.lh_net_posture.firewall.ufw
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Auditor for UFW (Uncomplicated Firewall) configurations."""

from __future__ import annotations

import re
from pathlib import Path

from lh_net_posture.models import ADDR_ANY_IPV4, AuditReport, Finding, Severity
from lh_net_posture.sockets.auditor import SENSITIVE_MANAGEMENT_PORTS

# Regex helpers for UFW configuration formats
RE_DEFAULT_INPUT = re.compile(
    r'^\s*DEFAULT_INPUT_POLICY\s*=\s*["\']?([A-Za-z]+)["\']?', re.IGNORECASE
)
RE_STATUS_DEFAULT = re.compile(r"Default:\s*([a-zA-Z]+)\s*\(incoming\)", re.IGNORECASE)
RE_IPTABLES_INPUT = re.compile(r"-A\s+ufw-user-input\s+(.*?)-j\s+([A-Za-z]+)", re.IGNORECASE)
RE_TUPLE_RULE = re.compile(
    r"^###\s*tuple\s*###\s*([a-zA-Z]+)\s+([a-zA-Z0-9]+)\s+([0-9:,]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(in|out)",
    re.IGNORECASE,
)
RE_STATUS_RULE = re.compile(r"^\s*([0-9]+(?:/[a-z]+)?)\s+(ALLOW(?:\s+IN)?)\s+(\S+)", re.IGNORECASE)


def _extract_ports(port_str: str) -> list[int]:
    """Extract individual integer ports from single port or comma-separated string."""
    ports: list[int] = []
    # Strip protocol if present e.g. "22/tcp"
    clean_str = port_str.split("/")[0]
    for part in clean_str.split(","):
        part = part.strip()
        if part.isdigit():
            ports.append(int(part))
    return ports


def audit_ufw(file_path: Path, content: str | None = None) -> AuditReport:
    """Audit a UFW configuration file or status dump.

    Evaluates:
    - Default input policy (missing default-deny / drop)
    - Inbound rules allowing 0.0.0.0/0 or Anywhere on management ports
    - Unrestricted blanket allow inbound rules

    Args:
        file_path: Path to configuration file.
        content: Optional string content override (used for testing).

    Returns:
        AuditReport containing discovered findings.
    """
    if content is None:
        content = file_path.read_text(encoding="utf-8", errors="replace")

    report = AuditReport(
        tool="lh-net-posture",
        target=str(file_path),
        component="firewall-ufw",
    )

    lines = content.splitlines()
    has_default_input_declaration = False
    default_input_deny = False

    for line_num, line in enumerate(lines, start=1):
        line_str = line.strip()
        if not line_str or line_str.startswith("#") and not line_str.startswith("### tuple"):
            continue

        # Check DEFAULT_INPUT_POLICY in /etc/default/ufw
        m_default = RE_DEFAULT_INPUT.search(line_str)
        if m_default:
            has_default_input_declaration = True
            policy = m_default.group(1).upper()
            if policy in ("DROP", "REJECT"):
                default_input_deny = True
                report.passed_checks += 1
            else:
                report.findings.append(
                    Finding(
                        id="RULE-FW-DEFAULT-POLICY",
                        title="Missing Default-Deny Inbound Policy in UFW",
                        description=(
                            f"UFW DEFAULT_INPUT_POLICY is set to {policy!r} "
                            "instead of DROP or REJECT."
                        ),
                        severity=Severity.CRITICAL,
                        component="firewall-ufw",
                        target=f"{file_path}:{line_num}",
                        recommendation='Set DEFAULT_INPUT_POLICY="DROP" in /etc/default/ufw.',
                        file_path=str(file_path),
                        line_number=line_num,
                    )
                )

        # Check status output default line e.g. "Default: deny (incoming)..."
        m_status_def = RE_STATUS_DEFAULT.search(line_str)
        if m_status_def:
            has_default_input_declaration = True
            policy = m_status_def.group(1).lower()
            if policy in ("deny", "reject", "drop"):
                default_input_deny = True
                report.passed_checks += 1
            else:
                report.findings.append(
                    Finding(
                        id="RULE-FW-DEFAULT-POLICY",
                        title="Missing Default-Deny Inbound Policy in UFW",
                        description=(
                            f"UFW inbound default policy is set to {policy!r} instead of deny."
                        ),
                        severity=Severity.CRITICAL,
                        component="firewall-ufw",
                        target=f"{file_path}:{line_num}",
                        recommendation="Run 'ufw default deny incoming' to enforce default-deny.",
                        file_path=str(file_path),
                        line_number=line_num,
                    )
                )

        # Check UFW tuple rule: ### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
        m_tuple = RE_TUPLE_RULE.match(line_str)
        if m_tuple:
            action = m_tuple.group(1).lower()
            proto = m_tuple.group(2).lower()
            port_spec = m_tuple.group(3)
            src_ip = m_tuple.group(4)
            direction = m_tuple.group(7).lower()

            if action == "allow" and direction == "in":
                ports = _extract_ports(port_spec)
                is_wildcard_src = src_ip in ("0.0.0.0/0", "::/0", "any", ADDR_ANY_IPV4)

                if is_wildcard_src:
                    if not ports:
                        report.findings.append(
                            Finding(
                                id="RULE-FW-BLANKET-ALLOW",
                                title="Blanket Inbound Allow Rule in UFW",
                                description=(
                                    f"UFW rule on line {line_num} allows all inbound traffic "
                                    f"from {src_ip}."
                                ),
                                severity=Severity.CRITICAL,
                                component="firewall-ufw",
                                target=f"{file_path}:{line_num}",
                                recommendation=(
                                    "Restrict inbound allow rules to specific required ports."
                                ),
                                file_path=str(file_path),
                                line_number=line_num,
                            )
                        )
                    else:
                        for p in ports:
                            if p in SENSITIVE_MANAGEMENT_PORTS:
                                svc = SENSITIVE_MANAGEMENT_PORTS[p]
                                report.findings.append(
                                    Finding(
                                        id="RULE-FW-OVERPERMISSIVE-MGMT",
                                        title=f"Management Port {p} Exposed to Wildcard in UFW",
                                        description=(
                                            f"Inbound rule allows unrestricted access ({src_ip}) "
                                            f"to sensitive management service {svc} on port {p}."
                                        ),
                                        severity=Severity.HIGH,
                                        component="firewall-ufw",
                                        target=f"{file_path}:{line_num}",
                                        recommendation=(
                                            f"Restrict source IP addresses allowed to access {svc} "
                                            f"(port {p}) using specific bastion or VPN CIDRs."
                                        ),
                                        file_path=str(file_path),
                                        line_number=line_num,
                                        metadata={"port": p, "protocol": proto, "source": src_ip},
                                    )
                                )
                            else:
                                report.passed_checks += 1
                else:
                    report.passed_checks += 1

        # Check iptables-style rules: -A ufw-user-input ... -j ACCEPT
        m_ipt = RE_IPTABLES_INPUT.search(line_str)
        if m_ipt:
            args = m_ipt.group(1)
            target_action = m_ipt.group(2).upper()

            if target_action == "ACCEPT":
                src_match = re.search(r"-s\s+(\S+)", args)
                src = src_match.group(1) if src_match else "0.0.0.0/0"
                is_wildcard_src = src in ("0.0.0.0/0", "::/0", ADDR_ANY_IPV4)

                # Match port
                dport_match = re.search(r"--dport(?:s)?\s+([0-9:,]+)", args)
                if is_wildcard_src:
                    if dport_match:
                        ports = _extract_ports(dport_match.group(1))
                        for p in ports:
                            if p in SENSITIVE_MANAGEMENT_PORTS:
                                svc = SENSITIVE_MANAGEMENT_PORTS[p]
                                report.findings.append(
                                    Finding(
                                        id="RULE-FW-OVERPERMISSIVE-MGMT",
                                        title=f"Management Port {p} Exposed to Wildcard in UFW",
                                        description=(
                                            f"Inbound rule allows unrestricted access ({src}) to "
                                            f"management port {p} ({svc})."
                                        ),
                                        severity=Severity.HIGH,
                                        component="firewall-ufw",
                                        target=f"{file_path}:{line_num}",
                                        recommendation=(
                                            f"Restrict access to port {p} to trusted source IPs."
                                        ),
                                        file_path=str(file_path),
                                        line_number=line_num,
                                        metadata={"port": p, "source": src},
                                    )
                                )
                            else:
                                report.passed_checks += 1
                    else:
                        report.findings.append(
                            Finding(
                                id="RULE-FW-BLANKET-ALLOW",
                                title="Blanket Inbound Allow Rule in UFW",
                                description=f"UFW user-input rule allows all traffic from {src}.",
                                severity=Severity.CRITICAL,
                                component="firewall-ufw",
                                target=f"{file_path}:{line_num}",
                                recommendation="Remove blanket allow rule and restrict by port.",
                                file_path=str(file_path),
                                line_number=line_num,
                            )
                        )

        # Check status table lines e.g. "22/tcp ALLOW IN Anywhere"
        m_stat = RE_STATUS_RULE.match(line_str)
        if m_stat:
            port_spec = m_stat.group(1)
            action = m_stat.group(2).upper()
            src = m_stat.group(3)
            is_wildcard = src.lower() in ("anywhere", "0.0.0.0/0", "::/0", "(v6)")
            if "ALLOW" in action and is_wildcard:
                ports = _extract_ports(port_spec)
                for p in ports:
                    if p in SENSITIVE_MANAGEMENT_PORTS:
                        svc = SENSITIVE_MANAGEMENT_PORTS[p]
                        report.findings.append(
                            Finding(
                                id="RULE-FW-OVERPERMISSIVE-MGMT",
                                title=f"Management Port {p} Exposed to Wildcard in UFW",
                                description=(f"UFW status reports port {p} ({svc}) open to {src}."),
                                severity=Severity.HIGH,
                                component="firewall-ufw",
                                target=f"{file_path}:{line_num}",
                                recommendation=(
                                    f"Restrict port {p} to specific trusted IP addresses."
                                ),
                                file_path=str(file_path),
                                line_number=line_num,
                                metadata={"port": p, "source": src},
                            )
                        )
                    else:
                        report.passed_checks += 1

    # If the file had user rules but was missing any default policy statement:
    if not has_default_input_declaration and (
        "ufw-user-input" in content or "Default:" in content or "DEFAULT_INPUT_POLICY" in content
    ):
        if not default_input_deny:
            report.findings.append(
                Finding(
                    id="RULE-FW-DEFAULT-POLICY",
                    title="Missing Default-Deny Inbound Policy in UFW",
                    description=(
                        "No default DROP/REJECT policy for inbound traffic was found "
                        "in the configuration."
                    ),
                    severity=Severity.CRITICAL,
                    component="firewall-ufw",
                    target=str(file_path),
                    recommendation="Configure default deny policy for incoming connections.",
                    file_path=str(file_path),
                )
            )

    return report
