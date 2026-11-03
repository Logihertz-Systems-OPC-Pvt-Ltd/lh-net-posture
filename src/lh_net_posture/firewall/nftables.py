"""Auditor for nftables firewall configurations."""

from __future__ import annotations

import re
from pathlib import Path

from lh_net_posture.models import ADDR_ANY_IPV4, AuditReport, Finding, Severity
from lh_net_posture.sockets.auditor import SENSITIVE_MANAGEMENT_PORTS

RE_CHAIN_INPUT = re.compile(r"chain\s+([A-Za-z0-9_-]+)\s*\{?", re.IGNORECASE)
RE_HOOK_INPUT = re.compile(r"hook\s+input\b", re.IGNORECASE)
RE_POLICY = re.compile(r"policy\s+([a-zA-Z]+);?", re.IGNORECASE)
RE_DPORT_SINGLE = re.compile(r"(?:tcp|udp)?\s*dport\s+([0-9]+)\b", re.IGNORECASE)
RE_DPORT_SET = re.compile(r"(?:tcp|udp)?\s*dport\s*\{\s*([0-9,\s]+)\s*\}", re.IGNORECASE)
RE_SADDR = re.compile(r"(?:ip|ip6)?\s*saddr\s+(\S+)", re.IGNORECASE)


def _extract_nft_ports(rule: str) -> list[int]:
    """Extract port numbers from an nftables rule line."""
    ports: list[int] = []
    # Check set first: dport { 22, 3389 }
    m_set = RE_DPORT_SET.search(rule)
    if m_set:
        for p in m_set.group(1).split(","):
            p = p.strip()
            if p.isdigit():
                ports.append(int(p))
        return ports

    # Check single dport: dport 22
    for m in RE_DPORT_SINGLE.finditer(rule):
        ports.append(int(m.group(1)))
    return ports


def audit_nftables(file_path: Path, content: str | None = None) -> AuditReport:
    """Audit an nftables configuration file for exposure risks.

    Evaluates:
    - Default input policy (missing default drop)
    - Inbound rules allowing 0.0.0.0/0 on management ports
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
        component="firewall-nftables",
    )

    lines = content.splitlines()
    in_input_chain = False
    brace_depth = 0
    input_chain_brace_depth = -1
    found_hook_input = False
    has_policy_drop = False
    input_chain_line = 1

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Update brace count
        opens = stripped.count("{")
        closes = stripped.count("}")

        if not stripped or stripped.startswith("#"):
            brace_depth += opens - closes
            continue

        # Check chain start
        m_chain = RE_CHAIN_INPUT.search(stripped)
        if m_chain:
            chain_name = m_chain.group(1).lower()
            if "input" in chain_name:
                in_input_chain = True
                input_chain_brace_depth = brace_depth + (1 if "{" in stripped else 0)
                input_chain_line = line_num

        # Check hook input
        if RE_HOOK_INPUT.search(stripped):
            in_input_chain = True
            found_hook_input = True
            input_chain_line = line_num

        # Check policy statement inside input chain
        if in_input_chain:
            m_pol = RE_POLICY.search(stripped)
            if m_pol:
                policy = m_pol.group(1).lower()
                if policy in ("drop", "reject"):
                    has_policy_drop = True
                    report.passed_checks += 1
                else:
                    report.findings.append(
                        Finding(
                            id="RULE-FW-DEFAULT-POLICY",
                            title="Missing Default-Deny Policy in nftables Chain",
                            description=(
                                f"nftables input chain policy is explicitly set to {policy!r} "
                                "instead of drop or reject."
                            ),
                            severity=Severity.CRITICAL,
                            component="firewall-nftables",
                            target=f"{file_path}:{line_num}",
                            recommendation="Configure 'policy drop;' on the input hook chain.",
                            file_path=str(file_path),
                            line_number=line_num,
                        )
                    )

            # Check individual rules in input chain
            if "accept" in stripped.lower():
                # Ignore loopback interface allowances
                if 'iif "lo"' in stripped or "iif lo" in stripped or 'iifname "lo"' in stripped:
                    report.passed_checks += 1
                # Ignore established / related connection tracking
                elif "established" in stripped or "related" in stripped:
                    report.passed_checks += 1
                else:
                    # Check source address
                    m_saddr = RE_SADDR.search(stripped)
                    saddr = m_saddr.group(1) if m_saddr else None
                    is_wildcard = saddr is None or saddr in (
                        "0.0.0.0/0",
                        "::/0",
                        ADDR_ANY_IPV4,
                        "::",
                        "any",
                    )

                    ports = _extract_nft_ports(stripped)

                    if is_wildcard:
                        if not ports:
                            # Rule has accept without dport or source restriction
                            report.findings.append(
                                Finding(
                                    id="RULE-FW-BLANKET-ALLOW",
                                    title="Blanket Inbound Allow Rule in nftables",
                                    description=(
                                        f"nftables input rule on line {line_num} accepts all "
                                        "inbound traffic without port or source restriction."
                                    ),
                                    severity=Severity.CRITICAL,
                                    component="firewall-nftables",
                                    target=f"{file_path}:{line_num}",
                                    recommendation=(
                                        "Restrict inbound rules to required destination ports "
                                        "and trusted CIDRs."
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
                                            title=f"Management Port {p} Exposed to Wildcard",
                                            description=(
                                                f"Inbound rule allows unrestricted wildcard access "
                                                f"to management port {p} ({svc})."
                                            ),
                                            severity=Severity.HIGH,
                                            component="firewall-nftables",
                                            target=f"{file_path}:{line_num}",
                                            recommendation=(
                                                "Specify a trusted source CIDR using "
                                                f"'ip saddr <trusted> tcp dport {p} accept'."
                                            ),
                                            file_path=str(file_path),
                                            line_number=line_num,
                                            metadata={"port": p, "source": saddr or "wildcard"},
                                        )
                                    )
                                else:
                                    report.passed_checks += 1
                    else:
                        report.passed_checks += 1

        brace_depth += opens - closes
        if in_input_chain and brace_depth < input_chain_brace_depth:
            in_input_chain = False

    # If an input chain or hook was found but never declared policy drop
    if (found_hook_input or input_chain_brace_depth > 0) and not has_policy_drop:
        # Check if we already reported an explicit policy finding
        already_reported = any(f.id == "RULE-FW-DEFAULT-POLICY" for f in report.findings)
        if not already_reported:
            report.findings.append(
                Finding(
                    id="RULE-FW-DEFAULT-POLICY",
                    title="Missing Default-Deny Policy in nftables Chain",
                    description=(
                        "nftables input chain does not specify 'policy drop;' (defaults to accept)."
                    ),
                    severity=Severity.CRITICAL,
                    component="firewall-nftables",
                    target=f"{file_path}:{input_chain_line}",
                    recommendation="Add 'policy drop;' to the input hook chain definition.",
                    file_path=str(file_path),
                    line_number=input_chain_line,
                )
            )

    return report
