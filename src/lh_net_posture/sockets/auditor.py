# ==============================================================================
# Product:       lh-net-posture (lh-net)
# Module:        src.lh_net_posture.sockets.auditor
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Auditor for active network sockets and baseline drift detection."""

from __future__ import annotations

import json
from pathlib import Path

from lh_net_posture.models import (
    ADDR_ANY_IPV4,
    ADDR_ANY_IPV6,
    AuditReport,
    Finding,
    Protocol,
    Severity,
    SocketInfo,
)
from lh_net_posture.sockets.parser import TCP_STATE_LISTEN

# Standard management, remote access, database, and control-plane ports
SENSITIVE_MANAGEMENT_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    111: "rpcbind",
    135: "RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle DB",
    2375: "Docker Daemon (Unencrypted)",
    2376: "Docker Daemon (TLS)",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    6443: "Kubernetes API Server",
    8080: "HTTP Alternate / Admin Console",
    8443: "HTTPS Alternate / Admin Console",
    8500: "HashiCorp Consul",
    9090: "Prometheus Admin",
    9200: "Elasticsearch HTTP",
    10250: "Kubelet API",
    11211: "Memcached",
    27017: "MongoDB",
}


class BaselineRule:
    """Represents an approved socket baseline configuration."""

    def __init__(
        self,
        port: int,
        protocol: Protocol | None = None,
        address: str | None = None,
        description: str = "",
    ) -> None:
        self.port = port
        self.protocol = protocol
        self.address = address
        self.description = description

    def matches(self, sock: SocketInfo) -> bool:
        """Check if a socket matches this baseline rule."""
        if self.port != sock.local_port:
            return False
        if self.protocol is not None and self.protocol != sock.protocol:
            return False
        if self.address is not None:
            # Normalize address comparison (e.g. localhost matching)
            if self.address in ("127.0.0.1", "::1", "localhost", "loopback"):
                return sock.is_loopback
            if self.address in (ADDR_ANY_IPV4, ADDR_ANY_IPV6, "*", "any"):
                return sock.is_wildcard or True
            if self.address != sock.local_address:
                return False
        return True


def load_baseline(baseline_path: Path | str | None) -> list[BaselineRule]:
    """Load and normalize an approved port baseline from a JSON file.

    Supports multiple JSON schemas:
    - List of port numbers: [22, 80, 443]
    - Object with 'approved_ports': [22, 80, 443]
    - Object with 'approved_bindings': [{"port": 80, "protocol": "tcp", "address": "0.0.0.0"}]
    - Protocol-keyed dictionary: {"tcp": [80, 443], "udp": [53]}
    - Port-to-description mapping: {"22": "SSH", "80": "HTTP"}

    Args:
        baseline_path: Path to baseline JSON file, or None if no baseline provided.

    Returns:
        List of BaselineRule objects.
    """
    if baseline_path is None:
        return []

    path = Path(baseline_path)
    if not path.exists():
        raise FileNotFoundError(f"Baseline file not found: {path}")

    content = path.read_text(encoding="utf-8")
    data = json.loads(content)
    rules: list[BaselineRule] = []

    if isinstance(data, list):
        for item in data:
            if isinstance(item, int):
                rules.append(BaselineRule(port=item))
            elif isinstance(item, dict):
                port = int(item["port"])
                proto = Protocol(item["protocol"].lower()) if "protocol" in item else None
                addr = item.get("address")
                desc = item.get("description", "")
                rules.append(
                    BaselineRule(port=port, protocol=proto, address=addr, description=desc)
                )

    elif isinstance(data, dict):
        if "approved_bindings" in data and isinstance(data["approved_bindings"], list):
            for b in data["approved_bindings"]:
                port = int(b["port"])
                proto = Protocol(b["protocol"].lower()) if "protocol" in b else None
                addr = b.get("address")
                desc = b.get("description", "")
                rules.append(
                    BaselineRule(port=port, protocol=proto, address=addr, description=desc)
                )

        if "approved_ports" in data and isinstance(data["approved_ports"], list):
            for p in data["approved_ports"]:
                rules.append(BaselineRule(port=int(p)))

        for proto_key in ("tcp", "udp"):
            if proto_key in data and isinstance(data[proto_key], list):
                for p in data[proto_key]:
                    rules.append(
                        BaselineRule(
                            port=int(p),
                            protocol=Protocol(proto_key),
                        )
                    )

        # Handle simple string-keyed mappings e.g. {"22": "SSH"}
        for k, v in data.items():
            if k.isdigit() and isinstance(v, (str, dict)):
                port = int(k)
                desc = v if isinstance(v, str) else v.get("description", "")
                addr = v.get("address") if isinstance(v, dict) else None
                rules.append(BaselineRule(port=port, address=addr, description=desc))

    return rules


def audit_sockets(
    sockets: list[SocketInfo],
    baseline_rules: list[BaselineRule] | None = None,
    target: str = "localhost",
) -> AuditReport:
    """Audit active sockets against wildcard exposure and approved baseline.

    Args:
        sockets: List of SocketInfo instances parsed from /proc/net.
        baseline_rules: List of BaselineRule objects, or None.
        target: Target identifier string for reporting.

    Returns:
        AuditReport containing all discovered findings.
    """
    baseline_rules = baseline_rules or []
    has_baseline = len(baseline_rules) > 0

    report = AuditReport(
        tool="lh-net-posture",
        target=target,
        component="sockets",
    )

    # Filter for active listening or bound sockets
    # TCP listening sockets have state '0A'
    # UDP sockets are bound receiver sockets
    listening_sockets: list[SocketInfo] = []
    for s in sockets:
        if s.protocol == Protocol.TCP:
            if s.state == TCP_STATE_LISTEN:
                listening_sockets.append(s)
        elif s.protocol == Protocol.UDP:
            # Remote port 0 indicates listening/bound UDP server
            if s.remote_port == 0 or s.state in ("07", ""):
                listening_sockets.append(s)

    for sock in listening_sockets:
        service_name = SENSITIVE_MANAGEMENT_PORTS.get(sock.local_port, "Unknown service")
        matched_rules = [r for r in baseline_rules if r.matches(sock)]

        # Baseline check
        if has_baseline:
            port_in_baseline = any(r.port == sock.local_port for r in baseline_rules)
            if not port_in_baseline:
                severity = (
                    Severity.CRITICAL
                    if sock.local_port in SENSITIVE_MANAGEMENT_PORTS
                    else Severity.HIGH
                )
                report.findings.append(
                    Finding(
                        id="RULE-SOCK-UNAPPROVED",
                        title=f"Unapproved Listening Service: {sock.binding_str}",
                        description=(
                            f"Socket {sock.binding_str} ({service_name}) is listening but "
                            "is not present in the approved port baseline."
                        ),
                        severity=severity,
                        component="sockets",
                        target=sock.binding_str,
                        recommendation=(
                            f"Terminate unapproved service on port {sock.local_port} or "
                            "update the approved baseline if this exposure is intended."
                        ),
                        metadata={
                            "protocol": sock.protocol.value,
                            "port": sock.local_port,
                            "address": sock.local_address,
                            "uid": sock.uid,
                            "inode": sock.inode,
                        },
                    )
                )
            elif not matched_rules:
                # Port is in baseline, but binding criteria (address/protocol) drifted
                report.findings.append(
                    Finding(
                        id="RULE-SOCK-BASELINE-DRIFT",
                        title=f"Baseline Drift for Port {sock.local_port}",
                        description=(
                            f"Socket {sock.binding_str} ({service_name}) is listening on "
                            f"{sock.local_address}, violating baseline binding constraints."
                        ),
                        severity=Severity.HIGH,
                        component="sockets",
                        target=sock.binding_str,
                        recommendation=(
                            f"Reconfigure the service on port {sock.local_port} to bind strictly "
                            "to its approved address."
                        ),
                        metadata={
                            "protocol": sock.protocol.value,
                            "port": sock.local_port,
                            "address": sock.local_address,
                        },
                    )
                )

        # Wildcard binding check
        if sock.is_wildcard:
            # Check if this wildcard binding was explicitly approved
            wildcard_approved = False
            for r in matched_rules:
                if r.address in (ADDR_ANY_IPV4, ADDR_ANY_IPV6, "*", "any"):
                    wildcard_approved = True
                    break

            if not wildcard_approved:
                is_sensitive = sock.local_port in SENSITIVE_MANAGEMENT_PORTS
                severity = Severity.HIGH if is_sensitive else Severity.WARNING
                report.findings.append(
                    Finding(
                        id="RULE-SOCK-WILDCARD",
                        title=f"Wildcard 0.0.0.0/:: Binding on Port {sock.local_port}",
                        description=(
                            f"Socket {sock.binding_str} ({service_name}) is bound to wildcard "
                            f"address {sock.local_address}, exposing the port on all interfaces."
                        ),
                        severity=severity,
                        component="sockets",
                        target=sock.binding_str,
                        recommendation=(
                            f"Bind {service_name} on port {sock.local_port} to 127.0.0.1 or a "
                            "specific internal interface unless external access is required."
                        ),
                        metadata={
                            "protocol": sock.protocol.value,
                            "port": sock.local_port,
                            "address": sock.local_address,
                            "is_sensitive": is_sensitive,
                        },
                    )
                )
            else:
                report.passed_checks += 1
        elif matched_rules or (not has_baseline and sock.is_loopback):
            report.passed_checks += 1

    return report
