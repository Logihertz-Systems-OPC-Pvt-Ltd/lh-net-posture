# ==============================================================================
# Product:       lh-net-posture (lh-net)
# Module:        src.lh_net_posture.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models for lh-net-posture network exposure auditor.

Defines findings, severities, socket information, firewall rules, and audit reports.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Severity classification for audit findings."""

    INFO = "info"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def sarif_level(self) -> str:
        """Map severity to SARIF v2.1.0 level."""
        mapping = {
            Severity.INFO: "note",
            Severity.WARNING: "warning",
            Severity.HIGH: "error",
            Severity.CRITICAL: "error",
        }
        return mapping[self]

    @property
    def rich_color(self) -> str:
        """Color code for Rich terminal rendering."""
        mapping = {
            Severity.INFO: "cyan",
            Severity.WARNING: "yellow",
            Severity.HIGH: "bold dark_orange",
            Severity.CRITICAL: "bold red",
        }
        return mapping[self]


class OutputFormat(StrEnum):
    """Supported output formats."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


class Protocol(StrEnum):
    """Network transport protocol."""

    TCP = "tcp"
    UDP = "udp"


ADDR_ANY_IPV4 = "0.0.0.0"  # nosec B104
ADDR_ANY_IPV6 = "::"
WILDCARD_ADDRESSES = frozenset({ADDR_ANY_IPV4, ADDR_ANY_IPV6})


@dataclass(frozen=True)
class SocketInfo:
    """Represents an active network socket parsed from /proc/net."""

    protocol: Protocol
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str
    inode: int
    uid: int
    is_ipv6: bool = False

    @property
    def is_wildcard(self) -> bool:
        """Determine if socket binds to all interfaces."""
        return self.local_address in WILDCARD_ADDRESSES

    @property
    def is_loopback(self) -> bool:
        """Determine if socket binds strictly to localhost."""
        return self.local_address.startswith("127.") or self.local_address == "::1"

    @property
    def binding_str(self) -> str:
        """Human-readable binding string."""
        return f"{self.protocol.value}:{self.local_address}:{self.local_port}"


@dataclass
class Finding:
    """A single security finding discovered during an audit."""

    id: str
    title: str
    description: str
    severity: Severity
    component: str
    target: str
    recommendation: str
    metadata: dict[str, Any] = field(default_factory=dict)
    file_path: str | None = None
    line_number: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary representation."""
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class AuditReport:
    """Comprehensive report summarizing an audit run."""

    tool: str = "lh-net-posture"
    version: str = "0.1.0"
    target: str = "local"
    component: str = "general"
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    findings: list[Finding] = field(default_factory=list)
    passed_checks: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        """Number of critical findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Number of high severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def warning_count(self) -> int:
        """Number of warning severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    @property
    def info_count(self) -> int:
        """Number of info severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def total_findings(self) -> int:
        """Total number of findings."""
        return len(self.findings)

    @property
    def has_failures(self) -> bool:
        """Determine if high or critical findings exist."""
        return (self.critical_count + self.high_count) > 0

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary representation."""
        return {
            "tool": self.tool,
            "version": self.version,
            "target": self.target,
            "component": self.component,
            "timestamp": self.timestamp,
            "summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "warning": self.warning_count,
                "info": self.info_count,
                "total": self.total_findings,
                "passed": self.passed_checks,
            },
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
        }
