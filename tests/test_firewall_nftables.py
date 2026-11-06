# ==============================================================================
# Product:       lh-net-posture (lh-net)
# Module:        tests.test_firewall_nftables
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Tests for nftables configuration auditor."""

from __future__ import annotations

from pathlib import Path

from lh_net_posture.firewall.nftables import audit_nftables
from lh_net_posture.models import Severity


def test_nftables_policy_drop(tmp_path: Path) -> None:
    """Test nftables configuration with secure default drop policy."""
    f = tmp_path / "nftables.conf"
    content = """\
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;

        ct state established,related accept
        iif "lo" accept
        tcp dport 80 accept
    }
}
"""
    f.write_text(content, encoding="utf-8")

    report = audit_nftables(f)
    assert len(report.findings) == 0
    assert report.passed_checks >= 2


def test_nftables_missing_default_drop(tmp_path: Path) -> None:
    """Test nftables configuration with missing or accept default policy."""
    f = tmp_path / "nftables.conf"
    content = """\
table inet filter {
    chain input {
        type filter hook input priority filter; policy accept;
        tcp dport 80 accept
    }
}
"""
    f.write_text(content, encoding="utf-8")

    report = audit_nftables(f)
    policy_findings = [f for f in report.findings if f.id == "RULE-FW-DEFAULT-POLICY"]
    assert len(policy_findings) == 1
    assert policy_findings[0].severity == Severity.CRITICAL


def test_nftables_overpermissive_management_ports(tmp_path: Path) -> None:
    """Test detection of management ports open to wildcard in nftables."""
    f = tmp_path / "nftables.conf"
    content = """\
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;

        tcp dport 22 accept
        tcp dport { 3389, 5432 } accept
        ip saddr 10.0.0.0/8 tcp dport 2375 accept
    }
}
"""
    f.write_text(content, encoding="utf-8")

    report = audit_nftables(f)
    mgmt_findings = [f for f in report.findings if f.id == "RULE-FW-OVERPERMISSIVE-MGMT"]
    ports = [f.metadata.get("port") for f in mgmt_findings]

    assert 22 in ports
    assert 3389 in ports
    assert 5432 in ports
    # Port 2375 was restricted to 10.0.0.0/8
    assert 2375 not in ports


def test_nftables_blanket_allow(tmp_path: Path) -> None:
    """Test detection of blanket accept rules in nftables."""
    f = tmp_path / "nftables.conf"
    content = """\
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;

        accept
    }
}
"""
    f.write_text(content, encoding="utf-8")

    report = audit_nftables(f)
    blanket = [f for f in report.findings if f.id == "RULE-FW-BLANKET-ALLOW"]
    assert len(blanket) == 1
    assert blanket[0].severity == Severity.CRITICAL
