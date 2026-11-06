# ==============================================================================
# Product:       lh-net-posture (lh-net)
# Module:        tests.test_firewall_ufw
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Tests for UFW configuration auditor."""

from __future__ import annotations

from pathlib import Path

from lh_net_posture.firewall.ufw import audit_ufw
from lh_net_posture.models import Severity


def test_ufw_default_config_accept(tmp_path: Path) -> None:
    """Test detection of overly permissive DEFAULT_INPUT_POLICY in /etc/default/ufw."""
    f = tmp_path / "ufw_default"
    content = 'DEFAULT_INPUT_POLICY="ACCEPT"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n'
    f.write_text(content, encoding="utf-8")

    report = audit_ufw(f)
    finding = next((f for f in report.findings if f.id == "RULE-FW-DEFAULT-POLICY"), None)
    assert finding is not None
    assert finding.severity == Severity.CRITICAL


def test_ufw_default_config_drop(tmp_path: Path) -> None:
    """Test valid default drop policy in /etc/default/ufw."""
    f = tmp_path / "ufw_default"
    content = 'DEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n'
    f.write_text(content, encoding="utf-8")

    report = audit_ufw(f)
    assert len(report.findings) == 0
    assert report.passed_checks == 1


def test_ufw_user_rules_management_ports(tmp_path: Path) -> None:
    """Test user.rules detecting management ports exposed to 0.0.0.0/0."""
    f = tmp_path / "user.rules"
    content = """\
*filter
:ufw-user-input - [0:0]
### RULES ###
### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 22 -j ACCEPT
### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 80 -j ACCEPT
### tuple ### allow tcp 3389 10.0.0.0/8 any 0.0.0.0/0 in
-A ufw-user-input -s 10.0.0.0/8 -p tcp --dport 3389 -j ACCEPT
COMMIT
"""
    f.write_text(content, encoding="utf-8")

    report = audit_ufw(f)
    mgmt_findings = [f for f in report.findings if f.id == "RULE-FW-OVERPERMISSIVE-MGMT"]
    # Port 22 should be flagged for tuple and/or iptables rule
    ports_flagged = [f.metadata.get("port") for f in mgmt_findings]
    assert 22 in ports_flagged
    # Port 3389 was restricted to 10.0.0.0/8, so it shouldn't be flagged as overly permissive!
    assert 3389 not in ports_flagged


def test_ufw_blanket_allow(tmp_path: Path) -> None:
    """Test detection of blanket allow rules without port restriction."""
    f = tmp_path / "user.rules"
    content = """\
*filter
:ufw-user-input - [0:0]
### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -j ACCEPT
COMMIT
"""
    f.write_text(content, encoding="utf-8")

    report = audit_ufw(f)
    blanket = [f for f in report.findings if f.id == "RULE-FW-BLANKET-ALLOW"]
    assert len(blanket) >= 1
    assert blanket[0].severity == Severity.CRITICAL


def test_ufw_status_output(tmp_path: Path) -> None:
    """Test auditing formatted ufw status output."""
    f = tmp_path / "ufw_status.txt"
    content = """\
Status: active
Logging: on (low)
Default: allow (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
3306                       ALLOW IN    Anywhere
80/tcp                     ALLOW IN    Anywhere
5432                       ALLOW IN    10.1.2.3
"""
    f.write_text(content, encoding="utf-8")

    report = audit_ufw(f)
    # Default policy finding
    assert any(f.id == "RULE-FW-DEFAULT-POLICY" for f in report.findings)

    # Management ports exposed to Anywhere
    mgmt_ports = [
        f.metadata.get("port") for f in report.findings if f.id == "RULE-FW-OVERPERMISSIVE-MGMT"
    ]
    assert 22 in mgmt_ports
    assert 3306 in mgmt_ports
    # 5432 is restricted to 10.1.2.3
    assert 5432 not in mgmt_ports
