"""Tests for socket auditor and baseline drift detection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lh_net_posture.models import Protocol, Severity, SocketInfo
from lh_net_posture.sockets.auditor import (
    BaselineRule,
    audit_sockets,
    load_baseline,
)


def test_load_baseline_list(tmp_path: Path) -> None:
    """Test loading baseline from flat integer port list."""
    f = tmp_path / "baseline_list.json"
    f.write_text(json.dumps([22, 80, 443]))
    rules = load_baseline(f)
    assert len(rules) == 3
    assert {r.port for r in rules} == {22, 80, 443}


def test_load_baseline_dict_ports(tmp_path: Path) -> None:
    """Test loading baseline from object with approved_ports."""
    f = tmp_path / "baseline_dict.json"
    f.write_text(json.dumps({"approved_ports": [80, 443]}))
    rules = load_baseline(f)
    assert len(rules) == 2
    assert {r.port for r in rules} == {80, 443}


def test_load_baseline_dict_bindings(tmp_path: Path) -> None:
    """Test loading baseline with explicit binding constraints."""
    f = tmp_path / "baseline_bindings.json"
    content = {
        "approved_bindings": [
            {"port": 22, "protocol": "tcp", "address": "127.0.0.1"},
            {"port": 80, "protocol": "tcp", "address": "0.0.0.0"},
        ]
    }
    f.write_text(json.dumps(content))
    rules = load_baseline(f)
    assert len(rules) == 2
    assert rules[0].port == 22
    assert rules[0].address == "127.0.0.1"
    assert rules[0].protocol == Protocol.TCP


def test_load_baseline_protocol_keys(tmp_path: Path) -> None:
    """Test loading baseline structured with tcp/udp keys."""
    f = tmp_path / "baseline_proto.json"
    f.write_text(json.dumps({"tcp": [80, 443], "udp": [53]}))
    rules = load_baseline(f)
    assert len(rules) == 3


def test_load_baseline_string_mapping(tmp_path: Path) -> None:
    """Test loading baseline structured as port-to-name mapping."""
    f = tmp_path / "baseline_map.json"
    f.write_text(json.dumps({"22": "SSH", "80": {"description": "HTTP", "address": "0.0.0.0"}}))
    rules = load_baseline(f)
    assert len(rules) == 2


def test_load_baseline_missing_file() -> None:
    """Test FileNotFoundError for missing baseline file."""
    with pytest.raises(FileNotFoundError):
        load_baseline("/path/does/not/exist.json")


def test_audit_sockets_wildcard_detection() -> None:
    """Test detection of wildcard 0.0.0.0 and :: bindings."""
    socks = [
        SocketInfo(
            protocol=Protocol.TCP,
            local_address="0.0.0.0",
            local_port=22,  # Sensitive management port
            remote_address="0.0.0.0",
            remote_port=0,
            state="0A",
            inode=1001,
            uid=0,
        ),
        SocketInfo(
            protocol=Protocol.TCP,
            local_address="0.0.0.0",
            local_port=80,  # Non-sensitive port
            remote_address="0.0.0.0",
            remote_port=0,
            state="0A",
            inode=1002,
            uid=33,
        ),
        SocketInfo(
            protocol=Protocol.TCP,
            local_address="127.0.0.1",
            local_port=5432,
            remote_address="0.0.0.0",
            remote_port=0,
            state="0A",
            inode=1003,
            uid=999,
        ),
    ]

    report = audit_sockets(socks, baseline_rules=None)
    # Wildcard on 22 should be HIGH severity
    finding_22 = next(f for f in report.findings if f.metadata.get("port") == 22)
    assert finding_22.severity == Severity.HIGH
    assert finding_22.id == "RULE-SOCK-WILDCARD"

    # Wildcard on 80 should be WARNING severity
    finding_80 = next(f for f in report.findings if f.metadata.get("port") == 80)
    assert finding_80.severity == Severity.WARNING

    # 127.0.0.1:5432 is not wildcard, should count as passed check
    assert report.passed_checks == 1


def test_audit_sockets_unapproved_service() -> None:
    """Test unapproved listening port detection against approved baseline."""
    baseline = [BaselineRule(port=80, protocol=Protocol.TCP)]
    socks = [
        SocketInfo(
            protocol=Protocol.TCP,
            local_address="127.0.0.1",
            local_port=22,  # Not in baseline!
            remote_address="0.0.0.0",
            remote_port=0,
            state="0A",
            inode=1001,
            uid=0,
        ),
        SocketInfo(
            protocol=Protocol.TCP,
            local_address="127.0.0.1",
            local_port=80,  # In baseline!
            remote_address="0.0.0.0",
            remote_port=0,
            state="0A",
            inode=1002,
            uid=33,
        ),
    ]

    report = audit_sockets(socks, baseline_rules=baseline)
    unapproved = [f for f in report.findings if f.id == "RULE-SOCK-UNAPPROVED"]
    assert len(unapproved) == 1
    assert unapproved[0].metadata["port"] == 22
    assert report.passed_checks == 1


def test_audit_sockets_approved_wildcard() -> None:
    """Test that explicitly approved wildcard bindings pass without findings."""
    baseline = [
        BaselineRule(port=80, protocol=Protocol.TCP, address="0.0.0.0"),
    ]
    socks = [
        SocketInfo(
            protocol=Protocol.TCP,
            local_address="0.0.0.0",
            local_port=80,
            remote_address="0.0.0.0",
            remote_port=0,
            state="0A",
            inode=1001,
            uid=33,
        )
    ]
    report = audit_sockets(socks, baseline_rules=baseline)
    assert len(report.findings) == 0
    assert report.passed_checks == 1


def test_baseline_rule_specific_ip_match() -> None:
    """Test matching against exact specific IP address."""
    rule = BaselineRule(port=8080, address="192.168.1.10")
    sock_match = SocketInfo(
        protocol=Protocol.TCP,
        local_address="192.168.1.10",
        local_port=8080,
        remote_address="0.0.0.0",
        remote_port=0,
        state="0A",
        inode=1,
        uid=0,
    )
    sock_nomatch = SocketInfo(
        protocol=Protocol.TCP,
        local_address="192.168.1.11",
        local_port=8080,
        remote_address="0.0.0.0",
        remote_port=0,
        state="0A",
        inode=2,
        uid=0,
    )
    assert rule.matches(sock_match)
    assert not rule.matches(sock_nomatch)

    """Test baseline drift when address does not match approved binding."""
    baseline = [
        BaselineRule(port=5432, protocol=Protocol.TCP, address="127.0.0.1"),
    ]
    socks = [
        SocketInfo(
            protocol=Protocol.TCP,
            local_address="192.168.1.50",
            local_port=5432,
            remote_address="0.0.0.0",
            remote_port=0,
            state="0A",
            inode=1001,
            uid=999,
        )
    ]

    report = audit_sockets(socks, baseline_rules=baseline)
    drift = [f for f in report.findings if f.id == "RULE-SOCK-BASELINE-DRIFT"]
    assert len(drift) == 1
    assert drift[0].severity == Severity.HIGH
