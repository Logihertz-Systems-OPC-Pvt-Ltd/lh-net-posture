"""Tests for unified firewall auditor."""

from __future__ import annotations

from pathlib import Path

import pytest

from lh_net_posture.firewall.auditor import audit_firewall_file, detect_firewall_type


def test_detect_firewall_type_nftables(tmp_path: Path) -> None:
    """Test nftables detection by name and content."""
    p1 = tmp_path / "nftables.conf"
    assert detect_firewall_type(p1, "table inet filter {}") == "nftables"

    p2 = tmp_path / "custom.rules"
    assert detect_firewall_type(p2, "table inet filter { chain input {} }") == "nftables"


def test_detect_firewall_type_ufw(tmp_path: Path) -> None:
    """Test UFW detection by name and content."""
    p1 = tmp_path / "user.rules"
    assert detect_firewall_type(p1, "### tuple ### allow tcp 22") == "ufw"

    p2 = tmp_path / "ufw_default"
    assert detect_firewall_type(p2, 'DEFAULT_INPUT_POLICY="DROP"') == "ufw"


def test_audit_firewall_file_not_found() -> None:
    """Test FileNotFoundError when auditing missing firewall configuration."""
    with pytest.raises(FileNotFoundError):
        audit_firewall_file("/nonexistent/firewall.conf")


def test_audit_firewall_file_dispatch(tmp_path: Path) -> None:
    """Test that audit_firewall_file dispatches properly to nftables or ufw."""
    nft_file = tmp_path / "nftables.conf"
    nft_file.write_text("table inet filter { chain input { policy accept; } }")
    rep_nft = audit_firewall_file(nft_file)
    assert rep_nft.component == "firewall-nftables"

    ufw_file = tmp_path / "ufw.conf"
    ufw_file.write_text('DEFAULT_INPUT_POLICY="ACCEPT"')
    rep_ufw = audit_firewall_file(ufw_file)
    assert rep_ufw.component == "firewall-ufw"

