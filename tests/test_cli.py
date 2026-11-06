# ==============================================================================
# Product:       lh-net-posture (lh-net)
# Module:        tests.test_cli
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Tests for lh-net CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lh_net_posture.__version__ import __version__
from lh_net_posture.cli import app

runner = CliRunner()


def test_cli_version() -> None:
    """Test lh-net --version output."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_cli_help() -> None:
    """Test lh-net --help output."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "audit-sockets" in result.stdout
    assert "audit-firewall" in result.stdout
    assert "check-tls" in result.stdout


def test_cli_audit_sockets(mock_procfs: Path, tmp_path: Path) -> None:
    """Test audit-sockets command with baseline and procfs root."""
    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(json.dumps([80, 443]))

    result = runner.invoke(
        app,
        [
            "audit-sockets",
            "--procfs-root",
            str(mock_procfs),
            "--baseline",
            str(baseline_file),
            "--format",
            "json",
        ],
    )
    # Port 22 in mock_procfs is unapproved, so exit code should be 1
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["tool"] == "lh-net-posture"
    assert data["summary"]["total"] >= 1


def test_cli_audit_sockets_output_file(mock_procfs: Path, tmp_path: Path) -> None:
    """Test audit-sockets saving SARIF output to file."""
    out_file = tmp_path / "sockets_sarif.json"
    result = runner.invoke(
        app,
        [
            "audit-sockets",
            "--procfs-root",
            str(mock_procfs),
            "--format",
            "sarif",
            "--output",
            str(out_file),
        ],
    )
    assert result.exit_code in (0, 1)
    assert out_file.exists()
    sarif = json.loads(out_file.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"


def test_cli_audit_sockets_invalid_baseline(tmp_path: Path) -> None:
    """Test error handling on nonexistent baseline file."""
    result = runner.invoke(
        app,
        [
            "audit-sockets",
            "--baseline",
            "/nonexistent/baseline.json",
        ],
    )
    assert result.exit_code == 2


def test_cli_audit_firewall(tmp_path: Path) -> None:
    """Test audit-firewall command with sample config file."""
    conf = tmp_path / "nftables.conf"
    conf.write_text("table inet filter { chain input { policy drop; tcp dport 22 accept } }")

    out_file = tmp_path / "fw_report.json"
    result = runner.invoke(
        app,
        [
            "audit-firewall",
            str(conf),
            "--format",
            "json",
            "--output",
            str(out_file),
        ],
    )
    # Port 22 open to wildcard triggers HIGH finding -> exit code 1
    assert result.exit_code == 1
    assert out_file.exists()
    report = json.loads(out_file.read_text(encoding="utf-8"))
    assert report["component"] == "firewall-nftables"


def test_cli_audit_firewall_missing_file() -> None:
    """Test audit-firewall on non-existent config file."""
    result = runner.invoke(app, ["audit-firewall", "/missing/conf.rules"])
    assert result.exit_code != 0


def test_cli_check_tls(sample_certs_dir: Path, tmp_path: Path) -> None:
    """Test check-tls command with local PEM certificate."""
    cert_path = sample_certs_dir / "rsa2048.pem"
    out_file = tmp_path / "tls_report.json"

    result = runner.invoke(
        app,
        [
            "check-tls",
            str(cert_path),
            "--warn-days",
            "30",
            "--format",
            "json",
            "--output",
            str(out_file),
        ],
    )
    # Self-signed is WARNING (not high or critical), so exit code is 0
    assert result.exit_code == 0
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["component"] == "tls"
    assert data["metadata"]["key_size_bits"] == 2048
