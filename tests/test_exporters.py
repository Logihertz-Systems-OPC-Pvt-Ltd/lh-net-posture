"""Tests for table, JSON, and SARIF report exporters."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from lh_net_posture.exporters.dispatcher import export_report
from lh_net_posture.exporters.json_export import export_json
from lh_net_posture.exporters.rich_table import render_rich_table
from lh_net_posture.exporters.sarif_export import export_sarif
from lh_net_posture.models import AuditReport, Finding, OutputFormat, Severity


def _create_sample_report() -> AuditReport:
    """Helper creating an AuditReport with test findings."""
    return AuditReport(
        tool="lh-net-posture",
        version="0.1.0",
        target="0.0.0.0:22",
        component="sockets",
        findings=[
            Finding(
                id="RULE-SOCK-WILDCARD",
                title="Wildcard 0.0.0.0 Binding on Port 22",
                description="Socket tcp:0.0.0.0:22 is bound to wildcard address 0.0.0.0.",
                severity=Severity.HIGH,
                component="sockets",
                target="tcp:0.0.0.0:22",
                recommendation="Bind SSH service strictly to 127.0.0.1.",
                file_path="/proc/net/tcp",
                line_number=2,
            )
        ],
        passed_checks=3,
    )


def test_render_rich_table_with_findings() -> None:
    """Test Rich table rendering with active findings."""
    report = _create_sample_report()
    rendered = render_rich_table(report)

    assert "Logihertz Network Exposure Auditor" in rendered
    assert "RULE-SOCK-WILDCARD" in rendered
    assert "0.0.0.0:22" in rendered
    assert "HIGH" in rendered


def test_render_rich_table_clean() -> None:
    """Test Rich table rendering with zero findings."""
    report = AuditReport(
        tool="lh-net-posture",
        version="0.1.0",
        target="clean-node",
        component="general",
        findings=[],
        passed_checks=5,
    )
    rendered = render_rich_table(report)
    assert "No exposure risks or policy violations detected" in rendered


def test_export_json() -> None:
    """Test exporting report to JSON format."""
    report = _create_sample_report()
    json_str = export_json(report)
    data = json.loads(json_str)

    assert data["tool"] == "lh-net-posture"
    assert data["version"] == "0.1.0"
    assert data["summary"]["high"] == 1
    assert data["summary"]["critical"] == 0
    assert len(data["findings"]) == 1
    assert data["findings"][0]["id"] == "RULE-SOCK-WILDCARD"


def test_export_sarif() -> None:
    """Test exporting report to SARIF v2.1.0 standard format."""
    report = _create_sample_report()
    sarif_str = export_sarif(report)
    sarif_doc = json.loads(sarif_str)

    assert sarif_doc["version"] == "2.1.0"
    assert "sarif-spec" in sarif_doc["$schema"]
    assert len(sarif_doc["runs"]) == 1

    driver = sarif_doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "lh-net-posture"
    rule_ids = [r["id"] for r in driver["rules"]]
    assert "RULE-SOCK-WILDCARD" in rule_ids

    results = sarif_doc["runs"][0]["results"]
    assert len(results) == 1
    res = results[0]
    assert res["ruleId"] == "RULE-SOCK-WILDCARD"
    assert res["level"] == "error"  # HIGH maps to error in SARIF
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 2


def test_export_sarif_custom_rule() -> None:
    """Test SARIF export fallback with a custom uncataloged rule ID."""
    report = AuditReport(
        tool="lh-net-posture",
        version="0.1.0",
        target="custom-target",
        component="custom",
        findings=[
            Finding(
                id="RULE-CUSTOM-999",
                title="Custom Security Warning",
                description="Custom vulnerability detected.",
                severity=Severity.INFO,
                component="custom",
                target="custom-target",
                recommendation="Investigate custom finding.",
            )
        ],
    )
    sarif_str = export_sarif(report)
    doc = json.loads(sarif_str)
    rule_ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
    assert "RULE-CUSTOM-999" in rule_ids


def test_dispatcher_export_to_file(tmp_path: Path) -> None:
    """Test dispatcher writing report to a file on disk."""
    report = _create_sample_report()
    out_file = tmp_path / "report.json"

    export_report(report, format=OutputFormat.JSON, output_path=out_file)
    assert out_file.exists()
    content = json.loads(out_file.read_text(encoding="utf-8"))
    assert content["tool"] == "lh-net-posture"


def test_dispatcher_console_print() -> None:
    """Test dispatcher rendering to console when no output file is provided."""
    report = _create_sample_report()
    console = Console()
    rendered = export_report(report, format=OutputFormat.TABLE, console=console)
    assert "Logihertz" in rendered
