"""Dispatcher for audit report serialization and export."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from lh_net_posture.exporters.json_export import export_json
from lh_net_posture.exporters.rich_table import render_rich_table
from lh_net_posture.exporters.sarif_export import export_sarif
from lh_net_posture.models import AuditReport, OutputFormat


def render_report(report: AuditReport, format: OutputFormat | str = OutputFormat.TABLE) -> str:
    """Render an AuditReport to a string in the requested format.

    Args:
        report: AuditReport instance.
        format: Target format (table, json, or sarif).

    Returns:
        Formatted string output.
    """
    fmt_str = format.value if isinstance(format, OutputFormat) else str(format).lower()

    if fmt_str == OutputFormat.JSON.value:
        return export_json(report)
    if fmt_str == OutputFormat.SARIF.value:
        return export_sarif(report)
    return render_rich_table(report)


def export_report(
    report: AuditReport,
    format: OutputFormat | str = OutputFormat.TABLE,
    output_path: Path | str | None = None,
    console: Console | None = None,
) -> str:
    """Export AuditReport to stdout or a file.

    Args:
        report: AuditReport instance.
        format: Desired output format (table, json, or sarif).
        output_path: Optional path to destination file.
        console: Optional Rich Console for direct terminal printing.

    Returns:
        Rendered report content string.
    """
    rendered = render_report(report, format=format)

    if output_path is not None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")

    fmt_str = format.value if isinstance(format, OutputFormat) else str(format).lower()

    if output_path is None:
        if fmt_str == OutputFormat.TABLE.value:
            render_rich_table(report, console=console or Console())
        else:
            print(rendered)

    return rendered
