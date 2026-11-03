"""Rich terminal table renderer for audit findings."""

from __future__ import annotations

import io

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lh_net_posture.models import AuditReport


def render_rich_table(report: AuditReport, console: Console | None = None) -> str:
    """Render an AuditReport as a formatted Rich terminal table.

    Args:
        report: AuditReport to render.
        console: Optional Console instance.

    Returns:
        Rendered string representation.
    """
    buffer = io.StringIO()
    target_console = console or Console(file=buffer, force_terminal=False, width=120)

    # Header title
    title_text = Text()
    title_text.append(" Logihertz Network Exposure Auditor ", style="bold white on blue")
    title_text.append(f" [v{report.version}]", style="dim")
    target_console.print(Panel(title_text, expand=False))

    # Metadata summary
    meta_table = Table(show_header=False, box=None, padding=(0, 2))
    meta_table.add_row("[bold]Target:[/bold]", report.target)
    meta_table.add_row("[bold]Component:[/bold]", report.component)
    meta_table.add_row("[bold]Timestamp:[/bold]", report.timestamp)
    meta_table.add_row(
        "[bold]Passed Checks:[/bold]",
        f"[green]{report.passed_checks}[/green]",
    )
    summary_str = (
        f"[bold red]CRITICAL: {report.critical_count}[/bold red]  |  "
        f"[bold dark_orange]HIGH: {report.high_count}[/bold dark_orange]  |  "
        f"[yellow]WARNING: {report.warning_count}[/yellow]  |  "
        f"[cyan]INFO: {report.info_count}[/cyan]"
    )
    meta_table.add_row("[bold]Findings Summary:[/bold]", summary_str)
    target_console.print(Panel(meta_table, title="Audit Metadata", border_style="dim"))

    if not report.findings:
        pass_banner = Text("✔ No exposure risks or policy violations detected.", style="bold green")
        target_console.print(Panel(pass_banner, border_style="green"))
    else:
        table = Table(
            title=f"Discovered Findings ({len(report.findings)})",
            border_style="dim",
            header_style="bold magenta",
            expand=True,
        )
        table.add_column("Severity", justify="center", width=12)
        table.add_column("Rule ID", justify="left", width=22)
        table.add_column("Target", justify="left", width=22)
        table.add_column("Description", justify="left")
        table.add_column("Recommendation", justify="left", style="dim")

        for f in report.findings:
            sev_badge = Text(f.severity.value.upper(), style=f.severity.rich_color)
            table.add_row(
                sev_badge,
                f.id,
                f.target,
                f.description,
                f.recommendation,
            )

        target_console.print(table)

    output = buffer.getvalue()
    if console is not None and console.file != buffer:
        # If external console passed, ensure it was printed to stdout
        pass
    return output
