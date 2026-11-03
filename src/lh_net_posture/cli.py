"""Command-line interface for lh-net-posture exposure auditor."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from lh_net_posture.__version__ import __version__
from lh_net_posture.exporters.dispatcher import export_report
from lh_net_posture.firewall.auditor import audit_firewall_file
from lh_net_posture.models import OutputFormat
from lh_net_posture.sockets.auditor import audit_sockets, load_baseline
from lh_net_posture.sockets.parser import read_proc_sockets
from lh_net_posture.tls.inspector import audit_tls_target

app = typer.Typer(
    name="lh-net",
    help="Asynchronous network exposure auditor by Logihertz Systems OPC Pvt Ltd.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def version_callback(value: bool) -> None:
    """Print tool version and exit."""
    if value:
        console.print(f"[bold blue]lh-net-posture[/bold blue] version [green]{__version__}[/green]")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-v",
            help="Show the version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """Logihertz Network Posture exposure auditor entry point."""


@app.command("audit-sockets")
def cmd_audit_sockets(
    baseline: Annotated[
        Path | None,
        typer.Option(
            "--baseline",
            "-b",
            help="Path to approved port baseline JSON file.",
        ),
    ] = None,
    procfs_root: Annotated[
        Path,
        typer.Option(
            "--procfs-root",
            help="Path to procfs root directory (defaults to /proc).",
            hidden=True,
        ),
    ] = Path("/proc"),
    format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            case_sensitive=False,
            help="Output report format (table, json, sarif).",
        ),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="File path to save the generated report.",
        ),
    ] = None,
) -> None:
    """Audit active listening sockets against wildcard bindings and approved baselines."""
    try:
        baseline_rules = load_baseline(baseline) if baseline else []
    except Exception as exc:
        console.print(f"[bold red]Error loading baseline:[/bold red] {exc}", style="red")
        raise typer.Exit(code=2) from exc

    sockets = read_proc_sockets(procfs_root=procfs_root)
    report = audit_sockets(sockets, baseline_rules=baseline_rules, target=str(procfs_root))

    export_report(report, format=format, output_path=output, console=console)

    if report.has_failures:
        raise typer.Exit(code=1)


@app.command("audit-firewall")
def cmd_audit_firewall(
    config_file: Annotated[
        Path,
        typer.Argument(
            help="Path to UFW or nftables configuration file to audit.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
    format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            case_sensitive=False,
            help="Output report format (table, json, sarif).",
        ),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="File path to save the generated report.",
        ),
    ] = None,
) -> None:
    """Audit UFW and nftables configuration files for policy drift and exposure."""
    try:
        report = audit_firewall_file(config_file)
    except Exception as exc:
        console.print(f"[bold red]Error auditing firewall configuration:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    export_report(report, format=format, output_path=output, console=console)

    if report.has_failures:
        raise typer.Exit(code=1)


@app.command("check-tls")
def cmd_check_tls(
    target: Annotated[
        str,
        typer.Argument(
            help="Target endpoint (host:port) or local PEM certificate file path.",
        ),
    ],
    warn_days: Annotated[
        int,
        typer.Option(
            "--warn-days",
            "-w",
            min=1,
            help="Expiration threshold in days to trigger warnings.",
        ),
    ] = 30,
    format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            case_sensitive=False,
            help="Output report format (table, json, sarif).",
        ),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="File path to save the generated report.",
        ),
    ] = None,
) -> None:
    """Inspect local PEM certificate or remote TLS endpoint for cryptographic posture."""
    report = audit_tls_target(target=target, warn_days=warn_days)

    export_report(report, format=format, output_path=output, console=console)

    if report.has_failures:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
