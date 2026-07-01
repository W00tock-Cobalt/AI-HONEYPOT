"""Scan report formatting and export."""

import json
from dataclasses import asdict
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from llmsql.models import ScanReport, Severity


def print_report(report: ScanReport, console: Console | None = None) -> None:
    """Print human-readable scan report."""
    con = console or Console()

    con.print(Panel.fit(
        f"[bold]Target:[/bold] {report.target_url}\n"
        f"[bold]Requests:[/bold] {report.total_requests}  "
        f"[bold]Duration:[/bold] {report.duration_seconds:.1f}s  "
        f"[bold]LLM:[/bold] {report.llm_model}",
        title="LLMSQL Scan Report",
        border_style="cyan",
    ))

    if report.injection_points:
        table = Table(title="Injection Points")
        table.add_column("Parameter")
        table.add_column("Location")
        table.add_column("Original Value")
        for p in report.injection_points:
            table.add_row(p.name, p.location.value, p.original_value[:60])
        con.print(table)

    if report.findings:
        con.print(f"\n[bold red]Found {len(report.findings)} vulnerability/vulnerabilities[/bold red]\n")
        for i, f in enumerate(report.findings, 1):
            color = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "red",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "blue",
                Severity.INFO: "dim",
            }.get(f.severity, "white")
            con.print(Panel(
                f"[bold]Parameter:[/bold] {f.param} ({f.location.value})\n"
                f"[bold]Type:[/bold] {f.injection_type.value}\n"
                f"[bold]Payload:[/bold] {f.payload}\n"
                f"[bold]Confidence:[/bold] {f.confidence:.0%}\n"
                f"[bold]DB:[/bold] {f.db_type or 'unknown'}\n"
                f"[bold]Evidence:[/bold] {f.evidence}",
                title=f"[{color}]Finding #{i} — {f.severity.value.upper()}[/{color}]",
                border_style=color,
            ))
    else:
        con.print("\n[green]No SQL injection vulnerabilities detected.[/green]")

    if report.errors:
        con.print("\n[yellow]Warnings/Errors:[/yellow]")
        for e in report.errors:
            con.print(f"  • {e}")

    if report.agent_log:
        con.print("\n[dim]Agent log:[/dim]")
        for line in report.agent_log[-10:]:
            con.print(f"  [dim]{line}[/dim]")


def export_json(report: ScanReport) -> dict[str, Any]:
    """Export report as JSON-serializable dict."""

    def _serialize(obj):
        if hasattr(obj, "value"):  # Enum
            return obj.value
        if hasattr(obj, "__dataclass_fields__"):
            return {k: _serialize(v) for k, v in asdict(obj).items()}
        if isinstance(obj, list):
            return [_serialize(i) for i in obj]
        if isinstance(obj, dict):
            return {k: _serialize(v) for k, v in obj.items()}
        return obj

    return _serialize(report)


def save_json(report: ScanReport, path: str) -> None:
    """Write report to JSON file."""
    with open(path, "w") as f:
        json.dump(export_json(report), f, indent=2)
