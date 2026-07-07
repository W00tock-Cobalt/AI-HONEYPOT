"""Scan report formatting and export."""

import json
from dataclasses import asdict
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from sqli_ai.models import ScanReport, Severity


def _indent(text: str, prefix: str = "    ", limit: int = 600) -> str:
    """Indent a multi-line snippet and cap its length for display."""
    text = (text or "").strip()
    if len(text) > limit:
        text = text[:limit] + " …"
    lines = text.splitlines() or ["(empty)"]
    return "\n".join(prefix + ln for ln in lines)


def print_report(report: ScanReport, console: Console | None = None) -> None:
    """Print a human-readable scan report to the console."""
    con = console or Console()

    con.print(Panel.fit(
        f"[bold]Target:[/bold] {report.target_url}\n"
        f"[bold]Requests:[/bold] {report.total_requests}  "
        f"[bold]Duration:[/bold] {report.duration_seconds:.1f}s  "
        f"[bold]LLM:[/bold] {report.llm_model}",
        title="SQLi-AI Scan Report",
        border_style="cyan",
    ))

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

            # Core finding info
            details = (
                f"[bold]Parameter:[/bold]  {f.param} ({f.location.value})\n"
                f"[bold]Type:[/bold]       {f.injection_type.value}\n"
                f"[bold]DB:[/bold]         {f.db_type or 'unknown'}\n"
                f"[bold]Confidence:[/bold] {f.confidence:.0%}\n"
                f"[bold]Payload:[/bold]    {f.payload}\n"
                f"[bold]Evidence:[/bold]   {f.evidence}"
            )

            # Append PoC curl command if available
            if f.poc_curl:
                details += f"\n\n[bold]PoC:[/bold]\n  [cyan]{f.poc_curl}[/cyan]"

            # Before/after evidence — show exactly what the payload changed.
            if f.response_before or f.response_after:
                details += (
                    "\n\n[bold]Response BEFORE[/bold] [dim](baseline)[/dim]:\n"
                    f"[dim]{_indent(f.response_before)}[/dim]"
                    "\n\n[bold]Response AFTER[/bold] [dim](payload injected)[/dim]:\n"
                    f"[yellow]{_indent(f.response_after)}[/yellow]"
                )

            con.print(Panel(
                details,
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
        for line in report.agent_log[-5:]:
            con.print(f"  [dim]{line}[/dim]")


def export_json(report: ScanReport) -> dict[str, Any]:
    """Serialize a ScanReport to a JSON-compatible dict."""

    def _serialize(obj):
        if hasattr(obj, "value"):          # Enum → string
            return obj.value
        if hasattr(obj, "__dataclass_fields__"):  # dataclass → dict
            return {k: _serialize(v) for k, v in asdict(obj).items()}
        if isinstance(obj, list):
            return [_serialize(i) for i in obj]
        if isinstance(obj, dict):
            return {k: _serialize(v) for k, v in obj.items()}
        return obj

    return _serialize(report)


def save_json(report: ScanReport, path: str) -> None:
    """Write a JSON report file."""
    with open(path, "w") as f:
        json.dump(export_json(report), f, indent=2)
