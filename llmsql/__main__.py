"""
LLMSQL CLI — AI-powered SQL injection scanner.

Usage:
  python -m llmsql -u "http://target/page?id=1"
  python -m llmsql -u "http://target/api" --data '{"user":"admin"}' --header "Content-Type: application/json"
  python -m llmsql -u "http://target/login" --data "user=admin&pass=test" --method POST
"""

import argparse
import sys

from rich.console import Console

from llmsql import __version__
from llmsql.agent import LlmAgent
from llmsql.http_probe import HttpProbe
from llmsql.ollama import (
    DEFAULT_OLLAMA_MODEL,
    ensure_ready,
    ollama_base_url,
)
from llmsql.report import print_report, save_json
from llmsql.scanner import Scanner


def parse_headers(header_args: list[str]) -> dict[str, str]:
    headers = {}
    for h in header_args:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
        elif "=" in h:
            k, v = h.split("=", 1)
            headers[k.strip()] = v.strip()
    return headers


def parse_cookies(cookie_str: str) -> dict[str, str]:
    cookies = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="llmsql",
        description="LLMSQL — AI-powered SQL injection scanner (sqlmap alternative)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u "http://testphp.vulnweb.com/artists.php?artist=1"
  %(prog)s -u "http://target/search" --data "q=test" --method POST
  %(prog)s -l urls.txt --only-with-params        # scan a URL list
  katana -u https://target -f qurl -silent | %(prog)s --stdin --only-with-params
  %(prog)s -u "http://target/page?id=1" --model qwen2.5-coder:7b
  %(prog)s -u "http://target/page?id=1" --no-llm          # heuristic-only

Note: a bare host with no ?params has nothing to inject. Crawl first
(katana/gau/hakrawler) to collect parameterized URLs, then pipe them in.
        """,
    )

    # Target (sqlmap-style)
    p.add_argument("-u", "--url", help="Target URL")
    p.add_argument("-l", "--list", dest="url_list",
                   help="File with target URLs, one per line (e.g. katana output)")
    p.add_argument("--stdin", action="store_true",
                   help="Read target URLs from stdin (e.g. katana ... | llmsql --stdin)")
    p.add_argument("--only-with-params", action="store_true",
                   help="Skip URLs that have no injectable parameters (recommended for crawl input)")
    p.add_argument("--data", help="POST data (form or JSON string)")
    p.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    p.add_argument("-H", "--header", action="append", default=[], dest="headers",
                   help="Extra header (Name: Value or Name=Value)")
    p.add_argument("--cookie", help="Cookie string (name=value; name2=value2)")
    p.add_argument("-p", "--param", action="append", dest="params",
                   help="Test only this parameter (repeatable)")
    p.add_argument("--proxy", help="HTTP proxy URL")

    # Scan depth
    p.add_argument("--level", type=int, default=1, choices=[1, 2, 3],
                   help="Test depth: 1=quick, 2=normal, 3=deep (default: 1)")
    p.add_argument("--risk", type=int, default=1, choices=[1, 2, 3],
                   help="Risk: 1=safe payloads, 3=aggressive (default: 1)")
    p.add_argument("--max-attempts", type=int, default=None,
                   help="Max payloads per parameter (default: level-based)")

    # LLM backend — Ollama is default
    p.add_argument("--ollama-host", default=None,
                   help="Ollama host (default: http://127.0.0.1:11434)")
    p.add_argument("--model", default=DEFAULT_OLLAMA_MODEL,
                   help=f"Ollama/LLM model (default: {DEFAULT_OLLAMA_MODEL})")
    p.add_argument("--no-start-ollama", action="store_true",
                   help="Do not auto-start Ollama; expect it already running")
    p.add_argument("--no-pull", action="store_true",
                   help="Do not auto-pull model if missing")
    p.add_argument("--api-key", help="Override API key (for non-Ollama backends)")
    p.add_argument("--base-url", help="Override LLM base URL (skips Ollama default)")
    p.add_argument("--no-llm", action="store_true",
                   help="Heuristic-only mode (no LLM, works offline)")

    # Output
    p.add_argument("-o", "--output", help="Save JSON report to file")
    p.add_argument("--batch", action="store_true", help="Non-interactive mode")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument("--version", action="version", version=f"llmsql {__version__}")

    return p


def level_to_attempts(level: int) -> int:
    return {1: 5, 2: 8, 3: 15}[level]


def collect_targets(args) -> list[str]:
    """Gather target URLs from -u, -l file, and/or stdin."""
    targets: list[str] = []
    if args.url:
        targets.append(args.url.strip())

    if args.url_list:
        try:
            with open(args.url_list) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except OSError as e:
            raise SystemExit(f"Cannot read --list file: {e}")

    if args.stdin or (not sys.stdin.isatty() and not args.url and not args.url_list):
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)

    # De-duplicate while preserving order
    seen = set()
    unique = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


def has_injectable_params(url: str) -> bool:
    """Quick check: does the URL carry query parameters?"""
    from urllib.parse import urlparse
    return bool(urlparse(url).query)


def setup_llm_backend(args, console: Console) -> tuple[bool, str | None, str | None]:
    """
    Prepare LLM backend. Returns (use_llm, base_url, error_message).
    """
    if args.no_llm:
        return False, None, None

    # Explicit remote backend (OpenAI, LiteLLM, etc.)
    if args.base_url:
        import os
        if not args.api_key and not os.getenv("OPENAI_API_KEY"):
            return False, None, (
                "Remote LLM backend requires --api-key or OPENAI_API_KEY. "
                "Omit --base-url to use local Ollama."
            )
        return True, args.base_url.rstrip("/"), None

    # Default: local Ollama background
    host = args.ollama_host
    status = console.print if args.verbose else lambda m: console.print(f"[dim]{m}[/dim]")

    ok, msg = ensure_ready(
        model=args.model,
        host=host,
        auto_start=not args.no_start_ollama,
        auto_pull=not args.no_pull,
        on_status=status,
    )
    if not ok:
        return False, None, msg

    if not args.verbose:
        console.print(f"[green]✓[/green] {msg}")
    return True, ollama_base_url(host), None


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()

    console.print(
        f"[bold cyan]LLMSQL v{__version__}[/bold cyan] — "
        f"AI-powered SQL injection scanner [dim](Ollama backend)[/dim]\n"
    )

    targets = collect_targets(args)
    if not targets:
        console.print(
            "[red]No targets.[/red] Provide one of:\n"
            "  -u \"http://host/page?id=1\"\n"
            "  -l urls.txt            (file of URLs)\n"
            "  --stdin                (pipe URLs in)\n\n"
            "[dim]Tip: a bare host with no parameters has nothing to inject. "
            "Crawl first, e.g.:[/dim]\n"
            "  [dim]katana -u https://target -f qurl -silent | "
            "python -m llmsql --stdin --only-with-params[/dim]"
        )
        return 2

    # For crawl input, it's common to only care about parameterized URLs
    if args.only_with_params:
        before = len(targets)
        targets = [t for t in targets if has_injectable_params(t)]
        skipped = before - len(targets)
        if skipped:
            console.print(f"[dim]Skipped {skipped} URL(s) without query parameters[/dim]")
        if not targets:
            console.print("[yellow]No URLs with parameters to test.[/yellow]")
            return 2

    if len(targets) > 1:
        console.print(f"[*] {len(targets)} targets queued\n")

    headers = parse_headers(args.headers)
    cookies = parse_cookies(args.cookie) if args.cookie else {}
    content_type = headers.get("Content-Type") or headers.get("content-type")
    max_attempts = args.max_attempts or level_to_attempts(args.level)

    use_llm, base_url, llm_error = setup_llm_backend(args, console)
    if llm_error:
        console.print(f"[yellow]{llm_error}[/yellow]")
        console.print("[yellow]Falling back to heuristic-only mode.[/yellow]\n")
        use_llm = False

    probe = HttpProbe(
        proxy=args.proxy,
        default_headers={"User-Agent": "llmsql/0.1"},
        cookies=cookies,
    )

    agent = LlmAgent(
        api_key=args.api_key,
        base_url=base_url,
        model=args.model if use_llm else DEFAULT_OLLAMA_MODEL,
    )

    def progress(msg: str):
        if args.verbose or msg.startswith(("[!]", "[+]", "[*]\n", "[*] Scan")):
            console.print(msg)

    scanner = Scanner(
        agent=agent,
        probe=probe,
        max_attempts_per_param=max_attempts,
        use_llm=use_llm,
        on_progress=progress if args.verbose else lambda m: (
            console.print(m) if m.startswith(("[!]", "[+]", "[*] Scan", "[*] Found")) else None
        ),
    )

    all_reports = []
    total_findings = 0
    try:
        for idx, target in enumerate(targets, 1):
            if len(targets) > 1:
                console.print(f"\n[bold]── Target {idx}/{len(targets)}:[/bold] {target}")
            report = scanner.scan(
                url=target,
                method=args.method,
                data=args.data,
                content_type=content_type,
                extra_headers=headers,
                params=args.params,
            )
            all_reports.append(report)
            total_findings += len(report.findings)
            print_report(report, console)
    finally:
        probe.close()
        agent.close()

    if args.output:
        if len(all_reports) == 1:
            save_json(all_reports[0], args.output)
        else:
            _save_multi(all_reports, args.output)
        console.print(f"\n[dim]Report saved to {args.output}[/dim]")

    if len(targets) > 1:
        console.print(
            f"\n[bold]Summary:[/bold] {len(targets)} targets scanned, "
            f"{total_findings} finding(s)"
        )

    return 1 if total_findings else 0


def _save_multi(reports, path: str) -> None:
    """Save multiple scan reports to a single JSON file."""
    import json
    from llmsql.report import export_json
    with open(path, "w") as f:
        json.dump([export_json(r) for r in reports], f, indent=2)


if __name__ == "__main__":
    sys.exit(main())
