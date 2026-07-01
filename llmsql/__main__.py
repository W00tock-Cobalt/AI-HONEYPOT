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
  %(prog)s -u "http://target/api" --data '{"id":1}' -H "Content-Type: application/json"
  %(prog)s -u "http://target/page?id=1" --no-llm   # heuristic-only mode
  %(prog)s -u "http://target/page?id=1" -p id      # test specific param only
        """,
    )

    # Target (sqlmap-style)
    p.add_argument("-u", "--url", required=True, help="Target URL")
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

    # LLM backend
    p.add_argument("--api-key", help="LLM API key (or OPENAI_API_KEY env)")
    p.add_argument("--base-url", help="OpenAI-compatible API base URL")
    p.add_argument("--model", default="gpt-4o-mini", help="LLM model (default: gpt-4o-mini)")
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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()

    console.print(f"[bold cyan]LLMSQL v{__version__}[/bold cyan] — AI-powered SQL injection scanner\n")

    headers = parse_headers(args.headers)
    cookies = parse_cookies(args.cookie) if args.cookie else {}
    content_type = headers.get("Content-Type") or headers.get("content-type")
    max_attempts = args.max_attempts or level_to_attempts(args.level)
    use_llm = not args.no_llm

    if use_llm and not args.api_key:
        import os
        if not os.getenv("OPENAI_API_KEY"):
            console.print(
                "[yellow]No API key found. Running in heuristic-only mode. "
                "Set OPENAI_API_KEY or pass --api-key for AI-guided scanning.[/yellow]\n"
            )
            use_llm = False

    probe = HttpProbe(
        proxy=args.proxy,
        default_headers={"User-Agent": "llmsql/0.1"},
        cookies=cookies,
    )

    agent = LlmAgent(
        api_key=args.api_key,
        base_url=args.base_url,
        model=args.model,
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

    try:
        report = scanner.scan(
            url=args.url,
            method=args.method,
            data=args.data,
            content_type=content_type,
            extra_headers=headers,
            params=args.params,
        )
    finally:
        probe.close()
        agent.close()

    print_report(report, console)

    if args.output:
        save_json(report, args.output)
        console.print(f"\n[dim]Report saved to {args.output}[/dim]")

    return 1 if report.findings else 0


if __name__ == "__main__":
    sys.exit(main())
