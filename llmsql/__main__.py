"""
LLMSQL CLI — AI-powered SQL injection scanner.

Usage:
  python -m llmsql -u "http://target/page?id=1"
  python -m llmsql -u "http://target/api" --data '{"user":"admin"}' --header "Content-Type: application/json"
  python -m llmsql -u "http://target/login" --data "user=admin&pass=test" --method POST
"""

import argparse
import sys
from typing import Optional

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

    # Target (sqlmap-style). A bare positional URL also works:
    #   python -m llmsql https://target/
    p.add_argument("target", nargs="?", default=None,
                   help="Target URL (positional; equivalent to -u)")
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
                   help="Mine common param names (query,q,id,search,...) on each URL. "
                        "ON BY DEFAULT; this flag is kept for compatibility.")
    p.add_argument("--no-guess-params", action="store_true",
                   help="Disable common-param mining (organic discovery still runs)")
    p.add_argument("--param-wordlist",
                   help="File of parameter names to guess (implies --guess-params)")
    p.add_argument("--no-organic", dest="organic", action="store_false",
                   default=True,
                   help="Disable organic parameter discovery (mining param names "
                        "from the target's own forms/links/JS/JSON responses). "
                        "On by default so the scanner adapts to any app.")
    p.add_argument("--second-order", action="store_true",
                   help="Test for SECOND-ORDER SQLi: submit a unique marker+quote "
                        "via write endpoints (POST/PUT), then re-read and flag if "
                        "the stored value surfaces in a SQL error later. NOTE: "
                        "writes marker data to the target, so it is opt-in.")
    p.add_argument("--openapi",
                   help="Import an OpenAPI/Swagger spec (URL, file, or site root) "
                        "to discover endpoints WITH their real parameter names")
    p.add_argument("--auto", action="store_true",
                   help="Force smart discovery (Swagger probe + app fingerprint "
                        "+ katana crawl). This is ON BY DEFAULT for a single -u "
                        "target; the flag just forces it on for list/stdin input.")
    p.add_argument("--no-auto", action="store_true",
                   help="Disable the default auto-discovery for a single -u target")
    p.add_argument("--crawl", action="store_true",
                   help="Run katana on each seed target to discover URLs "
                        "(works without --auto; crawls authenticated when a "
                        "--cookie/--login session is set)")
    p.add_argument("--crawl-depth", type=int, default=3,
                   help="katana crawl depth for --auto/--crawl (default: 3)")
    p.add_argument("--brute", action="store_true",
                   help="Brute-force common web/API paths to discover endpoints "
                        "organically (soft-404 aware). On by default in --auto.")
    p.add_argument("--no-brute", action="store_true",
                   help="Disable the default path brute-forcing in --auto mode")
    p.add_argument("--brute-wordlist", metavar="FILE",
                   help="Custom path wordlist for --brute (e.g. a SecLists file); "
                        "merged with the built-in list")
    p.add_argument("--data", help="POST data (form or JSON string)")
    p.add_argument("--method", default="GET",
                   help="HTTP method(s), comma-separated to try several "
                        "(e.g. 'GET,POST'). Default: GET")
    p.add_argument("-H", "--header", action="append", default=[], dest="headers",
                   help="Extra header (Name: Value or Name=Value)")
    p.add_argument("--cookie", help="Cookie string (name=value; name2=value2)")
    p.add_argument("--grab-cookie", nargs="?", const="__FIRST__", metavar="URL",
                   help="Fetch a URL (or the first target) and capture its Set-Cookie "
                        "session cookie, then reuse it for the scan and sqlmap handoff")
    p.add_argument("--login-url", help="POST credentials here to obtain a session cookie")
    p.add_argument("--login-data", help="Login POST body (form or JSON) for --login-url")

    # Authenticated scanning (bearer/JWT token auth)
    p.add_argument("--auth-url",
                   help="Login endpoint to POST credentials to and extract a bearer/JWT "
                        "token for authenticated scanning")
    p.add_argument("--auth-data",
                   help="Credentials body for --auth-url (JSON or form)")
    p.add_argument("--auth-token",
                   help="Use this bearer/JWT token directly (skips login)")
    p.add_argument("--auth-token-path",
                   help="Dotted JSON path to the token in the login response "
                        "(e.g. 'authentication.token'); auto-detected if omitted")
    p.add_argument("--auth-header", default="Authorization",
                   help="Header to carry the token (default: Authorization)")
    p.add_argument("--no-auto-auth", action="store_true",
                   help="Disable automatic authentication for recognized apps "
                        "(e.g. Juice Shop login-SQLi self-auth)")
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
    p.add_argument("--threads", "-t", type=int, default=None,
                   help="Concurrent targets to scan (default: auto — 1 for a "
                        "single target, up to 8 when many targets are discovered)")
    p.add_argument("--fast", action="store_true",
                   help="Skip per-param LLM payload suggestion; heuristics + LLM confirm only "
                        "(much faster with local models like llama3.2)")
    p.add_argument("--no-precheck", action="store_true",
                   help="Disable the quick pre-check that skips params with no response diff "
                        "(default: precheck ON — drops dead params after 1 request)")
    p.add_argument("--payloads", default="sqlmap",
                   choices=["sqlmap", "embedded", "error", "boolean", "union", "time", "stacked"],
                   help="Payload source: 'sqlmap' reads from sqlmap XML library, "
                        "'embedded' uses built-in set, or pick a technique (default: sqlmap)")
    p.add_argument("--sqlmap-data", metavar="DIR",
                   help="Path to sqlmap data/xml/payloads dir (auto-detected if not set)")
    p.add_argument("--sleep", type=int, default=3,
                   help="Sleep seconds for time-based payloads (default: 3)")
    # Default: keep testing every parameter on every URL, even after confirming
    # SQLi, so the FULL set of findings is known before ever asking about sqlmap.
    # --stop-on-first-finding restores the old "stop at the first hit" behavior
    # for faster (but less complete) scans.
    p.add_argument("--continue-on-found", dest="continue_on_found",
                   action="store_true", default=True,
                   help="(default) Keep testing all parameters/URLs to find every "
                        "SQLi point before offering to run sqlmap")
    p.add_argument("--stop-on-first-finding", dest="continue_on_found",
                   action="store_false",
                   help="Stop testing a parameter/URL as soon as one finding is "
                        "confirmed (faster, but may miss additional injection points)")
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

    # nuclei handoff — multi-class DAST breadth on discovered URLs
    p.add_argument("--nuclei", action="store_true",
                   help="After scanning, run nuclei DAST templates on the "
                        "discovered URLs for multi-class coverage (sqli/xss/ssti/...)")
    p.add_argument("--nuclei-tags", default="sqli,dast",
                   help="nuclei -tags to run (default: sqli,dast). e.g. "
                        "'sqli,xss,ssti,lfi,redirect'")
    p.add_argument("--nuclei-args", default="",
                   help="Extra args appended to the nuclei command")
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
    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="Verbose output (repeatable: -v, -vv, -vvv)")
    p.add_argument("--show-response", action="store_true",
                   help="Print a snippet of each injected response (debug detection)")
    p.add_argument("--version", action="version", version=f"llmsql {__version__}")

    return p


def level_to_attempts(level: int) -> int:
    return {1: 5, 2: 8, 3: 15}[level]


def collect_targets(args) -> list[str]:
    """Gather target URLs from -u, a bare positional URL, -l file, and/or stdin."""
    targets: list[str] = []
    # A bare positional URL is treated like -u (standard CLI ergonomics).
    if getattr(args, "target", None) and not args.url:
        args.url = args.target.strip()
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
    keep_urls: set[str] | None = None,
) -> tuple[list[str], dict[str, int]]:
    """
    httpx-style liveness check. Returns (alive_urls, status_map).

    A URL is 'alive' unless it returns a truly-dead status. Note that 405
    (Method Not Allowed) means the endpoint EXISTS but doesn't accept GET —
    that's exactly a POST-only endpoint (e.g. a login route), so it is NOT
    treated as dead. URLs in `keep_urls` (known POST/PUT targets whose GET
    probe is meaningless) are never filtered out.
    """
    import concurrent.futures

    import httpx

    # 405 removed: it means "endpoint exists, wrong method" = alive (POST route).
    dead_statuses = {0, 404, 410, 501}
    keep_urls = keep_urls or set()
    status_map: dict[str, int] = {}

    client_kwargs = {"timeout": timeout, "verify": verify_ssl, "follow_redirects": True}
    if proxy:
        client_kwargs["proxy"] = proxy

    def check(url: str) -> tuple[str, int]:
        try:
            with httpx.Client(**client_kwargs) as c:
                resp = c.get(url, headers=headers or {})
                return url, resp.status_code
        except (httpx.HTTPError, OSError):
            return url, 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        for url, status in ex.map(check, urls):
            status_map[url] = status

    alive = [
        u for u in urls
        if u in keep_urls or status_map.get(u, 0) not in dead_statuses
    ]
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
                    data = dict(parse_qsl(login_data))
                    # CSRF-aware login: GET the login page first (also seeds the
                    # session cookie) and merge any pre-filled hidden fields
                    # (anti-CSRF tokens like DVWA's user_token) that the user's
                    # static --login-data can't know. User-supplied values win.
                    try:
                        page = c.get(login_url, headers=headers or {})
                        from llmsql.param_discovery import hidden_form_fields
                        for k, v in hidden_form_fields(page.text).items():
                            data.setdefault(k, v)
                    except httpx.HTTPError:
                        pass
                    c.post(login_url, data=data, headers=headers or {})
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


_STATIC_EXT = frozenset({
    ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".pdf", ".zip", ".gz",
    ".tar", ".mp4", ".mp3", ".webm", ".wav",
})
_STATIC_SEGS = (
    "/assets/", "/static/", "/images/", "/img/", "/fonts/",
    "/dist/", "/build/", "/vendor/", "/node_modules/",
    "/@ng/",    # Angular internal routes
    "/Trident/", "/Edge/", "/MSIE/",  # browser sniffing paths
    "/%5C/",    # backslash encoded — SPA artifact
)


def _is_static(url: str) -> bool:
    """Return True for static assets that cannot contain SQL injection."""
    from urllib.parse import urlparse
    path = urlparse(url).path.lower()
    ext = path[path.rfind("."):] if "." in path else ""
    if ext in _STATIC_EXT:
        return True
    return any(s in url.lower() for s in _STATIC_SEGS)


def organic_expand_targets(
    targets: list[str],
    headers: dict[str, str],
    console,
    verify_ssl: bool = True,
    proxy: str | None = None,
    timeout: float = 10.0,
    max_seeds: int = 20,
    max_new: int = 120,
    post_extras: dict | None = None,
) -> list[str]:
    """One-pass organic expansion: fetch each seed page and add scan targets it
    points at — GET-form actions pre-filled with fields, query-carrying links,
    and (organically) POST forms with their fields. This lets ``-u https://site``
    reach the login/cart/search/order endpoints a form points to — including CGI
    ``?action=`` forms — without any per-app endpoint list.

    POST forms are registered in ``post_extras`` (url -> (method, body, ct, None))
    so the scanner tests their body params. Bounded: only the first ``max_seeds``
    targets are fetched and at most ``max_new`` URLs are added.
    """
    import httpx

    from llmsql.param_discovery import discover

    existing = set(targets)
    discovered: list[str] = []
    post_extras = post_extras if post_extras is not None else {}
    kwargs: dict = {"timeout": timeout, "verify": verify_ssl, "follow_redirects": True}
    if proxy:
        kwargs["proxy"] = proxy

    seeds = [t for t in targets if not _is_static(t)][:max_seeds]
    with httpx.Client(**kwargs) as c:
        for seed in seeds:
            try:
                resp = c.get(seed, headers=headers or {})
            except (httpx.HTTPError, OSError):
                continue
            ct = resp.headers.get("content-type", "")
            try:
                _names, urls, post_forms = discover(seed, resp.text, ct)
            except Exception:
                continue
            for u in urls:
                if u in existing or _is_static(u) or len(discovered) >= max_new:
                    continue
                existing.add(u)
                discovered.append(u)
            # POST forms → POST scan targets with their fields (organic).
            for furl, fbody, fct in post_forms:
                if furl in existing or len(discovered) >= max_new:
                    continue
                existing.add(furl)
                discovered.append(furl)
                post_extras[furl] = ("POST", fbody, fct, None)

    if discovered:
        n_post = sum(1 for u in discovered if u in post_extras)
        console.print(
            f"[green]✓ Organic crawl found {len(discovered)} extra target(s)[/green] "
            f"[dim](forms/links on the seed page(s); {n_post} POST form(s))[/dim]"
        )
        for u in discovered[:15]:
            tag = " [dim]POST[/dim]" if u in post_extras else ""
            console.print(f"    [cyan]->[/cyan] {u}{tag}")
        if len(discovered) > 15:
            console.print(f"    [dim]... and {len(discovered) - 15} more[/dim]")
    return targets + discovered


def katana_crawl(
    site: str,
    console,
    depth: int = 3,
    headers: dict[str, str] | None = None,
    cookie: str | None = None,
    verbose: bool = False,
    timeout: int = 120,
) -> list[str]:
    """Crawl a site with katana and return discovered (non-static) URLs.

    Passes auth headers/cookie through to katana so authenticated areas are
    crawled too. Returns [] if katana isn't installed or finds nothing.
    """
    import shutil
    if not shutil.which("katana"):
        console.print(
            "[yellow]katana is not installed — cannot crawl.[/yellow] "
            "[dim](https://github.com/projectdiscovery/katana)[/dim]"
        )
        return []

    cmd = ["katana", "-u", site, "-jc", "-silent", "-d", str(depth)]
    for k, v in (headers or {}).items():
        if k.lower() == "user-agent":
            cmd += ["-H", f"User-Agent: {v}"]
        else:
            cmd += ["-H", f"{k}: {v}"]
    if cookie:
        cmd += ["-H", f"Cookie: {cookie}"]

    console.print(f"[*] Crawling with katana (depth {depth})...")
    import subprocess as _sp
    try:
        result = _sp.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        console.print(f"[yellow]katana failed to run: {e}[/yellow]")
        return []

    raw = [l.strip() for l in result.stdout.splitlines() if l.strip()]
    crawled = sorted({u for u in raw if not _is_static(u)})
    filtered = len(raw) - len(crawled)
    if crawled:
        console.print(
            f"[green]✓ katana found {len(crawled)} URL(s)[/green] "
            f"[dim]({filtered} static assets filtered out)[/dim]"
        )
        show_n = crawled if verbose else crawled[:15]
        for u in show_n:
            console.print(f"    [cyan]->[/cyan] {u}")
        if len(show_n) < len(crawled):
            console.print(f"    [dim]... and {len(crawled) - len(show_n)} more (-v to see all)[/dim]")
    else:
        console.print(
            f"[yellow]katana ran but found no usable URLs[/yellow] "
            f"[dim]({len(raw)} raw hits, all static/filtered)[/dim]"
        )
    return crawled


def _auto_discover(args, targets: list[str], console) -> None:
    """
    Smart target discovery for --auto mode. Fully transparent: every step
    prints exactly what it tried and what it found — no silent fallbacks.

    1. Probe common Swagger/OpenAPI spec paths on the site root.
       Prints every path tried and its HTTP status/outcome (verbose: all,
       non-verbose: summary + non-200 count).
    2. If a spec is found: set args.openapi so the spec importer runs.
    3. If not: crawl the site to discover URLs. This step is ONLY labeled
       "katana" if katana actually runs — the discovered URLs are always
       printed (not just a count) so you can see exactly what will be scanned.
    """
    site = targets[0]
    console.print(f"\n[bold]Auto-discovery: {site}[/bold]")

    # ---- Step 1: probe for an OpenAPI/Swagger spec ----------------------
    from llmsql.openapi import COMMON_SPEC_PATHS, load_openapi, last_probe_log
    console.print(f"[*] Probing {len(COMMON_SPEC_PATHS)} common Swagger/OpenAPI paths...")
    try:
        spec_hits = load_openapi(
            site,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
        )
    except Exception as e:
        spec_hits = []
        console.print(f"[yellow]  OpenAPI probe raised an error: {e}[/yellow]")

    if args.verbose:
        for r in last_probe_log:
            tag = "[green]200[/green]" if r.status == 200 else f"[dim]{r.status or 'ERR'}[/dim]"
            console.print(f"    {tag}  {r.path}  [dim]— {r.reason}[/dim]")

    if spec_hits:
        found_path = next((r.path for r in last_probe_log if r.reason == "valid OpenAPI spec found"), "?")
        console.print(
            f"[green]✓ Found OpenAPI/Swagger spec at {found_path}[/green] — "
            f"{len(spec_hits)} endpoint(s) will be imported"
        )
        args.openapi = site
        return

    non200 = sum(1 for r in last_probe_log if r.status != 200)
    blocked = sum(1 for r in last_probe_log if r.status == 403)
    console.print(
        f"[yellow]✗ No OpenAPI/Swagger spec found[/yellow] "
        f"({len(last_probe_log)} paths tried, {non200} non-200 responses"
        + (f", {blocked} returned 403 — target may be blocking automated probes" if blocked else "")
        + ")"
    )
    if not args.verbose:
        console.print("[dim]  (run with -v to see every path + status code tried)[/dim]")

    # ---- Step 1.5: fingerprint well-known vulnerable training apps -------
    # Apps like OWASP Juice Shop deliberately ship with NO OpenAPI spec, and
    # their real endpoints are triggered by client-side JS (search boxes,
    # login forms) that a static crawler often misses. Recognize them and
    # seed their known-vulnerable endpoints directly instead of relying
    # solely on the crawl.
    known_app_seeds: list[tuple] = []  # (method, url, body, content_type)
    try:
        from llmsql.known_apps import KNOWN_APPS, fingerprint, get_seed_urls
        app_id = fingerprint(site)
        if app_id:
            app = KNOWN_APPS[app_id]
            known_app_seeds = get_seed_urls(site, app_id)
            # Expose auth config so main() can auto-authenticate this app
            if app.auth:
                args._known_app_auth = (site, app.auth)
            console.print(
                f"[green]✓ Recognized target as {app.name}[/green] — "
                f"seeding {len(known_app_seeds)} known-vulnerable endpoint(s)"
            )
            for method, url, _, _ in known_app_seeds:
                console.print(f"    [cyan]->[/cyan] {method} {url}")
    except Exception as e:
        console.print(f"[dim]App fingerprinting skipped: {e}[/dim]")

    # ---- Step 2: crawl to discover additional URLs ------------------------
    crawled = katana_crawl(
        site, console,
        depth=getattr(args, "crawl_depth", 3),
        verbose=args.verbose,
    )
    # Record the host so a later --crawl doesn't crawl the same host again.
    from urllib.parse import urlparse as _up_site
    args._crawled_hosts = getattr(args, "_crawled_hosts", set()) | {_up_site(site).netloc}

    # ---- Step 3: organic path brute-forcing (content discovery) ----------
    # Discover injectable endpoints (/api/products/search, /api/.../count, ...)
    # by probing a wordlist — no per-app hardcoding needed. Soft-404 aware so
    # SPAs don't flood us with false hits. On by default in --auto.
    bruted: list[str] = []
    if not getattr(args, "no_brute", False):
        from llmsql.content_discovery import discover_paths
        extra_words = None
        wl = getattr(args, "brute_wordlist", None)
        if wl:
            try:
                with open(wl) as f:
                    extra_words = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
            except OSError as e:
                console.print(f"[yellow]Cannot read --brute-wordlist: {e}[/yellow]")
        try:
            bruted = discover_paths(
                site,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
                extra_words=extra_words,
                on_status=lambda m: console.print(m),
            )
        except Exception as e:
            console.print(f"[yellow]Content discovery failed: {e}[/yellow]")
        if bruted:
            console.print(
                f"[green]✓ Brute-force found {len(bruted)} live path(s)[/green]"
            )
            show_b = bruted if args.verbose else bruted[:15]
            for u in show_b:
                console.print(f"    [cyan]->[/cyan] {u}")
            if len(show_b) < len(bruted):
                console.print(f"    [dim]... and {len(bruted) - len(show_b)} more (-v to see all)[/dim]")

    # ---- Merge: known-app seeds + katana crawl + brute (+ root as last resort) ----
    known_urls = [u for _, u, _, _ in known_app_seeds]
    combined = sorted(set(known_urls) | set(crawled) | set(bruted))
    if not combined:
        console.print("[yellow]Nothing discovered — scanning root only[/yellow]")
        combined = targets

    args._auto_targets = combined
    args._known_app_extras = {
        url: (method, body, ct, None)
        for method, url, body, ct in known_app_seeds
    }
    args.guess_params = True  # crawled URLs rarely expose real params — mine them


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

    # Zero-config defaults: auto-discovery runs automatically for a single -u
    # site (bare scanning) so the user doesn't have to pass --auto every time.
    # It's skipped for list/stdin input (those already come from a crawler) and
    # when an explicit --openapi spec is given, and can be forced with --auto or
    # disabled with --no-auto.
    single_seed = bool(args.url) and not args.url_list and not args.stdin
    auto_on = (
        (args.auto or single_seed)
        and not args.no_auto
        and not args.openapi
        and bool(targets)
    )
    if auto_on:
        _auto_discover(args, targets, console)
        # If auto ran katana it may have replaced targets; re-read
        if hasattr(args, '_auto_targets'):
            targets = args._auto_targets

    # OpenAPI/Swagger import — discover endpoints with their real param names
    # spec_extras maps url -> (method, body, content_type, inject_headers)
    spec_extras: dict[str, tuple[str, Optional[str], Optional[str], Optional[dict]]] = {}

    # Known-app fingerprinting (from --auto) seeds well-known vulnerable
    # endpoints with their method/body — merge those in the same way.
    if hasattr(args, "_known_app_extras"):
        spec_extras.update(args._known_app_extras)

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

    # ---- Authenticated scanning: obtain a bearer/JWT token --------------
    # Priority: explicit --auth-token > --auth-url/--auth-data login >
    # known-app auto-auth (e.g. Juice Shop login-SQLi self-auth).
    from llmsql.auth import obtain_token
    auth_token: Optional[str] = None
    if args.auth_token:
        auth_token = args.auth_token
        console.print("[green]✓[/green] Using supplied auth token")
    elif args.auth_url and args.auth_data:
        console.print(f"[*] Authenticating via {args.auth_url} ...")
        auth_token, msg = obtain_token(
            args.auth_url, args.auth_data, headers=headers,
            token_path=args.auth_token_path, proxy=args.proxy,
        )
        console.print(f"[green]✓[/green] {msg}" if auth_token else f"[yellow]{msg}[/yellow]")
    elif not args.no_auto_auth and hasattr(args, "_known_app_auth"):
        site, (login_path, login_body, tok_path) = args._known_app_auth
        login_url = site.rstrip("/") + login_path
        console.print(f"[*] Auto-authenticating recognized app via {login_url} ...")
        auth_token, msg = obtain_token(
            login_url, login_body, headers=headers,
            token_path=tok_path, proxy=args.proxy,
        )
        if auth_token:
            console.print(
                f"[green]✓ Authenticated[/green] — token obtained, "
                f"authenticated endpoints are now in scope"
            )
        else:
            console.print(f"[yellow]Auto-auth failed: {msg}[/yellow]")

    if auth_token:
        # Attach to every request. Not treated as an injection point
        # (Authorization is in the http_probe skip list).
        headers[args.auth_header] = f"Bearer {auth_token}"

    # Explicit katana crawl (--crawl): crawl each unique HOST ONCE from its root
    # (not once per already-discovered endpoint), authenticated with whatever
    # session we just established. Hosts already crawled by --auto are skipped.
    if args.crawl:
        from urllib.parse import urlparse as _up_crawl
        crawl_headers = dict(headers)
        crawl_headers.setdefault("User-Agent",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120 Safari/537.36")
        already_crawled = getattr(args, "_crawled_hosts", set())
        origins: list[str] = []
        seen_hosts: set[str] = set()
        for t in targets:
            pr = _up_crawl(t)
            if pr.netloc and pr.netloc not in seen_hosts:
                seen_hosts.add(pr.netloc)
                if pr.netloc not in already_crawled:
                    origins.append(f"{pr.scheme}://{pr.netloc}/")
        skipped = len(seen_hosts) - len(origins)
        if skipped:
            console.print(
                f"[dim]--crawl: {skipped} host(s) already crawled by --auto, skipping[/dim]"
            )
        seen_c = set(targets)
        added: list[str] = []
        for origin in origins:
            for u in katana_crawl(
                origin, console, depth=args.crawl_depth,
                headers=crawl_headers, cookie=args.cookie, verbose=args.verbose,
            ):
                if u not in seen_c:
                    seen_c.add(u)
                    added.append(u)
        if added:
            console.print(f"[green]✓ Crawl added {len(added)} new target(s)[/green]")
            targets = targets + added

    # Explicit path brute-forcing (--brute without --auto): discover endpoints
    # organically on each unique host.
    if args.brute and not auto_on:
        from urllib.parse import urlparse as _up_b

        from llmsql.content_discovery import discover_paths
        extra_words = None
        if args.brute_wordlist:
            try:
                with open(args.brute_wordlist) as f:
                    extra_words = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
            except OSError as e:
                console.print(f"[yellow]Cannot read --brute-wordlist: {e}[/yellow]")
        b_headers = dict(headers)
        b_headers.setdefault("User-Agent",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
        seen_hosts_b: set[str] = set()
        seen_b = set(targets)
        added_b: list[str] = []
        for t in list(targets):
            host = _up_b(t).netloc
            if host in seen_hosts_b:
                continue
            seen_hosts_b.add(host)
            root = f"{_up_b(t).scheme}://{host}/"
            for u in discover_paths(
                root, headers=b_headers, proxy=args.proxy,
                extra_words=extra_words, on_status=lambda m: console.print(m),
            ):
                if u not in seen_b:
                    seen_b.add(u)
                    added_b.append(u)
        if added_b:
            console.print(f"[green]✓ Brute-force added {len(added_b)} target(s)[/green]")
            targets = targets + added_b

    # Organic target expansion: crawl the seed page(s) one level to add the
    # forms/links they point at as scan targets. Skipped for large crawl lists
    # (katana/gau already did the crawling) and when --no-organic is set.
    if args.organic and len(targets) <= 20:
        expand_headers = dict(headers)
        expand_headers.setdefault("User-Agent",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120 Safari/537.36")
        targets = organic_expand_targets(
            targets, expand_headers, console,
            proxy=args.proxy, timeout=min(args.timeout, 10.0),
            post_extras=spec_extras,
        )

    # Organic cookie capture: if the target sets a session cookie (CartID,
    # SSOid, PHPSESSID, ...) and the user didn't supply one, grab it and add it
    # as an injection point. Because the precheck APPENDS to the cookie's real
    # value, a structured cookie like "ts:1:11.5:1000" is tested as
    # "ts:1:11.5:1000'", hitting the exact vulnerable field — fully organic,
    # no per-app knowledge. Catches cookie-based SQLi (e.g. unquoted IN()).
    if args.organic and not cookies and targets:
        try:
            _cstr, _jar = grab_cookie(
                targets[0], headers=headers, proxy=args.proxy
            )
        except Exception:
            _jar = {}
        if _jar:
            cookies.update(_jar)
            console.print(
                f"[dim]Organic cookie capture: {', '.join(_jar)} "
                f"(will be tested for injection)[/dim]"
            )

    # Parameter mining wordlist — ON by default (disable with --no-guess-params).
    guess_params = None
    if (not args.no_guess_params) or args.param_wordlist or args.guess_params:
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
        # Never liveness-filter known POST/PUT/PATCH endpoints — a GET probe
        # against them is meaningless (returns 404/405) and would wrongly drop
        # e.g. the login SQLi endpoint before it's ever scanned.
        keep_urls = {
            url for url, extra in spec_extras.items()
            if extra and extra[0] and str(extra[0]).upper() != "GET"
        }
        alive, status_map = probe_alive(
            targets,
            threads=args.probe_threads,
            timeout=min(args.timeout, 8.0),
            headers=probe_headers,
            proxy=args.proxy,
            keep_urls=keep_urls,
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

    # Per-parameter payload budget. Testing the ENTIRE suite (~100+ payloads) on
    # every reacting param explodes a single endpoint into 1000s of requests
    # (e.g. a non-SQL /api/file whose params react to junk). Cap by --level;
    # the dedicated boolean-ratio/UNION/time-based/NoSQL tests cover techniques
    # that the capped seed list might not reach. --max-attempts overrides.
    if _raw_max_attempts:
        max_attempts = _raw_max_attempts
    else:
        level_caps = {1: 20, 2: 40, 3: len(display_payloads)}
        max_attempts = min(len(display_payloads), level_caps.get(args.level, 20))

    console.print(f"[dim]Payloads: {payload_src} | max {max_attempts}/param[/dim]")

    tamper_chain = []
    if args.tamper:
        from llmsql.tamper import AUTO_TAMPER_CHAIN, TAMPERS
        if args.tamper.strip().lower() == "auto":
            tamper_chain = list(AUTO_TAMPER_CHAIN)
        else:
            for name in args.tamper.split(","):
                name = name.strip()
                if name and name in TAMPERS:
                    tamper_chain.append(name)
                elif name:
                    console.print(f"[yellow]Unknown tamper '{name}' (see --list-tamper)[/yellow]")

    # Auto-scale concurrency: 1 for a single target, up to 8 when discovery
    # expanded the run into many targets — unless the user set -t explicitly.
    if args.threads is None:
        args.threads = min(8, max(1, len(targets))) if len(targets) > 1 else 1

    if len(targets) > 1:
        console.print(
            f"[*] {len(targets)} targets queued "
            f"[dim](scanning with {args.threads} thread(s))[/dim]\n"
        )

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
        organic=args.organic,
        second_order=args.second_order,
        on_progress=progress if verbose_progress else lambda m: (
            console.print(m) if m.lstrip().startswith(("[!]", "[*] Scan", "[*] Found")) else None
        ),
    )
    scanner._sleep_ms = args.sleep * 1000
    scanner._precheck = not args.no_precheck
    if tamper_chain:
        console.print(f"[dim]Tamper chain: {', '.join(tamper_chain)}[/dim]")
    if test_path:
        console.print("[dim]Path-segment injection: enabled[/dim]")
    if guess_params:
        console.print(f"[dim]Parameter mining: {len(guess_params)} names per URL[/dim]")
    if args.organic:
        console.print("[dim]Organic discovery: params mined from each response (forms/links/JS/JSON)[/dim]")

    # Methods to try per target. --method may be comma-separated (e.g. GET,POST).
    cli_methods = [m.strip().upper() for m in args.method.split(",") if m.strip()] or ["GET"]

    # A synthetic JSON body for POST/PUT when the user gave no --data and the
    # endpoint has no known spec body — gives body-param injection something
    # to work with (common credential/search/id field names).
    _SYNTH_BODY = (
        '{"id":"1","email":"test@test.com","username":"test","user":"test",'
        '"password":"test","q":"test","search":"test","name":"test"}'
    )

    all_reports = []
    total_findings = 0
    interrupted = False
    try:
        def run_one(target: str):
            # Method/body/headers from OpenAPI or known-app spec if available,
            # otherwise the CLI method list (which may be several methods).
            spec_data = spec_extras.get(target, (None, None, None, None))
            spec_method, spec_body, spec_ct, spec_headers = spec_data
            merged_headers = dict(headers)
            if spec_headers:
                for k, v in spec_headers.items():
                    if k not in merged_headers:
                        merged_headers[k] = v

            # If the spec pins a method for this URL, use only that.
            # Otherwise try every method the user requested.
            methods = [spec_method] if spec_method else cli_methods

            reports = []
            for m in methods:
                if spec_method:
                    body, ct = spec_body, spec_ct
                elif m == "GET":
                    body, ct = None, None
                else:
                    # POST/PUT with no supplied data → synthesize a JSON body
                    body = args.data or _SYNTH_BODY
                    ct = content_type or "application/json"
                reports.append(scanner.scan(
                    url=target,
                    method=m,
                    data=body,
                    content_type=ct,
                    extra_headers=merged_headers if merged_headers else headers,
                    params=args.params,
                ))

            # Merge multi-method reports into one for this target
            merged = reports[0]
            for r in reports[1:]:
                merged.findings.extend(r.findings)
                merged.total_requests += r.total_requests
                merged.errors.extend(r.errors)
            return merged

        if args.threads > 1 and len(targets) > 1:
            import concurrent.futures
            console.print(
                f"[dim]Scanning {len(targets)} targets with {args.threads} threads...[/dim]\n"
            )
            ex = concurrent.futures.ThreadPoolExecutor(max_workers=args.threads)
            futures = {ex.submit(run_one, t): t for t in targets}
            done = 0
            try:
                for fut in concurrent.futures.as_completed(futures):
                    done += 1
                    try:
                        report = fut.result()
                    except Exception as e:
                        # One bad target must never suppress the final summary.
                        console.print(f"[yellow]Target failed: {futures[fut]} — {e}[/yellow]")
                        continue
                    all_reports.append(report)
                    total_findings += len(report.findings)
                    console.print(
                        f"\n[bold]── ({done}/{len(targets)}):[/bold] {report.target_url}"
                    )
                    print_report(report, console)
            except KeyboardInterrupt:
                interrupted = True
                for f in futures:
                    f.cancel()
            finally:
                ex.shutdown(wait=False, cancel_futures=True)
        else:
            try:
                for idx, target in enumerate(targets, 1):
                    if len(targets) > 1:
                        console.print(f"\n[bold]── Target {idx}/{len(targets)}:[/bold] {target}")
                    try:
                        report = run_one(target)
                    except Exception as e:
                        console.print(f"[yellow]Target failed: {target} — {e}[/yellow]")
                        continue
                    all_reports.append(report)
                    total_findings += len(report.findings)
                    print_report(report, console)
            except KeyboardInterrupt:
                interrupted = True
    finally:
        probe.close()
        agent.close()

    if interrupted:
        console.print(
            "\n[yellow]Interrupted — showing the findings collected so far.[/yellow]"
        )
    console.print(
        f"\n[bold green]━━━ Stage 1 complete[/bold green] — "
        f"{len(all_reports)} URL(s) scanned, "
        f"[bold]{total_findings}[/bold] finding(s)"
    )
    # Reconcile DB type per host (one host = one backend). This corrects
    # outlier/unknown guesses and is what sqlmap's --dbms is derived from.
    if total_findings:
        unify_db_types(all_reports, console)
    if total_findings:
        from rich.panel import Panel
        from rich.table import Table
        from urllib.parse import urlparse as _up

        from llmsql.report import _indent

        # Collect unique findings and GROUP THEM BY HOST so the output is linear
        # per site (not interleaved in scan-completion order). Within a host,
        # highest-confidence findings come first.
        seen_sinks: set[tuple[str, str, str]] = set()
        rows: list[tuple] = []  # (host, report, finding)
        deduped = 0
        for r in all_reports:
            host = _up(r.target_url).netloc
            for f in r.findings:
                sink = (host, _up(r.target_url).path, f.param)
                if sink in seen_sinks:
                    deduped += 1
                    continue
                seen_sinks.add(sink)
                rows.append((host, r, f))
        rows.sort(key=lambda t: (t[0], -t[2].confidence, t[2].param))
        unique_findings = [(r, f) for _, r, f in rows]

        tbl = Table(title="Confirmed SQLi Findings", show_lines=False)
        tbl.add_column("Host", style="magenta", no_wrap=False, max_width=32)
        tbl.add_column("Endpoint", no_wrap=False, max_width=42)
        tbl.add_column("Param", style="bold yellow")
        tbl.add_column("Type", style="cyan")
        tbl.add_column("DB", style="green")
        tbl.add_column("Conf")
        prev_host = None
        for host, r, f in rows:
            tbl.add_row(
                host if host != prev_host else "",
                _up(r.target_url).path,
                f.param,
                f.injection_type.value,
                f.db_type or "?",
                f"{f.confidence:.0%}",
            )
            prev_host = host
        console.print(tbl)
        if deduped:
            console.print(
                f"[dim]({deduped} duplicate finding(s) collapsed — same endpoint+param)[/dim]"
            )

        # Per-host breakdown: "found X SQLi for this host".
        from collections import OrderedDict
        per_host: "OrderedDict[str, list]" = OrderedDict()
        for host, r, f in rows:
            per_host.setdefault(host, []).append(f)
        console.print("\n[bold]── Per-host SQLi summary[/bold]")
        for host, flist in per_host.items():
            dbs = sorted({f.db_type for f in flist if f.db_type and f.db_type != "?"})
            db_tag = f" [green]{'/'.join(dbs)}[/green]" if dbs else ""
            params = ", ".join(sorted({f.param for f in flist}))
            console.print(
                f"  [magenta]{host}[/magenta] — [bold]{len(flist)}[/bold] "
                f"SQLi finding(s){db_tag}  [dim]({params})[/dim]"
            )
        from collections import Counter as _Counter
        _types = _Counter(f.injection_type.value for _, _r, f in rows)
        _type_break = ", ".join(f"{t}: {n}" for t, n in _types.most_common())
        console.print(
            f"  [dim]────────[/dim]\n"
            f"  [bold]Total: {len(rows)} finding(s) across {len(per_host)} host(s)[/bold]"
            f"  [dim]({_type_break})[/dim]"
        )

        # Detailed evidence per finding: PoC command + before/after responses so
        # each hit is immediately reproducible and reviewable.
        console.print("\n[bold]── Proof of Concept & evidence[/bold]")
        for i, (r, f) in enumerate(unique_findings, 1):
            body = (
                f"[bold]URL:[/bold]        {f.payload_url or r.target_url}\n"
                f"[bold]Parameter:[/bold]  {f.param} ({f.location.value})\n"
                f"[bold]Type:[/bold]       {f.injection_type.value}   "
                f"[bold]DB:[/bold] {f.db_type or '?'}   "
                f"[bold]Confidence:[/bold] {f.confidence:.0%}\n"
                f"[bold]Payload:[/bold]    {f.payload}\n"
                f"[bold]Evidence:[/bold]   {f.evidence}"
            )
            if f.poc_curl:
                body += f"\n\n[bold]PoC:[/bold]\n  [cyan]{f.poc_curl}[/cyan]"
            if f.response_before or f.response_after:
                body += (
                    "\n\n[bold]Response BEFORE[/bold] [dim](baseline)[/dim]:\n"
                    f"[dim]{_indent(f.response_before)}[/dim]"
                    "\n\n[bold]Response AFTER[/bold] [dim](payload injected)[/dim]:\n"
                    f"[yellow]{_indent(f.response_after)}[/yellow]"
                )
            sev_color = "red" if f.confidence >= 0.8 else "yellow"
            console.print(Panel(
                body,
                title=f"[{sev_color}]PoC #{i} — {f.param} @ {_up(r.target_url).path}[/{sev_color}]",
                border_style=sev_color,
            ))

    if args.output:
        if len(all_reports) == 1:
            save_json(all_reports[0], args.output)
        else:
            _save_multi(all_reports, args.output)
        console.print(f"[dim]LLMSQL report saved to {args.output}[/dim]")

    # Stage 2: sqlmap on confirmed findings ONLY — starts after ALL URLs scanned
    if args.then_sqlmap and not interrupted:
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
                    # Still show the final rollup before returning.
                    print_rollup(all_reports, console)
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
            spec_extras=spec_extras,
        )

    # nuclei DAST breadth on everything we discovered/scanned.
    if args.nuclei and not interrupted:
        nuclei_targets = [r.target_url for r in all_reports] or targets
        run_nuclei(
            nuclei_targets,
            tags=args.nuclei_tags,
            extra_args=args.nuclei_args,
            headers=headers,
            cookie=args.cookie,
            console=console,
            timeout=args.sqlmap_timeout,
        )

    # Final rollup — the last, unambiguous "how many did we find" statement.
    print_rollup(all_reports, console)

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
    spec_extras: Optional[dict] = None,
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
    _spec_extras = spec_extras or {}
    # base_url -> (param_extra, confidence, db_type, method, post_body, content_type)
    best_finding: dict[str, tuple] = {}
    for report in reports:
        raw_parsed = urlparse(report.target_url)
        raw_qs = parse_qs(raw_parsed.query, keep_blank_values=True)
        # Recover method/body from spec_extras if this was a POST finding
        spec_data = _spec_extras.get(report.target_url, (None, None, None, None))
        spec_method, spec_body, spec_ct, _ = spec_data
        for f in report.findings:
            base = report.target_url
            param_extra = ""
            method = spec_method or "GET"
            post_body = spec_body
            post_ct = spec_ct

            if f.location == ParamLocation.QUERY:
                spec_params = {k: v for k, v in raw_qs.items() if k == f.param}
                if not spec_params:
                    spec_params = {f.param: ["1"]}
                clean_url = urlunparse(raw_parsed._replace(
                    query=urlencode({k: v[0] for k, v in spec_params.items()})
                ))
                base = clean_url
                param_extra = f"-p {f.param}"

            elif f.location in (ParamLocation.BODY, ParamLocation.JSON):
                # POST body injection — pass method and data to sqlmap
                param_extra = f"-p {f.param}"
                if not post_body:
                    post_body = f'{{"{f.param}": "1"}}'
                    post_ct = "application/json"
                method = method or "POST"

            elif f.location == ParamLocation.HEADER:
                param_extra = f'-p {f.param} --headers="{f.param}: *"'

            elif f.location == ParamLocation.COOKIE:
                param_extra = f'--cookie="{f.param}=*"'

            elif f.location == ParamLocation.PATH:
                idx = None
                if f.param.startswith("path[") and "]" in f.param:
                    try:
                        idx = int(f.param[5:f.param.index("]")])
                    except ValueError:
                        idx = None
                parsed_p = urlparse(base)
                segs = parsed_p.path.split("/")
                if idx is not None and 0 <= idx < len(segs):
                    segs[idx] = segs[idx] + "*"
                    base = urlunparse(parsed_p._replace(path="/".join(segs)))

            prev = best_finding.get(base)
            if prev is None or f.confidence > prev[1]:
                best_finding[base] = (
                    param_extra, f.confidence, f.db_type,
                    method, post_body, post_ct,
                )

    jobs = [
        (url, d[0], d[2], d[3], d[4], d[5])
        for url, d in best_finding.items()
    ]

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
    for i, (url, extra, db, method, body, ct) in enumerate(jobs, 1):
        db_tag = f"  [dim][{db}][/dim]" if db else ""
        method_tag = f"  [dim]{method}[/dim]" if method and method != "GET" else ""
        console.print(f"  {i}) {url}  [dim]{extra}[/dim]{method_tag}{db_tag}")
    console.print()

    have_sqlmap = shutil.which("sqlmap") is not None
    for i, (url, extra, db, method, body, ct) in enumerate(jobs, 1):
        dbms_flag = f"--dbms={db}" if db else ""
        method_flag = ""
        if method and method.upper() != "GET":
            method_flag = f"--method={method.upper()}"
            if body:
                import shlex
                method_flag += f" --data={shlex.quote(body)}"
        cmd = f"sqlmap -u '{url}' {base_args} {dbms_flag} {method_flag} {sqlmap_args} {extra}{header_args}".strip()
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


def unify_db_types(all_reports, console=None) -> dict[str, str]:
    """Reconcile DB type across findings for each host.

    A single target host is almost always backed by ONE database engine, so
    per-finding DB guesses that disagree (e.g. one endpoint's error text
    happens to look SQLite-ish while the rest are clearly PostgreSQL) are noise.
    We take a confidence-weighted vote per host, pick the dominant engine, and
    rewrite every finding on that host to it. This also backfills findings whose
    DB was '?'/unknown — which is what then feeds sqlmap's --dbms.

    Returns {host: db_type} for the hosts that got a consensus.
    """
    from collections import defaultdict
    from urllib.parse import urlparse

    votes: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for r in all_reports:
        host = urlparse(r.target_url).netloc
        for f in r.findings:
            db = (f.db_type or "").strip().lower()
            if db and db not in ("?", "unknown"):
                votes[host][db] += max(f.confidence, 0.1)

    consensus: dict[str, str] = {}
    for host, dbmap in votes.items():
        if dbmap:
            consensus[host] = max(dbmap, key=lambda k: dbmap[k])

    changed = 0
    for r in all_reports:
        host = urlparse(r.target_url).netloc
        cdb = consensus.get(host)
        if not cdb:
            continue
        for f in r.findings:
            if (f.db_type or "").strip().lower() != cdb:
                f.db_type = cdb
                changed += 1

    if console and consensus:
        for host, db in consensus.items():
            others = sorted(k for k in votes[host] if k != db)
            note = f" (was mixed: {', '.join([db] + others)})" if others else ""
            console.print(
                f"[dim]DB consensus for {host}: [bold]{db}[/bold]{note} — "
                f"unified across findings and passed to sqlmap as --dbms[/dim]"
            )
    return consensus


def print_rollup(all_reports, console) -> None:
    """Print the final rollup: total SQLi, breakdown by injection type, and by
    host. This is intentionally the LAST thing shown so 'how many did we find'
    is unambiguous (e.g. 'Found 10 SQL injection point(s)')."""
    from collections import Counter, OrderedDict
    from urllib.parse import urlparse as _up

    from rich.panel import Panel

    # Dedup to unique sinks (host, path, param) so the count matches the table.
    seen: set[tuple] = set()
    findings: list[tuple] = []  # (host, finding)
    for r in all_reports:
        host = _up(r.target_url).netloc
        for f in r.findings:
            sink = (host, _up(r.target_url).path, f.param)
            if sink in seen:
                continue
            seen.add(sink)
            findings.append((host, f))

    total = len(findings)
    if total == 0:
        console.print(Panel.fit(
            "[bold]No SQL injection points confirmed.[/bold]",
            title="LLMSQL Result", border_style="green",
        ))
        return

    by_type = Counter(f.injection_type.value for _, f in findings)
    hosts = OrderedDict()
    for host, f in findings:
        hosts.setdefault(host, 0)
        hosts[host] += 1

    type_line = "  ".join(f"[cyan]{t}[/cyan]:{n}" for t, n in by_type.most_common())
    host_lines = "\n".join(
        f"  • [magenta]{h}[/magenta]: [bold]{n}[/bold] SQLi" for h, n in hosts.items()
    )
    console.print(Panel.fit(
        f"[bold red]Found {total} SQL injection point(s)[/bold red] "
        f"across [bold]{len(hosts)}[/bold] host(s)\n"
        f"[bold]By type:[/bold] {type_line}\n"
        f"[bold]By host:[/bold]\n{host_lines}",
        title="LLMSQL Result — Rollup", border_style="red",
    ))


def run_nuclei(
    targets: list[str],
    tags: str,
    extra_args: str,
    headers: dict[str, str],
    cookie: str | None,
    console,
    out_file: str = "llmsql-nuclei-urls.txt",
    timeout: int = 0,
) -> int:
    """Run nuclei DAST templates over the discovered URLs for multi-class
    coverage (SQLi/XSS/SSTI/LFI/...). Complements LLMSQL's deep SQLi/NoSQLi:
    LLMSQL does discovery + auth + deep SQLi, nuclei does breadth. Degrades to
    printing the command if nuclei isn't installed."""
    import shutil

    urls = [t for t in targets if t]
    if not urls:
        console.print("[yellow]No URLs to hand to nuclei.[/yellow]")
        return 2
    with open(out_file, "w") as f:
        f.write("\n".join(urls) + "\n")

    header_args = ""
    for k, v in (headers or {}).items():
        if k.lower() != "user-agent":
            header_args += f" -H '{k}: {v}'"
    if cookie:
        header_args += f" -H 'Cookie: {cookie}'"

    cmd = f"nuclei -l {out_file} -dast -tags {tags}{header_args} {extra_args}".strip()
    console.print(
        f"\n[bold cyan]━━━ nuclei DAST[/bold cyan] "
        f"[dim](tags: {tags}, {len(urls)} URL(s))[/dim]"
    )
    console.print(f"[dim]{cmd}[/dim]\n")

    if not shutil.which("nuclei"):
        console.print(
            "[yellow]nuclei not on PATH — command printed above to run manually.[/yellow]\n"
            "[dim]Install: https://github.com/projectdiscovery/nuclei[/dim]"
        )
        return 1
    return launch_sqlmap(cmd, timeout, console)  # reuse the safe subprocess runner


def _save_multi(reports, path: str) -> None:
    """Save multiple scan reports to a single JSON file."""
    import json
    from llmsql.report import export_json
    with open(path, "w") as f:
        json.dump([export_json(r) for r in reports], f, indent=2)


if __name__ == "__main__":
    sys.exit(main())
