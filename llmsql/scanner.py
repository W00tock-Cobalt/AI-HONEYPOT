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

    extra_h = "".join(
        f' -H "{k}: {v}"'
        for k, v in hdrs.items()
        if k.lower() not in ("user-agent", "accept-encoding", "connection", "host")
    )
    if method == "GET":
        curl = f'curl -si "{url}"{extra_h}'
    else:
        ct = hdrs.get("Content-Type", hdrs.get("content-type", "application/json"))
        body = (exchange.request_body or "").replace("'", "\\'")
        curl = (
            f'curl -si -X {method}{extra_h}'
            f' -H "Content-Type: {ct}"'
            f" --data '{body}'"
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

        # Discover injection points
        points = self.probe.extract_injection_points(
            url, method, data, content_type, extra_headers,
            test_path=self.test_path,
            path_all_segments=self.path_all_segments,
            guess_params=self.guess_params,
        )
        if params:
            allowed = set(params)
            points = [p for p in points if p.name in allowed]

        if not points:
            report.errors.append("No injection points found")
            report.duration_seconds = time.perf_counter() - start
            return report

        report.injection_points = points

        # Baseline request
        baseline = self.probe.send(url, method, data, content_type, extra_headers)
        report.exchanges.append(baseline)
        report.total_requests += 1
        self.on_progress(f"[*] Baseline: HTTP {baseline.status_code} ({baseline.response_time_ms:.0f}ms)")

        # Detect DB/backend offline — tell the user clearly rather than silently
        # returning 0 findings for every payload.
        if self.detector.is_db_offline(baseline):
            report.errors.append(
                f"DB/backend appears OFFLINE ({baseline.response_body[:120].strip()}) — "
                f"SQLi cannot be detected at runtime. Vulnerability may still exist in code."
            )
            self.on_progress(
                f"[!] DB appears OFFLINE — runtime detection not possible on this URL"
            )
            report.duration_seconds = time.perf_counter() - start
            return report

        # Skip dead endpoints — no point fuzzing a route that doesn't exist
        if not self.include_dead and baseline.status_code in (0, 404, 405, 501):
            report.errors.append(
                f"Skipped: baseline HTTP {baseline.status_code} "
                f"(endpoint dead/unroutable; use --include-404 to force)"
            )
            report.duration_seconds = time.perf_counter() - start
            self.on_progress(
                f"[*] Skipping (baseline HTTP {baseline.status_code})"
            )
            return report

        # Skip auth-gated / WAF-blocked baselines — can't test unauthenticated
        if not self.include_dead and baseline.status_code in (401, 403):
            report.errors.append(
                f"Skipped: baseline HTTP {baseline.status_code} "
                f"(auth-gated or WAF-blocked; supply -H 'Authorization: ...' "
                f"or --cookie, or use --include-404 to force)"
            )
            report.duration_seconds = time.perf_counter() - start
            self.on_progress(
                f"[*] Skipping (baseline HTTP {baseline.status_code}, needs auth/bypass)"
            )
            return report

        import concurrent.futures as _cf

        def _test_one(point):
            return self._test_parameter(
                url, method, data, content_type, extra_headers,
                point, baseline, report,
            )

        # Run param tests concurrently — big speed win when there are many params.
        # Cap at 4 workers to avoid hammering the target.
        workers = min(4, len(points))
        if workers > 1 and not self.continue_on_found:
            with _cf.ThreadPoolExecutor(max_workers=workers) as ex:
                futures = {ex.submit(_test_one, p): p for p in points}
                for fut in _cf.as_completed(futures):
                    try:
                        finding = fut.result()
                    except _cf.CancelledError:
                        continue  # skipped after first finding confirmed
                    except Exception as e:
                        report.errors.append(f"Param test error: {e}")
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
        # Quick pre-check: send a single quote before running the full payload suite.
        # If the response is identical to baseline, this param ignores the value.
        # Skip it immediately — avoids 100s of wasted requests on dead params.
        if self._precheck and not self.detector.baseline_already_erroring(baseline):
            star_probe = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload="*",
            )
            report.total_requests += 1
            star_score, _ = self.detector.quick_score(baseline, star_probe)

            if star_score == 0.0 and star_probe.status_code == baseline.status_code:
                return None  # dead param

            quote_probe = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload="'",
            )
            report.total_requests += 1

            # Check SQL errors and status change DIRECTLY — do not rely only on
            # quick_score which may miss unrecognised error patterns.
            quote_errors = self.detector.find_sql_errors(quote_probe.response_body)
            status_changed = quote_probe.status_code != baseline.status_code

            if quote_errors or status_changed:
                pre_score, pre_ev = self.detector.quick_score(baseline, quote_probe)
                evidence = pre_ev or (
                    f"SQL error: {quote_errors[0][:80]}" if quote_errors else
                    f"Status {baseline.status_code} -> {quote_probe.status_code}"
                )
                confidence = max(pre_score, 0.85 if quote_errors else 0.75)
                return self._build_finding(point, quote_probe, baseline, evidence, confidence)

            # No SQL errors and no status change — check if quote is more
            # interesting than '*'. If both give the same body-diff score,
            # this param is just dynamic (returns different content for any value).
            pre_score, pre_ev = self.detector.quick_score(baseline, quote_probe)
            if pre_score <= star_score and pre_score < 0.6:
                return None  # dynamic page, not SQLi-specific

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
                    report.agent_log.append(
                        f"LLM suggested {len(llm_payloads)} payloads for {point.name}"
                    )
            except Exception as e:
                report.errors.append(f"LLM suggest failed for {point.name}: {e}")

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
                injected._expected_sleep_ms = getattr(self, '_sleep_ms', 3000)
            report.exchanges.append(injected)
            report.total_requests += 1

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
                    report.agent_log.append(msg)
                    self.on_progress(f"    [!] {msg}")

            if score > best_score:
                best_score = score
                best_exchange = injected
                best_evidence = evidence

            # Confirmed finding — lower threshold when we have multiple consistent hits
            confirm_threshold = 0.85 if attempts <= 2 else 0.75
            if score >= confirm_threshold:
                finding = self._build_finding(point, injected, baseline, best_evidence, score)
                if not self.continue_on_found:
                    return finding
                # continue_on_found: record but keep probing for other inj types
                if not hasattr(report, '_interim_findings'):
                    report._interim_findings = []
                report._interim_findings.append(finding)
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
                    report.agent_log.append(
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
                        if not self.continue_on_found:
                            return finding
                        if not hasattr(report, '_interim_findings'):
                            report._interim_findings = []
                        report._interim_findings.append(finding)

                    if decision.action == "inject" and decision.payload:
                        if decision.payload not in seen:
                            unique_payloads.append(decision.payload)
                            report.agent_log.append(
                                f"LLM next payload: {decision.payload[:60]}"
                            )

                    if decision.action in ("skip", "done"):
                        break
                except Exception as e:
                    report.errors.append(f"LLM analyze failed: {e}")

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
                    report.errors.append(f"LLM confirm failed: {e}")

            if best_score >= 0.75:
                return self._build_finding(
                    point, best_exchange, baseline, best_evidence, best_score
                )

        # Boolean-blind pair testing — catches blind SQLi that produces no errors.
        # Only run if error-based/timing detection found nothing so far.
        if best_score < 0.7 and not self.fast:
            from llmsql.payloads import BOOLEAN_PAIRS
            for true_pl, false_pl in BOOLEAN_PAIRS[:4]:
                true_ex = self.probe.send(
                    url, method, data, content_type, extra_headers,
                    inject_point=point, payload=true_pl,
                )
                false_ex = self.probe.send(
                    url, method, data, content_type, extra_headers,
                    inject_point=point, payload=false_pl,
                )
                report.total_requests += 2
                score, evidence = self.detector.boolean_blind_score(
                    baseline, true_ex, false_ex
                )
                self.on_progress(
                    f"    [bool] T={true_ex.status_code}/{len(true_ex.response_body)}b "
                    f"F={false_ex.status_code}/{len(false_ex.response_body)}b "
                    f"score={score:.2f}"
                )
                if score >= 0.7:
                    return self._build_finding(
                        point, true_ex, baseline, evidence, score,
                        inj_type=InjectionType.BOOLEAN_BLIND,
                    )

        # If continue_on_found, return the best interim finding (or final one)
        interim = getattr(report, '_interim_findings', [])
        if interim:
            return interim[-1]

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
        # PATH injection: a 4xx response from a modified path segment is just routing
        # (the route doesn't exist), not SQLi. Require an SQL error in the body.
        if point.location.value == "path" and injected.status_code in (400, 404, 405):
            if not self.detector.find_sql_errors(injected.response_body):
                return None

        db = db_hint or self.detector.guess_db_from_errors(injected.response_body)
        itype = inj_type or self.detector.infer_injection_type(baseline, injected, evidence)
        severity = Severity.HIGH if confidence >= 0.8 else Severity.MEDIUM
        poc_curl, poc_req = _build_poc(injected)
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
