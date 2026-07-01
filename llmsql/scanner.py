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
        self.on_progress(f"[*] Found {len(points)} injection point(s)")

        # Baseline request
        baseline = self.probe.send(url, method, data, content_type, extra_headers)
        report.exchanges.append(baseline)
        report.total_requests += 1
        self.on_progress(f"[*] Baseline: HTTP {baseline.status_code} ({baseline.response_time_ms:.0f}ms)")

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

        for point in points:
            self.on_progress(f"\n[+] Testing parameter: {point.name} ({point.location.value})")
            finding = self._test_parameter(
                url, method, data, content_type, extra_headers,
                point, baseline, report,
            )
            if finding:
                report.findings.append(finding)
                self.on_progress(
                    f"[!] VULNERABLE: {point.name} — {finding.injection_type.value} "
                    f"(confidence {finding.confidence:.0%})"
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

        for payload in unique_payloads:
            if attempts >= self.max_attempts:
                break
            attempts += 1

            injected = self.probe.send(
                url, method, data, content_type, extra_headers,
                inject_point=point, payload=payload,
            )
            report.exchanges.append(injected)
            report.total_requests += 1

            score, evidence = self.detector.quick_score(baseline, injected)
            self.on_progress(
                f"    [{attempts}] payload={payload[:40]!r} score={score:.2f} "
                f"HTTP {injected.status_code}"
            )

            if score > best_score:
                best_score = score
                best_exchange = injected
                best_evidence = evidence

            # High-confidence heuristic hit — confirm with LLM if available
            if score >= 0.85:
                return self._build_finding(point, injected, baseline, best_evidence, score)

            # LLM-guided continuation
            if self.use_llm and score >= 0.3:
                try:
                    decision = self.agent.analyze_exchange(
                        baseline, injected, point, score, evidence,
                        attempts, self.max_attempts,
                    )
                    report.agent_log.append(
                        f"{point.name}: {decision.action} — {decision.reasoning[:100]}"
                    )

                    if decision.action == "confirm" and decision.confidence >= 0.7:
                        return self._build_finding(
                            point, injected, baseline,
                            decision.reasoning or evidence,
                            decision.confidence,
                            db_hint=decision.db_hint,
                            inj_type=decision.injection_type,
                        )

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
            if self.use_llm:
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
        db = db_hint or self.detector.guess_db_from_errors(injected.response_body)
        itype = inj_type or self.detector.infer_injection_type(baseline, injected, evidence)
        severity = Severity.HIGH if confidence >= 0.8 else Severity.MEDIUM
        return Finding(
            param=point.name,
            location=point.location,
            injection_type=itype,
            severity=severity,
            payload=injected.payload or "",
            evidence=evidence,
            confidence=confidence,
            db_type=db,
        )

    @staticmethod
    def _map_severity(s: str) -> Severity:
        try:
            return Severity(s.lower())
        except ValueError:
            return Severity.MEDIUM
