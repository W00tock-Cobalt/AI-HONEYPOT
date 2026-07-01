"""Hybrid SQL injection detection: regex triage + LLM confirmation."""

import re
from typing import Optional

from llmsql.models import HttpExchange, InjectionType
from llmsql.payloads import SQL_ERROR_PATTERNS


class SqlDetector:
    """Fast pattern-based detection before LLM analysis."""

    def __init__(self):
        self._patterns = [re.compile(p, re.IGNORECASE) for p in SQL_ERROR_PATTERNS]

    def find_sql_errors(self, text: str) -> list[str]:
        """Return matched SQL error strings."""
        matches = []
        for pattern in self._patterns:
            for m in pattern.finditer(text):
                matches.append(m.group(0))
        return matches

    def baseline_already_erroring(self, baseline: HttpExchange) -> bool:
        """True when the baseline response itself contains SQL error text."""
        return bool(self.find_sql_errors(baseline.response_body))

    _CONN_REFUSED = re.compile(
        r"ECONNREFUSED|connection refused|connect ECONNREFUSED|"
        r"ETIMEDOUT|ENOTFOUND|socket hang up",
        re.IGNORECASE,
    )

    def is_db_offline(self, exchange: HttpExchange) -> bool:
        """True when the response indicates the DB/backend is unreachable."""
        return bool(self._CONN_REFUSED.search(exchange.response_body))

    def boolean_blind_score(
        self,
        baseline: HttpExchange,
        true_exchange: HttpExchange,
        false_exchange: HttpExchange,
    ) -> tuple[float, str]:
        """
        Compare a true-condition response vs a false-condition response.
        A significant diff between true/false (while both differ from baseline)
        is a strong boolean-blind indicator.
        """
        b_len = len(baseline.response_body)
        t_len = len(true_exchange.response_body)
        f_len = len(false_exchange.response_body)

        if b_len == 0 or t_len == 0 or f_len == 0:
            return 0.0, ""

        # True and false should differ from each other — that's the signal.
        tf_diff = abs(t_len - f_len) / max(t_len, f_len)
        # True should resemble baseline (valid query still returns data).
        tb_diff = abs(t_len - b_len) / max(t_len, b_len)

        if tf_diff > 0.15 and tb_diff < 0.25:
            evidence = (
                f"Boolean blind: true={t_len}b vs false={f_len}b "
                f"({tf_diff:.0%} diff), baseline={b_len}b"
            )
            confidence = min(0.9, 0.5 + tf_diff)
            return confidence, evidence

        return 0.0, ""

    def quick_score(
        self,
        baseline: HttpExchange,
        injected: HttpExchange,
    ) -> tuple[float, str]:
        """
        Quick heuristic score without LLM.
        Returns (score 0-1, evidence string).
        """
        evidence_parts = []
        score = 0.0

        baseline_errors = self.find_sql_errors(baseline.response_body)
        baseline_broken = bool(baseline_errors)

        # SQL errors in injected response.
        # If the baseline is already erroring (e.g. OpenAPI placeholder `test`
        # used as a raw SQL param), only flag when the injected error is
        # *different* from the baseline error — same error = param was already
        # broken before injection, not a new SQLi trigger.
        errors = self.find_sql_errors(injected.response_body)
        if errors:
            if not baseline_broken:
                # Clean baseline → any SQL error is a finding
                score = max(score, 0.85)
                evidence_parts.append(f"SQL error: {errors[0][:120]}")
            else:
                # Baseline already has SQL errors; only flag if the injected
                # error text is materially different (new error appeared)
                new_errors = [e for e in errors if e not in baseline_errors]
                if new_errors:
                    score = max(score, 0.85)
                    evidence_parts.append(f"SQL error (new): {new_errors[0][:120]}")
                # Even with same error text, a status change is suspicious
                elif baseline.status_code != injected.status_code:
                    score = max(score, 0.5)
                    evidence_parts.append(
                        f"SQL error + status change {baseline.status_code}->{injected.status_code}"
                    )

        # Status code change — only meaningful alongside a SQL error in the body.
        # A bare HTTP 500 just means "server crashed on invalid input", which is
        # common for any unexpected value, not specific to SQLi.
        if baseline.status_code != injected.status_code:
            if injected.status_code >= 500 and errors:
                score = max(score, 0.5)
                evidence_parts.append(
                    f"Status {baseline.status_code} -> {injected.status_code}"
                )

        # Significant body length change (boolean blind hint).
        # Only meaningful when the injected response is a success-class status —
        # a 404→404 or 400→400 length diff is just normal error variation, not SQLi.
        base_len = len(baseline.response_body)
        inj_len = len(injected.response_body)
        injected_ok = 200 <= injected.status_code < 300
        baseline_ok = 200 <= baseline.status_code < 300
        if base_len > 0 and injected_ok and baseline_ok:
            ratio = abs(inj_len - base_len) / base_len
            if ratio > 0.3:
                score = max(score, 0.4)
                evidence_parts.append(
                    f"Body length changed {base_len} -> {inj_len} ({ratio:.0%})"
                )

        # Timing anomaly (time-based blind hint).
        # Only use the calibrated threshold on ACTUAL sleep payloads (tagged with
        # _expected_sleep_ms). For other payloads use a high fixed threshold so
        # slow servers don't generate false positives on every request.
        delay = injected.response_time_ms - baseline.response_time_ms
        expected_sleep_ms = getattr(injected, '_expected_sleep_ms', None)
        if expected_sleep_ms is not None and delay > expected_sleep_ms * 0.6:
            score = max(score, 0.8)
            evidence_parts.append(
                f"Time-blind delay +{delay:.0f}ms (expected ~{expected_sleep_ms}ms)"
            )
        elif delay > 4500:
            # High threshold for non-sleep payloads — avoids slow-server false positives
            score = max(score, 0.6)
            evidence_parts.append(f"Unexpected delay +{delay:.0f}ms")

        # Payload reflected with error context
        if injected.payload and injected.payload in injected.response_body:
            if errors:
                score = max(score, 0.9)
                evidence_parts.append("Payload reflected with SQL error")

        return score, "; ".join(evidence_parts) if evidence_parts else ""

    def guess_db_from_errors(self, text: str) -> Optional[str]:
        """Guess database type from error messages."""
        lower = text.lower()
        # Explicit vendor names
        if "mysql" in lower or "mariadb" in lower or "dbd::mysql" in lower:
            return "mysql"
        if "postgresql" in lower or "pg_" in lower or "psql" in lower:
            return "postgresql"
        if "sqlite" in lower:
            return "sqlite"
        if "sql server" in lower or "odbc" in lower or "mssql" in lower:
            return "mssql"
        if "ora-" in lower or "oracle" in lower:
            return "oracle"

        # Signature phrases when the vendor name isn't in the message
        # PostgreSQL / TypeORM / Sequelize wrappers
        if (
            "syntax error at or near" in lower
            or "unterminated quoted" in lower
            or "does not exist" in lower  # relation/column ... does not exist
            or "invalid input syntax for" in lower
            or "queryfailederror" in lower
            or "operator does not exist" in lower
        ):
            return "postgresql"
        # SQLite phrasing
        if (
            "unrecognized token" in lower
            or "no such table" in lower
            or "no such column" in lower
            or "incomplete input" in lower
            or 'syntax error' in lower and 'near "' in lower
        ):
            return "sqlite"
        # MySQL phrasing
        if "you have an error in your sql syntax" in lower:
            return "mysql"
        # MSSQL phrasing
        if "unclosed quotation mark" in lower or "incorrect syntax near" in lower:
            return "mssql"
        # Oracle phrasing
        if "quoted string not properly terminated" in lower:
            return "oracle"
        return None

    def infer_injection_type(
        self,
        baseline: HttpExchange,
        injected: HttpExchange,
        evidence: str,
    ) -> InjectionType:
        """Infer injection type from evidence."""
        lower = evidence.lower()
        if "sql error" in lower or self.find_sql_errors(injected.response_body):
            return InjectionType.ERROR_BASED
        if "delay" in lower or "sleep" in lower or "waitfor" in lower:
            return InjectionType.TIME_BLIND
        if "body length" in lower:
            return InjectionType.BOOLEAN_BLIND
        if "union" in (injected.payload or "").lower():
            return InjectionType.UNION_BASED
        if ";" in (injected.payload or ""):
            return InjectionType.STACKED
        return InjectionType.UNKNOWN
