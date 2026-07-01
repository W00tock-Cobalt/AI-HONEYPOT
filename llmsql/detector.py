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

        # SQL errors in injected response
        errors = self.find_sql_errors(injected.response_body)
        if errors:
            score = max(score, 0.85)
            evidence_parts.append(f"SQL error: {errors[0][:120]}")

        # Status code change
        if baseline.status_code != injected.status_code:
            if injected.status_code >= 500:
                score = max(score, 0.5)
                evidence_parts.append(
                    f"Status {baseline.status_code} -> {injected.status_code}"
                )

        # Significant body length change (boolean blind hint)
        base_len = len(baseline.response_body)
        inj_len = len(injected.response_body)
        if base_len > 0:
            ratio = abs(inj_len - base_len) / base_len
            if ratio > 0.3:
                score = max(score, 0.4)
                evidence_parts.append(
                    f"Body length changed {base_len} -> {inj_len} ({ratio:.0%})"
                )

        # Timing anomaly (time-based blind hint)
        if injected.response_time_ms - baseline.response_time_ms > 2500:
            score = max(score, 0.6)
            evidence_parts.append(
                f"Delay +{injected.response_time_ms - baseline.response_time_ms:.0f}ms"
            )

        # Payload reflected with error context
        if injected.payload and injected.payload in injected.response_body:
            if errors:
                score = max(score, 0.9)
                evidence_parts.append("Payload reflected with SQL error")

        return score, "; ".join(evidence_parts) if evidence_parts else ""

    def guess_db_from_errors(self, text: str) -> Optional[str]:
        """Guess database type from error messages."""
        lower = text.lower()
        if "mysql" in lower or "mariadb" in lower:
            return "mysql"
        if "postgresql" in lower or "pg_" in lower or "psql" in lower:
            return "postgresql"
        if "sqlite" in lower:
            return "sqlite"
        if "sql server" in lower or "odbc" in lower or "mssql" in lower:
            return "mssql"
        if "ora-" in lower or "oracle" in lower:
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
