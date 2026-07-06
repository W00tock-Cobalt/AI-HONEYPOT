"""Hybrid SQL injection detection: regex triage + LLM confirmation."""

import re
from typing import Optional

from llmsql.models import HttpExchange, InjectionType
from llmsql.payloads import NOSQL_ERROR_PATTERNS, SQL_ERROR_PATTERNS


class SqlDetector:
    """Fast pattern-based detection before LLM analysis."""

    def __init__(self):
        self._patterns = [re.compile(p, re.IGNORECASE) for p in SQL_ERROR_PATTERNS]
        self._nosql_patterns = [re.compile(p, re.IGNORECASE) for p in NOSQL_ERROR_PATTERNS]

    def find_nosql_errors(self, text: str) -> list[str]:
        """Return matched NoSQL (MongoDB/MarsDB) error strings."""
        matches = []
        for pattern in self._nosql_patterns:
            for m in pattern.finditer(text):
                matches.append(m.group(0))
        return matches

    def nosql_boolean_score(
        self,
        baseline: HttpExchange,
        true_exchange: HttpExchange,
        false_exchange: HttpExchange,
    ) -> tuple[float, str]:
        """
        NoSQL boolean-injection check: the 'true' payload should return more/
        different data than the 'false' payload (and differ from baseline),
        indicating the boolean expression altered query evaluation.
        """
        if any(e.status_code >= 500 for e in (true_exchange, false_exchange)):
            return 0.0, ""
        b_len = len(baseline.response_body)
        t_len = len(true_exchange.response_body)
        f_len = len(false_exchange.response_body)
        if t_len == 0 or f_len == 0:
            return 0.0, ""
        tf_diff = abs(t_len - f_len) / max(t_len, f_len)
        # true should differ from false AND from the (non-matching) baseline
        if tf_diff > 0.15 and t_len != b_len:
            return min(0.9, 0.55 + tf_diff), (
                f"NoSQL boolean: true={t_len}b vs false={f_len}b "
                f"({tf_diff:.0%} diff), baseline={b_len}b"
            )
        return 0.0, ""

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
        r"ETIMEDOUT|ENOTFOUND|socket hang up|"
        # Proxy/mesh (Envoy/Istio/nginx) upstream failures — infra, not SQLi.
        r"upstream connect error|reset reason|delayed connect error|"
        r"no healthy upstream|upstream request timeout|"
        r"502 bad gateway|503 service|service unavailable|gateway time-?out",
        re.IGNORECASE,
    )

    def is_db_offline(self, exchange: HttpExchange) -> bool:
        """True when the response indicates the DB/backend/upstream is unreachable."""
        return bool(self._CONN_REFUSED.search(exchange.response_body or ""))

    def is_infra_error(self, exchange: HttpExchange) -> bool:
        """True for gateway/upstream failures that are NOT application-level and
        therefore never a SQL-injection signal (502/503/504, connection reset,
        upstream connect error, ...). The request never reached a working app."""
        if exchange.status_code in (502, 503, 504):
            return True
        return self.is_db_offline(exchange)

    _PASSWORD_INPUT = re.compile(r'type=["\']?password', re.IGNORECASE)

    def looks_like_login_page(self, exchange: HttpExchange) -> bool:
        """Heuristic: is this response a login form (likely an auth redirect)?

        Used to warn when an unauthenticated scan is silently bounced to a login
        page (e.g. DVWA redirecting protected pages to login.php) — otherwise the
        scan just reports 0 findings with no explanation.
        """
        body = exchange.response_body or ""
        if not self._PASSWORD_INPUT.search(body):
            return False
        low = body.lower()
        signals = (
            "user_token", "csrf", 'action="login', "action='login", "/login",
            "sign in", "signin", "log in", "please log in",
            "authentication required", "loginform",
        )
        return any(s in low for s in signals)

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

    def boolean_amplification_score(
        self,
        baseline: HttpExchange,
        or_exchange: HttpExchange,
        and_exchange: HttpExchange,
    ) -> tuple[float, str]:
        """Nuclei-style boolean SQLi via OR/AND result amplification.

        An OR-true payload appended to the value (``... OR 1=1``) makes the
        WHERE clause always true, so a listing/search endpoint returns MORE rows
        (response grows vs. baseline). An AND-false payload (``... AND 1=2``)
        makes it always false, returning fewer/none (response shrinks). The
        asymmetry OR >> baseline >> AND is the signal — and, crucially, it works
        on endpoints that never emit a SQL error (which error-based detection
        misses). Caller must have already confirmed the endpoint is
        deterministic (see Scanner._natural_variance) to avoid dynamic-page FPs.
        """
        # Both variants should behave like the (successful) baseline status;
        # a 500 means we broke syntax (error-based territory), not boolean.
        if not (200 <= baseline.status_code < 300):
            return 0.0, ""
        if or_exchange.status_code != baseline.status_code:
            return 0.0, ""
        if and_exchange.status_code not in (baseline.status_code,):
            return 0.0, ""
        b = len(baseline.response_body)
        o = len(or_exchange.response_body)
        a = len(and_exchange.response_body)
        if b == 0 or o == 0:
            return 0.0, ""
        grow = (o - b) / b        # how much the OR-true response grew
        shrink = (b - a) / b      # how much the AND-false response shrank
        # OR must return materially MORE than baseline, AND must return
        # materially LESS, and OR must clearly exceed AND. Requiring BOTH
        # directions is what separates real boolean SQLi from a page that
        # merely reacts to any input.
        if grow > 0.25 and a < b and o > a * 1.3 and (shrink > 0.10 or a < o * 0.6):
            conf = min(0.9, 0.6 + grow / 5)
            return conf, (
                f"Boolean OR/AND amplification: baseline={b}b, "
                f"OR-true={o}b (+{grow:.0%}), AND-false={a}b (-{shrink:.0%})"
            )
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

        # Inert parameter: if the injected response is identical to the baseline
        # (same status AND same body), the parameter had no effect whatsoever —
        # it is NOT injectable. This is extremely common when param-mining /
        # organic discovery adds extra params (callback, redirect, ...) to an
        # endpoint that ignores them; without this guard every such param on an
        # already-erroring endpoint got falsely flagged via the reflection check.
        # EXCEPTION: time-based blind injection returns an identical body but a
        # delayed response — never short-circuit when a sleep is expected or the
        # response is anomalously slow, or we'd miss time-based SQLi.
        _delay = injected.response_time_ms - baseline.response_time_ms
        _timing_suspect = injected.expected_sleep_ms is not None or _delay > 4500
        if (injected.status_code == baseline.status_code
                and injected.response_body == baseline.response_body
                and not _timing_suspect):
            return 0.0, ""

        baseline_errors = self.find_sql_errors(baseline.response_body)
        baseline_broken = bool(baseline_errors)

        # SQL errors in injected response.
        # If the baseline is already erroring (e.g. OpenAPI placeholder `test`
        # used as a raw SQL param), only a *new* error (different text) is a
        # genuine SQLi signal. `new_errors` is the genuine-signal set used
        # everywhere below so pre-existing baseline errors never trigger a find.
        errors = self.find_sql_errors(injected.response_body)
        new_errors = (
            [e for e in errors if e not in baseline_errors] if baseline_broken else errors
        )
        if errors:
            if not baseline_broken:
                # Clean baseline → any SQL error is a finding
                score = max(score, 0.85)
                evidence_parts.append(f"SQL error: {errors[0][:120]}")
            else:
                if new_errors:
                    score = max(score, 0.85)
                    evidence_parts.append(f"SQL error (new): {new_errors[0][:120]}")
                # Even with same error text, a status change is suspicious
                elif baseline.status_code != injected.status_code:
                    score = max(score, 0.5)
                    evidence_parts.append(
                        f"SQL error + status change {baseline.status_code}->{injected.status_code}"
                    )

        # Status change: 200→500 is always interesting.
        # With SQL errors it strongly confirms (0.6); without, weak signal (0.45).
        if baseline.status_code != injected.status_code:
            # Gateway/upstream errors (502/503/504) and connection failures are
            # infrastructure problems, NOT SQL injection — the request never
            # reached a working app/DB. Never score them.
            if self.is_infra_error(injected):
                pass
            elif injected.status_code >= 500:
                score = max(score, 0.6 if new_errors else 0.45)
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

        # Authentication bypass via SQLi: baseline is denied (401/403 or a
        # generic "invalid credentials" 200) but the injected payload — which
        # looks like a SQLi auth-bypass attempt (quote + OR/UNION/comment) —
        # succeeds (200 with what looks like a session/token). This is the
        # classic ' OR 1=1-- login bypass and produces NO SQL error text at all,
        # so none of the other checks above catch it.
        payload_lower = (injected.payload or "").lower()
        looks_like_bypass_payload = (
            ("'" in payload_lower or '"' in payload_lower)
            and any(kw in payload_lower for kw in (" or ", "or 1=1", "union", "--", "#"))
        )
        baseline_denied = baseline.status_code in (401, 403) or any(
            kw in baseline.response_body.lower()
            for kw in ("invalid credentials", "invalid login", "authentication failed", "incorrect password")
        )
        injected_succeeded = (200 <= injected.status_code < 300) and any(
            kw in injected.response_body.lower()
            for kw in ("token", "authentication", "bearer", '"id"', "session", "jwt")
        )
        if looks_like_bypass_payload and baseline_denied and injected_succeeded:
            score = max(score, 0.9)
            evidence_parts.append(
                f"Auth bypass: baseline denied (HTTP {baseline.status_code}), "
                f"SQLi payload succeeded (HTTP {injected.status_code} with session/token)"
            )

        # Timing anomaly (time-based blind hint).
        # Only use the calibrated threshold on ACTUAL sleep payloads (tagged with
        # _expected_sleep_ms). For other payloads use a high fixed threshold so
        # slow servers don't generate false positives on every request.
        delay = injected.response_time_ms - baseline.response_time_ms
        expected_sleep_ms = injected.expected_sleep_ms
        if expected_sleep_ms is not None and delay > expected_sleep_ms * 0.6:
            score = max(score, 0.8)
            evidence_parts.append(
                f"Time-blind delay +{delay:.0f}ms (expected ~{expected_sleep_ms}ms)"
            )
        elif delay > 4500:
            # High threshold for non-sleep payloads — avoids slow-server false positives
            score = max(score, 0.6)
            evidence_parts.append(f"Unexpected delay +{delay:.0f}ms")

        # Payload reflected with error context — must be a NEW error, not the
        # baseline's pre-existing one, and the payload must be more than a lone
        # metacharacter (a bare " trivially appears inside `at or near "1"`).
        if (injected.payload and len(injected.payload.strip()) >= 2
                and injected.payload in injected.response_body and new_errors):
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
        # SQLite phrasing — only genuinely SQLite-specific tokens. The old
        # `syntax error ... near "` heuristic was removed: PostgreSQL ("syntax
        # error at or near") and MySQL ("...syntax; ... near '...'") both use
        # that phrasing, so it produced sqlite false positives on PG/MySQL apps.
        if (
            "unrecognized token" in lower
            or "no such table" in lower
            or "no such column" in lower
            or "sqlite3" in lower
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
        if "auth bypass" in lower:
            return InjectionType.BOOLEAN_BLIND  # logically a boolean-true injection
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
