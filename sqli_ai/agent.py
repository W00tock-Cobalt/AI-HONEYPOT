"""LLM agent for adaptive SQL injection testing."""

import json
import os
import re
from typing import Any, Optional

import httpx

from sqli_ai.models import AgentDecision, HttpExchange, InjectionPoint, InjectionType
from sqli_ai.ollama import (
    DEFAULT_OLLAMA_API_KEY,
    DEFAULT_OLLAMA_MODEL,
    ollama_base_url,
)
from sqli_ai.payloads import AGENT_SYSTEM_PROMPT, ANALYZE_TARGET_PROMPT


def _default_base_url() -> str:
    host = os.getenv("OLLAMA_HOST")
    if host:
        return ollama_base_url(host)
    return ollama_base_url()


def _default_model() -> str:
    return os.getenv("OLLAMA_MODEL") or os.getenv("SQLi-AI_MODEL") or DEFAULT_OLLAMA_MODEL


def _is_ollama_backend(base_url: str) -> bool:
    lower = base_url.lower()
    return "11434" in lower or "ollama" in lower


def _coerce_payload(value: Any) -> Optional[str]:
    """Normalize a single payload to a string (small models emit dicts/lists)."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        for key in ("payload", "value", "input", "text", "sql"):
            if key in value and isinstance(value[key], (str, int, float)):
                return str(value[key])
        return None
    return None


def _coerce_payloads(values: Any) -> list[str]:
    """Normalize a list of payloads to clean strings."""
    if not isinstance(values, list):
        values = [values]
    out: list[str] = []
    for v in values:
        s = _coerce_payload(v)
        if s:
            out.append(s)
    return out


class LlmAgent:
    """OpenAI-compatible LLM backend; defaults to local Ollama."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.2,
    ):
        self.base_url = (base_url or _default_base_url()).rstrip("/")
        self.is_ollama = _is_ollama_backend(self.base_url)
        self.model = model or _default_model()
        self.temperature = temperature

        if api_key:
            self.api_key = api_key
        elif self.is_ollama:
            self.api_key = DEFAULT_OLLAMA_API_KEY
        else:
            self.api_key = os.getenv("OPENAI_API_KEY", "")

        # Per-call timeout (env-overridable). A slow local model must fail fast
        # so it can't stall the whole scan — the deterministic engine carries on.
        try:
            _to = float(os.getenv("SQLi-AI_LLM_TIMEOUT", "25"))
        except ValueError:
            _to = 25.0
        self._client = httpx.Client(timeout=httpx.Timeout(_to, connect=5.0))
        # Circuit breaker: after this many consecutive timeouts/errors, stop
        # calling the LLM for the rest of the run (fall back to heuristics).
        self._fail_count = 0
        self._max_fails = 2
        self._disabled = False

    def close(self):
        self._client.close()

    def _chat(self, system: str, user: str) -> dict[str, Any]:
        """Call chat completions and parse JSON response."""
        if self._disabled:
            raise RuntimeError("LLM disabled (too slow/unreachable) — heuristics only")
        if not self.api_key and not self.is_ollama:
            raise RuntimeError(
                "No LLM API key. Set OPENAI_API_KEY, use Ollama (default), or pass --api-key"
            )

        body: dict[str, Any] = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }

        # JSON mode — supported by Ollama and OpenAI
        if self.is_ollama:
            body["format"] = "json"
        else:
            body["response_format"] = {"type": "json_object"}

        try:
            resp = self._client.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=body,
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
        except (httpx.TimeoutException, httpx.HTTPError) as e:
            # Trip the circuit breaker after repeated slowness/errors so one
            # stuck model can't stall the whole scan.
            self._fail_count += 1
            if self._fail_count >= self._max_fails:
                self._disabled = True
            raise RuntimeError(
                f"LLM call failed ({type(e).__name__})"
                + (" — disabling LLM for this run" if self._disabled else "")
            )
        self._fail_count = 0  # success resets the breaker
        return self._parse_json(content)

    @staticmethod
    def _parse_json(text: str) -> dict[str, Any]:
        """Extract JSON from LLM output, tolerant of small model quirks."""
        text = text.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\n?", "", text)
            text = re.sub(r"\n?```$", "", text)

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Extract the outermost {...} block (small models add prose around it)
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            candidate = text[start:end + 1]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                # Repair common issues: trailing commas, single quotes, unquoted null-ish
                repaired = re.sub(r",\s*([}\]])", r"\1", candidate)
                repaired = repaired.replace("'", '"')
                repaired = re.sub(r"\bTrue\b", "true", repaired)
                repaired = re.sub(r"\bFalse\b", "false", repaired)
                repaired = re.sub(r"\bNone\b", "null", repaired)
                try:
                    return json.loads(repaired)
                except json.JSONDecodeError:
                    pass

        raise json.JSONDecodeError("No valid JSON in LLM response", text, 0)

    def suggest_initial_payloads(
        self,
        url: str,
        method: str,
        point: InjectionPoint,
        content_type: Optional[str],
        baseline: HttpExchange,
    ) -> list[str]:
        """Ask LLM for first payloads to try on this parameter."""
        prompt = ANALYZE_TARGET_PROMPT.format(
            url=url,
            method=method,
            param=point.name,
            location=point.location.value,
            original_value=point.original_value,
            content_type=content_type or "unknown",
            status=baseline.status_code,
            baseline_body=baseline.response_body[:2000],
        )
        try:
            result = self._chat(AGENT_SYSTEM_PROMPT, prompt)
            return _coerce_payloads(result.get("payloads", []))[:5]
        except Exception:
            return []

    def suggest_targeted_payloads(
        self,
        url: str,
        method: str,
        point: InjectionPoint,
        content_type: Optional[str],
        baseline: HttpExchange,
        injected: HttpExchange,
    ) -> list[str]:
        """Near-miss assist: the deterministic engine saw this parameter REACT
        to injection but couldn't confirm it. Show the LLM the baseline vs the
        most-reactive injected response and ask for a few TARGETED payloads that
        would confirm/exploit it (right quoting/boundary/technique). This is the
        high-value, low-volume way to use the model."""
        prompt = (
            "A parameter appears injectable but is unconfirmed. Craft up to 6 "
            "targeted SQL-injection payloads (varied quoting/boundary/comment "
            "styles and techniques: error, boolean, UNION, time) most likely to "
            "confirm it for THIS context. Consider the reflected error/behavior.\n\n"
            f"URL: {url}\nMethod: {method}\nParameter: {point.name} "
            f"({point.location.value})\nOriginal value: {point.original_value}\n"
            f"Content-Type: {content_type or 'unknown'}\n"
            f"Baseline HTTP {baseline.status_code}:\n{baseline.response_body[:1200]}\n\n"
            f"Injected (payload={injected.payload!r}) HTTP {injected.status_code}:\n"
            f"{injected.response_body[:1200]}\n\n"
            'Respond ONLY as JSON: {"payloads": ["<p1>", "<p2>", ...]}'
        )
        try:
            result = self._chat(AGENT_SYSTEM_PROMPT, prompt)
            return _coerce_payloads(result.get("payloads", []))[:6]
        except Exception:
            return []

    def analyze_exchange(
        self,
        baseline: HttpExchange,
        injected: HttpExchange,
        point: InjectionPoint,
        quick_score: float,
        quick_evidence: str,
        attempts: int,
        max_attempts: int,
    ) -> AgentDecision:
        """Ask LLM to analyze a test result and decide next step."""
        user_prompt = f"""Injection point: {point.name} ({point.location.value})
Original value: {point.original_value}
Attempt: {attempts}/{max_attempts}
Quick heuristic score: {quick_score:.2f}
Quick evidence: {quick_evidence or "none"}

--- BASELINE ---
Status: {baseline.status_code}
Time: {baseline.response_time_ms:.0f}ms
Body (first 1500 chars):
{baseline.response_body[:1500]}

--- INJECTED (payload: {injected.payload!r}) ---
Status: {injected.status_code}
Time: {injected.response_time_ms:.0f}ms
Body (first 1500 chars):
{injected.response_body[:1500]}

Decide the next action."""

        try:
            result = self._chat(AGENT_SYSTEM_PROMPT, user_prompt)
        except Exception as e:
            return AgentDecision(
                action="skip",
                reasoning=f"LLM error: {e}",
                confidence=0.0,
            )

        action = result.get("action", "skip")
        inj_type_str = result.get("injection_type", "unknown")
        try:
            inj_type = InjectionType(inj_type_str)
        except ValueError:
            inj_type = InjectionType.UNKNOWN

        return AgentDecision(
            action=action,
            payload=_coerce_payload(result.get("payload")),
            injection_type=inj_type,
            reasoning=result.get("reasoning", ""),
            confidence=float(result.get("confidence", 0.0)),
            db_hint=result.get("db_hint"),
        )

    def analyze_finding(
        self,
        *,
        url: str,
        param: str,
        location: str,
        injection_type: str,
        db_type: Optional[str],
        payload: str,
        evidence: str,
        response_after: str,
    ) -> dict[str, Any]:
        """Post-confirmation AI analysis of a CONFIRMED finding.

        Runs after the deterministic engine has already confirmed the vuln, so
        it never affects detection (and thus scan consistency). It produces a
        human-readable impact/exploitation writeup that makes the LLM genuinely
        useful and visible on every finding, not just near-misses. Returns a
        dict with: impact, exploitation, remediation, severity, confidence.
        """
        system = (
            "You are a senior application security engineer writing the analysis "
            "section of a penetration-test finding for a CONFIRMED SQL/NoSQL "
            "injection. Be concise, technical and accurate. Respond ONLY as JSON."
        )
        user = (
            f"A SQL injection was CONFIRMED by a deterministic scanner. Write the "
            f"analysis.\n\n"
            f"URL: {url}\n"
            f"Parameter: {param} ({location})\n"
            f"Injection type: {injection_type}\n"
            f"Database: {db_type or 'unknown'}\n"
            f"Confirming payload: {payload!r}\n"
            f"Scanner evidence: {evidence}\n"
            f"Response excerpt:\n{(response_after or '')[:1200]}\n\n"
            'Respond ONLY as JSON with keys: '
            '{"impact": "<what an attacker can do>", '
            '"exploitation": "<concrete next step, e.g. sqlmap flags or a UNION/'
            'error-extraction approach for this DBMS>", '
            '"remediation": "<the fix>", '
            '"severity": "critical|high|medium|low", '
            '"confidence": 0.0-1.0}'
        )
        try:
            result = self._chat(system, user)
        except Exception as e:
            return {"error": str(e)}
        return result if isinstance(result, dict) else {}

    def confirm_finding(
        self,
        baseline: HttpExchange,
        injected: HttpExchange,
        point: InjectionPoint,
    ) -> dict[str, Any]:
        """Final LLM confirmation of vulnerability."""
        user_prompt = f"""Confirm whether this is a real SQL injection vulnerability.

Parameter: {point.name} ({point.location.value})
Payload: {injected.payload!r}

Baseline status {baseline.status_code}, injected status {injected.status_code}.
Baseline time {baseline.response_time_ms:.0f}ms, injected {injected.response_time_ms:.0f}ms.

Injected response (first 2000 chars):
{injected.response_body[:2000]}

Respond with JSON including: vulnerable (bool), confidence (0-1), evidence, db_type, injection_type, severity (critical/high/medium/low)."""

        try:
            return self._chat(AGENT_SYSTEM_PROMPT, user_prompt)
        except Exception as e:
            return {
                "vulnerable": False,
                "confidence": 0.0,
                "evidence": str(e),
            }
