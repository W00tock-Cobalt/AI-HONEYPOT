"""LLM agent for adaptive SQL injection testing."""

import json
import os
import re
from typing import Any, Optional

import httpx

from llmsql.models import AgentDecision, HttpExchange, InjectionPoint, InjectionType
from llmsql.payloads import AGENT_SYSTEM_PROMPT, ANALYZE_TARGET_PROMPT


class LlmAgent:
    """OpenAI-compatible LLM backend for scan decisions."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: str = "gpt-4o-mini",
        temperature: float = 0.2,
    ):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.base_url = (base_url or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.model = model
        self.temperature = temperature
        self._client = httpx.Client(timeout=60.0)

    def close(self):
        self._client.close()

    def _chat(self, system: str, user: str) -> dict[str, Any]:
        """Call chat completions and parse JSON response."""
        if not self.api_key:
            raise RuntimeError(
                "No LLM API key. Set OPENAI_API_KEY or pass --api-key"
            )

        resp = self._client.post(
            f"{self.base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.model,
                "temperature": self.temperature,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "response_format": {"type": "json_object"},
            },
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        return self._parse_json(content)

    @staticmethod
    def _parse_json(text: str) -> dict[str, Any]:
        """Extract JSON from LLM output."""
        text = text.strip()
        # Strip markdown fences if present
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\n?", "", text)
            text = re.sub(r"\n?```$", "", text)
        return json.loads(text)

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
            return result.get("payloads", [])[:5]
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
            payload=result.get("payload"),
            injection_type=inj_type,
            reasoning=result.get("reasoning", ""),
            confidence=float(result.get("confidence", 0.0)),
            db_hint=result.get("db_hint"),
        )

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
