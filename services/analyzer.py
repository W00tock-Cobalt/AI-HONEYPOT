"""
Groq-powered threat analysis service.

Uses Groq's fast LLM to analyze honeypot requests and provide
human-readable threat assessments.
"""

import os
import json
import asyncio
from typing import Optional
from dataclasses import dataclass, field
from datetime import datetime

import httpx
from rich.console import Console

console = Console()

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.1-8b-instant"  # Fast and cheap


@dataclass
class ThreatAnalysis:
    """AI-generated threat analysis result."""
    threat_level: str  # low, medium, high, critical
    threat_type: str  # e.g., "credential_testing", "reconnaissance", "prompt_injection"
    summary: str  # One-line summary
    details: str  # Detailed analysis
    recommendations: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)  # Indicators of compromise
    confidence: float = 0.0
    raw_response: Optional[str] = None


ANALYSIS_PROMPT = """You are an elite threat analyst specializing in AI API honeypots, credential theft, and LLM-targeted attacks. Analyze the following honeypot request.

REQUEST DATA:
- Timestamp: {timestamp}
- Source IP: {source_ip}
- Country: {country}
- ASN/Org: {asn_org}
- Method: {method}
- Path: {path}
- User-Agent: {user_agent}
- Authorization Header: {auth_header}
- API Key Used: {api_key}
- Model Requested: {model}
- Request Body: {body}

CONTEXT: This is a fake OpenAI API honeypot. ALL traffic is unauthorized. The attacker may be:
1. Testing stolen API credentials (credential stuffing)
2. Performing reconnaissance (enumerating endpoints, models, org users, files)
3. Attempting prompt injection or system-prompt extraction
4. Trying to exfiltrate data via LLM responses
5. Scanning for vulnerabilities (rate limits, SSRF, path traversal)
6. Using an LLM framework/SDK with a stolen key (LangChain, LiteLLM, etc.)
7. Probing for IDOR vulnerabilities in org/user/file endpoints

Respond ONLY in this exact JSON format (no extra text):
{{
    "threat_level": "low|medium|high|critical",
    "threat_type": "reconnaissance|credential_testing|prompt_injection|data_exfiltration|automated_scanner|manual_probe|api_abuse|jailbreak|unknown",
    "summary": "One concise sentence describing what this attacker is doing",
    "details": "2-4 sentences: what TTPs are evident, what goal the attacker likely has, and any noteworthy patterns in the payload",
    "recommendations": ["Specific action 1", "Specific action 2", "Specific action 3"],
    "iocs": ["ip:{source_ip}", "ua:<user-agent-snippet>", "key:<redacted-key-prefix>", "any other observables"],
    "confidence": 0.0-1.0
}}

Be specific and actionable. If the body contains a prompt, briefly quote the most suspicious part."""


class GroqAnalyzer:
    """Analyzes honeypot requests using Groq LLM."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        # Try config first, then env var
        from services.config import get_config
        config = get_config()

        self.api_key = api_key or config.get("groq_api_key") or os.getenv("GROQ_API_KEY")
        self.model = model or config.get("groq_model") or GROQ_MODEL
        self.enabled = bool(self.api_key) and config.get("groq_enabled", True)
        self.client: Optional[httpx.AsyncClient] = None

        if self.enabled:
            console.print(f"[green]Groq analyzer enabled (model: {self.model})[/green]")
        else:
            if not self.api_key:
                console.print("[yellow]Groq analyzer disabled (no API key - configure in /admin/settings)[/yellow]")
            else:
                console.print("[yellow]Groq analyzer disabled in settings[/yellow]")

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self.client is None:
            self.client = httpx.AsyncClient(timeout=30.0)
        return self.client

    async def close(self):
        """Close HTTP client."""
        if self.client:
            await self.client.aclose()
            self.client = None

    async def analyze(self, request_data: dict) -> Optional[ThreatAnalysis]:
        """
        Analyze a request using Groq LLM. Retries up to 3 times on transient errors.

        Returns ThreatAnalysis or None if analysis fails/disabled.
        """
        if not self.enabled:
            return None

        prompt = self._build_prompt(request_data)
        last_error: Optional[str] = None

        for attempt in range(3):
            try:
                client = await self._get_client()
                response = await client.post(
                    GROQ_API_URL,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {
                                "role": "system",
                                "content": (
                                    "You are an elite cybersecurity threat analyst specializing in AI API abuse, "
                                    "prompt injection, credential theft, and LLM-targeted attacks. "
                                    "Analyze the honeypot request data and provide a structured threat assessment. "
                                    "Be concise, specific, and actionable. Always respond with valid JSON only."
                                ),
                            },
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.1,
                        "max_tokens": 1200,
                        "response_format": {"type": "json_object"},
                    },
                )

                if response.status_code == 200:
                    result = response.json()
                    content = result["choices"][0]["message"]["content"]
                    return self._parse_response(content)
                elif response.status_code in (429, 502, 503, 504):
                    last_error = f"HTTP {response.status_code}"
                    await asyncio.sleep(2 ** attempt)
                    continue
                else:
                    console.print(f"[red]Groq API error: {response.status_code}[/red]")
                    return None

            except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError) as e:
                last_error = str(e)
                await asyncio.sleep(2 ** attempt)
                continue
            except Exception as e:
                console.print(f"[red]Groq analysis error: {e}[/red]")
                return None

        console.print(f"[red]Groq analysis failed after 3 attempts: {last_error}[/red]")
        return None

    def _build_prompt(self, request_data: dict) -> str:
        """Build the analysis prompt from request data."""
        return ANALYSIS_PROMPT.format(
            timestamp=request_data.get("timestamp", "unknown"),
            source_ip=request_data.get("source_ip", "unknown"),
            country=request_data.get("country_name", "Unknown"),
            asn_org=request_data.get("asn_org", "Unknown"),
            method=request_data.get("method", "unknown"),
            path=request_data.get("path", "/"),
            user_agent=self._truncate_body(request_data.get("user_agent", "none")),
            auth_header=self._redact_key(request_data.get("auth_header", "none")),
            api_key=self._redact_key(request_data.get("api_key", "none")),
            model=request_data.get("model_requested", "none"),
            body=self._truncate_body(request_data.get("body_raw", "none")),
        )

    def _redact_key(self, key: Optional[str]) -> str:
        """Partially redact API key for privacy."""
        if not key or key == "none":
            return "none"
        if len(key) > 20:
            return f"{key[:12]}...{key[-4:]}"
        return key

    def _truncate_body(self, body: Optional[str]) -> str:
        """Truncate body for prompt."""
        if not body or body == "none":
            return "none"
        if len(body) > 1000:
            return body[:1000] + "...[truncated]"
        return body

    def _parse_response(self, content: str) -> ThreatAnalysis:
        """Parse Groq JSON response into ThreatAnalysis."""
        try:
            analysis_data = json.loads(content)
            return ThreatAnalysis(
                threat_level=analysis_data.get("threat_level", "unknown"),
                threat_type=analysis_data.get("threat_type", "unknown"),
                summary=analysis_data.get("summary", "Analysis unavailable"),
                details=analysis_data.get("details", ""),
                recommendations=analysis_data.get("recommendations", []),
                iocs=analysis_data.get("iocs", []),
                confidence=float(analysis_data.get("confidence", 0.5)),
                raw_response=content,
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            return ThreatAnalysis(
                threat_level="unknown",
                threat_type="unknown",
                summary="Analysis parsing failed",
                details=content[:500],
                confidence=0.0,
                raw_response=content,
            )


# Singleton
_analyzer: Optional[GroqAnalyzer] = None


def get_analyzer() -> GroqAnalyzer:
    """Get or create analyzer singleton."""
    global _analyzer
    if _analyzer is None:
        _analyzer = GroqAnalyzer()
    return _analyzer


async def analyze_request(request_data: dict) -> Optional[ThreatAnalysis]:
    """Convenience function to analyze a request."""
    analyzer = get_analyzer()
    return await analyzer.analyze(request_data)
