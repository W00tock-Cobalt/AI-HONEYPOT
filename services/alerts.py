"""
Alert service for real-time notifications.

Supports:
- Slack webhooks
- Discord webhooks
- Generic webhooks (SIEM integration)
- Email (SMTP)
"""

import os
import json
import asyncio
from typing import Optional
from datetime import datetime
from dataclasses import dataclass

import httpx
from rich.console import Console

console = Console()


@dataclass
class Alert:
    """Alert payload."""
    request_id: int
    timestamp: str
    source_ip: str
    country: Optional[str]
    path: str
    method: str
    classification: str
    threat_level: Optional[str]
    api_key: Optional[str]
    ai_summary: Optional[str]
    details: dict


class AlertService:
    """Manages alert notifications."""

    def __init__(self):
        self.slack_webhook = os.getenv("SLACK_WEBHOOK_URL")
        self.discord_webhook = os.getenv("DISCORD_WEBHOOK_URL")
        self.generic_webhook = os.getenv("WEBHOOK_URL")
        self.alert_threshold = os.getenv("ALERT_THRESHOLD", "medium")  # low, medium, high, critical
        self.enabled = any([self.slack_webhook, self.discord_webhook, self.generic_webhook])
        self.client: Optional[httpx.AsyncClient] = None

        # Rate limiting
        self._last_alert_time = {}
        self._rate_limit_seconds = int(os.getenv("ALERT_RATE_LIMIT", "60"))

        if self.enabled:
            console.print("[green]Alert service enabled[/green]")
            if self.slack_webhook:
                console.print("  → Slack webhook configured")
            if self.discord_webhook:
                console.print("  → Discord webhook configured")
            if self.generic_webhook:
                console.print("  → Generic webhook configured")

    async def _get_client(self) -> httpx.AsyncClient:
        if self.client is None:
            self.client = httpx.AsyncClient(timeout=10.0)
        return self.client

    async def close(self):
        if self.client:
            await self.client.aclose()

    def should_alert(self, threat_level: Optional[str], classification: str) -> bool:
        """Determine if this event should trigger an alert."""
        if not self.enabled:
            return False

        # Always alert on these classifications
        high_priority = ["credential_stuffer", "prompt_harvester"]
        if classification in high_priority:
            return True

        # Threat level threshold
        levels = ["low", "medium", "high", "critical"]
        threshold_idx = levels.index(self.alert_threshold) if self.alert_threshold in levels else 1

        if threat_level and threat_level in levels:
            if levels.index(threat_level) >= threshold_idx:
                return True

        return False

    def _rate_limited(self, source_ip: str) -> bool:
        """Check if we should rate limit alerts for this IP."""
        now = datetime.utcnow().timestamp()
        last_time = self._last_alert_time.get(source_ip, 0)

        if now - last_time < self._rate_limit_seconds:
            return True

        self._last_alert_time[source_ip] = now
        return False

    async def send_alert(
        self,
        title: str = "Honeypot Alert",
        classification: str = "unknown",
        confidence: float = 0.0,
        source_ip: str = "unknown",
        country: str = "Unknown",
        path: str = "/",
        api_key: Optional[str] = None,
        reasons: Optional[list] = None,
        threat_level: Optional[str] = None,
        ai_summary: Optional[str] = None,
        **kwargs,
    ):
        """Send alert to all configured channels."""
        if not self.enabled:
            return

        if self._rate_limited(source_ip):
            return

        # Create alert object for internal use
        alert = Alert(
            request_id=kwargs.get("request_id", 0),
            timestamp=datetime.utcnow().isoformat(),
            source_ip=source_ip,
            country=country,
            path=path,
            method=kwargs.get("method", "POST"),
            classification=classification,
            threat_level=threat_level,
            api_key=api_key,
            ai_summary=ai_summary or ("; ".join(reasons[:3]) if reasons else None),
            details={"reasons": reasons or [], "confidence": confidence},
        )

        tasks = []
        if self.slack_webhook:
            tasks.append(self._send_slack(alert))
        if self.discord_webhook:
            tasks.append(self._send_discord(alert))
        if self.generic_webhook:
            tasks.append(self._send_generic(alert))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_slack(self, alert: Alert):
        """Send Slack webhook."""
        try:
            client = await self._get_client()

            color = {
                "low": "#36a64f",
                "medium": "#ff9800",
                "high": "#f44336",
                "critical": "#9c27b0",
            }.get(alert.threat_level, "#808080")

            payload = {
                "attachments": [{
                    "color": color,
                    "title": f"🍯 Honeypot Alert #{alert.request_id}",
                    "fields": [
                        {"title": "Source", "value": f"{alert.source_ip} ({alert.country or 'Unknown'})", "short": True},
                        {"title": "Request", "value": f"{alert.method} {alert.path}", "short": True},
                        {"title": "Classification", "value": alert.classification, "short": True},
                        {"title": "Threat Level", "value": alert.threat_level or "N/A", "short": True},
                    ],
                    "text": alert.ai_summary or "No AI analysis available",
                    "footer": "Honeypot Security Monitor",
                    "ts": int(datetime.utcnow().timestamp()),
                }]
            }

            if alert.api_key:
                redacted = f"{alert.api_key[:12]}...{alert.api_key[-4:]}" if len(alert.api_key) > 16 else alert.api_key
                payload["attachments"][0]["fields"].append({
                    "title": "API Key", "value": f"`{redacted}`", "short": True
                })

            await client.post(self.slack_webhook, json=payload)
        except Exception as e:
            console.print(f"[red]Slack alert failed: {e}[/red]")

    async def _send_discord(self, alert: Alert):
        """Send Discord webhook."""
        try:
            client = await self._get_client()

            color = {
                "low": 0x36a64f,
                "medium": 0xff9800,
                "high": 0xf44336,
                "critical": 0x9c27b0,
            }.get(alert.threat_level, 0x808080)

            payload = {
                "embeds": [{
                    "title": f"🍯 Honeypot Alert #{alert.request_id}",
                    "color": color,
                    "fields": [
                        {"name": "Source", "value": f"{alert.source_ip} ({alert.country or 'Unknown'})", "inline": True},
                        {"name": "Request", "value": f"{alert.method} {alert.path}", "inline": True},
                        {"name": "Classification", "value": alert.classification, "inline": True},
                        {"name": "Threat Level", "value": alert.threat_level or "N/A", "inline": True},
                    ],
                    "description": alert.ai_summary or "No AI analysis available",
                    "timestamp": datetime.utcnow().isoformat(),
                }]
            }

            await client.post(self.discord_webhook, json=payload)
        except Exception as e:
            console.print(f"[red]Discord alert failed: {e}[/red]")

    async def _send_generic(self, alert: Alert):
        """Send generic webhook (for SIEM/custom integrations)."""
        try:
            client = await self._get_client()

            payload = {
                "event": "honeypot_alert",
                "version": "1.0",
                "timestamp": alert.timestamp,
                "request_id": alert.request_id,
                "source": {
                    "ip": alert.source_ip,
                    "country": alert.country,
                },
                "request": {
                    "method": alert.method,
                    "path": alert.path,
                },
                "classification": alert.classification,
                "threat_level": alert.threat_level,
                "api_key": alert.api_key,
                "ai_summary": alert.ai_summary,
                "details": alert.details,
            }

            await client.post(
                self.generic_webhook,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
        except Exception as e:
            console.print(f"[red]Webhook alert failed: {e}[/red]")


# Singleton
_alert_service: Optional[AlertService] = None


def get_alert_service() -> AlertService:
    global _alert_service
    if _alert_service is None:
        _alert_service = AlertService()
    return _alert_service
