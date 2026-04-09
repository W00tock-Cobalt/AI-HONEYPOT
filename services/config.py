"""
Configuration service - stores settings in database/JSON.

Allows runtime configuration via admin GUI instead of .env files.
"""

import os
import json
from typing import Optional, Any
from pathlib import Path
from dataclasses import dataclass, field, asdict
from rich.console import Console

console = Console()

CONFIG_FILE = Path("./config.json")


@dataclass
class HoneypotConfig:
    """Honeypot configuration settings."""

    # Groq AI Analysis
    groq_api_key: str = ""
    groq_enabled: bool = True
    groq_model: str = "llama-3.1-8b-instant"

    # Alert Webhooks
    slack_webhook_url: str = ""
    discord_webhook_url: str = ""
    webhook_url: str = ""  # Generic webhook for SIEM
    alert_threshold: str = "medium"  # low, medium, high, critical
    alert_rate_limit: int = 60  # seconds between alerts per IP

    # Email Alerts (SMTP)
    smtp_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: str = ""  # Comma-separated list
    smtp_tls: bool = True

    # Multi-port Configuration
    additional_ports: list = field(default_factory=list)  # e.g., [8080, 8443, 443]

    # Logging Verbosity
    log_headers: bool = True
    log_body: bool = True
    log_response: bool = True
    verbose_console: bool = True

    # Data Retention
    retention_days: int = 90  # Auto-delete logs older than X days (0 = never)
    max_db_size_mb: int = 0  # Max database size in MB (0 = unlimited)

    # Admin Settings
    admin_username: str = "admin"
    admin_password: str = ""  # bcrypt hash stored here after setup
    jwt_secret: str = ""
    setup_complete: bool = False  # True after first-run wizard is done

    # GeoIP
    geoip_enabled: bool = True
    geoip_db_path: str = "./GeoLite2-City.mmdb"
    maxmind_license_key: str = ""

    # Canary Tokens — list of {"id": str, "label": str, "token": str, "added_at": str, "note": str}
    canary_tokens: list = field(default_factory=list)

    # Response Customization
    fake_org_name: str = "org-honeypot"
    response_delay_min_ms: int = 80
    response_delay_max_ms: int = 300

    def to_dict(self) -> dict:
        """Convert to dictionary, hiding sensitive fields."""
        d = asdict(self)
        # Mask sensitive fields for display
        if d.get("groq_api_key"):
            d["groq_api_key_masked"] = f"{d['groq_api_key'][:8]}...{d['groq_api_key'][-4:]}" if len(d["groq_api_key"]) > 12 else "***"
        if d.get("slack_webhook_url"):
            d["slack_webhook_masked"] = "Configured ✓"
        if d.get("discord_webhook_url"):
            d["discord_webhook_masked"] = "Configured ✓"
        return d

    def to_safe_dict(self) -> dict:
        """Convert to dictionary without sensitive values."""
        d = asdict(self)
        sensitive_keys = ["groq_api_key", "slack_webhook_url", "discord_webhook_url",
                         "webhook_url", "admin_password", "jwt_secret", "maxmind_license_key"]
        for key in sensitive_keys:
            if d.get(key):
                d[key] = "••••••••" if d[key] else ""
        return d


class ConfigService:
    """Manages honeypot configuration."""

    def __init__(self):
        self.config = HoneypotConfig()
        self._load()

    def _load(self):
        """Load configuration from file, falling back to env vars."""
        # First load from env vars (backwards compatibility)
        self.config.groq_api_key = os.getenv("GROQ_API_KEY", "")
        self.config.slack_webhook_url = os.getenv("SLACK_WEBHOOK_URL", "")
        self.config.discord_webhook_url = os.getenv("DISCORD_WEBHOOK_URL", "")
        self.config.webhook_url = os.getenv("WEBHOOK_URL", "")
        self.config.admin_username = os.getenv("ADMIN_USERNAME", "admin")
        self.config.admin_password = os.getenv("ADMIN_PASSWORD", "")
        self.config.jwt_secret = os.getenv("JWT_SECRET", "")
        self.config.geoip_db_path = os.getenv("GEOIP_DB_PATH", "./GeoLite2-City.mmdb")
        self.config.maxmind_license_key = os.getenv("MAXMIND_LICENSE_KEY", "")

        # Parse additional ports from env
        ports_env = os.getenv("ADDITIONAL_PORTS", "")
        if ports_env:
            try:
                self.config.additional_ports = [int(p.strip()) for p in ports_env.split(",") if p.strip()]
            except ValueError:
                pass

        # Then override with config file if exists
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    data = json.load(f)
                    for key, value in data.items():
                        if hasattr(self.config, key):
                            # Always restore setup_complete and canary_tokens even if falsy
                            if key in ("setup_complete", "canary_tokens"):
                                setattr(self.config, key, value)
                            elif value:  # Only override non-empty values for other fields
                                setattr(self.config, key, value)
                console.print(f"[green]Loaded config from {CONFIG_FILE}[/green]")
            except Exception as e:
                console.print(f"[yellow]Config load warning: {e}[/yellow]")

        # Backwards-compat: if ADMIN_PASSWORD env var is a non-default value, treat setup as done
        env_pw = os.getenv("ADMIN_PASSWORD", "")
        if env_pw and env_pw not in ("changeme", "admin", "") and not self.config.setup_complete:
            self.config.setup_complete = True

    def save(self):
        """Save configuration to file."""
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(asdict(self.config), f, indent=2)
            console.print(f"[green]Config saved to {CONFIG_FILE}[/green]")
            return True
        except Exception as e:
            console.print(f"[red]Config save failed: {e}[/red]")
            return False

    def is_setup_done(self) -> bool:
        """Return True if first-run setup has been completed."""
        return self.config.setup_complete

    def complete_setup(self, username: str, password_hash: str) -> bool:
        """Save admin credentials and mark setup as complete."""
        self.config.admin_username = username
        self.config.admin_password = password_hash
        self.config.setup_complete = True
        return self.save()

    def update(self, **kwargs) -> bool:
        """Update configuration values."""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                # Don't overwrite with empty strings for sensitive fields
                if value == "" and key in ["groq_api_key", "slack_webhook_url", "discord_webhook_url",
                                           "webhook_url", "admin_password", "jwt_secret"]:
                    continue
                setattr(self.config, key, value)
        return self.save()

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        return getattr(self.config, key, default)

    def get_all(self) -> dict:
        """Get all configuration as dict."""
        return asdict(self.config)

    def get_safe(self) -> dict:
        """Get configuration without sensitive values."""
        return self.config.to_safe_dict()


# Singleton
_config_service: Optional[ConfigService] = None


def get_config() -> ConfigService:
    global _config_service
    if _config_service is None:
        _config_service = ConfigService()
    return _config_service
