"""Ollama background service management."""

import os
import shutil
import subprocess
import time
from typing import Callable, Optional

import httpx

DEFAULT_OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
DEFAULT_OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
DEFAULT_OLLAMA_API_KEY = "ollama"  # Ollama ignores this; required for OpenAI client compat


def ollama_base_url(host: Optional[str] = None) -> str:
    """OpenAI-compatible base URL for Ollama."""
    base = (host or DEFAULT_OLLAMA_HOST).rstrip("/")
    if not base.endswith("/v1"):
        base = f"{base}/v1"
    return base


def ollama_native_url(host: Optional[str] = None) -> str:
    """Native Ollama API base (no /v1)."""
    base = (host or DEFAULT_OLLAMA_HOST).rstrip("/")
    if base.endswith("/v1"):
        base = base[:-3]
    return base


def is_running(host: Optional[str] = None, timeout: float = 2.0) -> bool:
    """Check if Ollama is responding."""
    try:
        resp = httpx.get(f"{ollama_native_url(host)}/api/tags", timeout=timeout)
        return resp.status_code == 200
    except (httpx.HTTPError, OSError):
        return False


def list_models(host: Optional[str] = None) -> list[str]:
    """Return installed model names."""
    try:
        resp = httpx.get(f"{ollama_native_url(host)}/api/tags", timeout=5.0)
        resp.raise_for_status()
        return [m["name"] for m in resp.json().get("models", [])]
    except (httpx.HTTPError, OSError, KeyError):
        return []


def model_available(model: str, host: Optional[str] = None) -> bool:
    """Check if model is pulled (supports partial name match)."""
    model_base = model.split(":")[0]
    for installed in list_models(host):
        if installed == model or installed.startswith(f"{model_base}:"):
            return True
    return False


def pull_model(model: str, host: Optional[str] = None, on_status: Optional[Callable[[str], None]] = None) -> bool:
    """Pull model via Ollama API (streaming)."""
    url = f"{ollama_native_url(host)}/api/pull"
    # No overall read timeout (pulls legitimately take minutes) but cap connect
    # and inter-chunk reads so a stalled/dead server can't hang the pull forever.
    _pull_timeout = httpx.Timeout(None, connect=10.0, read=120.0)
    try:
        with httpx.stream("POST", url, json={"name": model}, timeout=_pull_timeout) as resp:
            resp.raise_for_status()
            for line in resp.iter_lines():
                if not line or not on_status:
                    continue
                try:
                    import json
                    data = json.loads(line)
                    status = data.get("status", "")
                    if status:
                        on_status(status)
                except json.JSONDecodeError:
                    pass
        return model_available(model, host)
    except (httpx.HTTPError, OSError):
        return False


def _find_ollama_binary() -> Optional[str]:
    return shutil.which("ollama")


def start_background(host: Optional[str] = None) -> bool:
    """
    Start `ollama serve` in the background if not already running.
    Returns True when Ollama is reachable.
    """
    if is_running(host):
        return True

    binary = _find_ollama_binary()
    if not binary:
        return False

    env = os.environ.copy()
    if host:
        # OLLAMA_HOST for the server bind is just host:port without scheme
        parsed = host.replace("http://", "").replace("https://", "")
        env["OLLAMA_HOST"] = parsed

    subprocess.Popen(
        [binary, "serve"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        env=env,
    )

    # Wait up to 30s for startup
    for _ in range(30):
        if is_running(host):
            return True
        time.sleep(1)
    return False


def ensure_ready(
    model: str = DEFAULT_OLLAMA_MODEL,
    host: Optional[str] = None,
    auto_start: bool = True,
    auto_pull: bool = True,
    on_status: Optional[Callable[[str], None]] = None,
) -> tuple[bool, str]:
    """
    Ensure Ollama is running and model is available.

    Returns (success, message).
    """
    if not is_running(host):
        if not auto_start:
            return False, (
                f"Ollama not running at {ollama_native_url(host)}. "
                "Start it with: ollama serve"
            )
        if not _find_ollama_binary():
            return False, (
                "Ollama is not installed. Install from https://ollama.com "
                "or pass --base-url / --no-llm"
            )
        if on_status:
            on_status("Starting Ollama in background...")
        if not start_background(host):
            return False, "Failed to start Ollama background service"

    if on_status:
        on_status(f"Ollama ready at {ollama_native_url(host)}")

    if not model_available(model, host):
        if not auto_pull:
            return False, (
                f"Model '{model}' not found. Pull it with: ollama pull {model}"
            )
        if on_status:
            on_status(f"Pulling model {model} (first run may take a few minutes)...")
        if not pull_model(model, host, on_status):
            return False, f"Failed to pull model '{model}'"

    return True, f"Using Ollama model {model}"
