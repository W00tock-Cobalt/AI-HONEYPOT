"""
Authentication support for authenticated scanning.

Obtains a session token (JWT/bearer) by POSTing credentials to a login
endpoint and extracting the token from the JSON response, then exposes it as
an Authorization header applied to every subsequent request. This roughly
doubles the reachable attack surface: endpoints that 401/403 unauthenticated
(baskets, orders, profile, admin) become testable once a token is attached.
"""

import json
from typing import Any, Optional

import httpx

# JSON paths where auth tokens are commonly returned, in priority order.
# Each entry is a list of keys to walk down the response object.
_TOKEN_PATHS: list[list[str]] = [
    ["authentication", "token"],   # OWASP Juice Shop
    ["token"],
    ["access_token"],
    ["accessToken"],
    ["data", "token"],
    ["data", "access_token"],
    ["jwt"],
    ["id_token"],
    ["auth", "token"],
    ["result", "token"],
]


def _dig(obj: Any, path: list[str]) -> Optional[str]:
    """Walk a nested dict by key path; return a string leaf or None."""
    cur = obj
    for key in path:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return None
    return cur if isinstance(cur, str) and cur else None


def extract_token(response_text: str, explicit_path: Optional[str] = None) -> Optional[str]:
    """
    Extract an auth token from a JSON response body.

    explicit_path: optional dotted path (e.g. 'authentication.token') to try
    first before the built-in common paths.
    """
    try:
        data = json.loads(response_text)
    except (json.JSONDecodeError, ValueError):
        return None

    if explicit_path:
        val = _dig(data, explicit_path.split("."))
        if val:
            return val

    for path in _TOKEN_PATHS:
        val = _dig(data, path)
        if val:
            return val
    return None


def obtain_token(
    login_url: str,
    login_data: str,
    headers: Optional[dict[str, str]] = None,
    token_path: Optional[str] = None,
    timeout: float = 15.0,
    verify_ssl: bool = True,
    proxy: Optional[str] = None,
) -> tuple[Optional[str], str]:
    """
    POST credentials to a login endpoint and extract an auth token.

    login_data may be JSON ('{"email":...}') or form ('user=...&pass=...').
    Returns (token, message). token is None on failure; message explains why.
    """
    kwargs: dict[str, Any] = {
        "timeout": timeout, "verify": verify_ssl, "follow_redirects": True,
    }
    if proxy:
        kwargs["proxy"] = proxy

    hdrs = dict(headers or {})
    is_json = login_data.strip().startswith("{")
    if is_json and not any(k.lower() == "content-type" for k in hdrs):
        hdrs["Content-Type"] = "application/json"

    try:
        with httpx.Client(**kwargs) as c:
            if is_json:
                resp = c.post(login_url, content=login_data, headers=hdrs)
            else:
                from urllib.parse import parse_qsl
                resp = c.post(login_url, data=dict(parse_qsl(login_data)), headers=hdrs)
    except httpx.HTTPError as e:
        return None, f"login request failed: {e}"

    token = extract_token(resp.text, token_path)
    if token:
        return token, f"obtained token via {login_url} (HTTP {resp.status_code})"
    return None, (
        f"login returned HTTP {resp.status_code} but no token found in response "
        f"(tried common JSON paths). Body starts: {resp.text[:100]}"
    )


def apply_bearer(headers: dict[str, str], token: str, header_name: str = "Authorization",
                 scheme: str = "Bearer") -> dict[str, str]:
    """Return a copy of headers with the auth token attached."""
    out = dict(headers)
    out[header_name] = f"{scheme} {token}".strip() if scheme else token
    return out
