"""
Fingerprinting for well-known deliberately-vulnerable training apps.

Some popular targets (OWASP Juice Shop, BadStore, DVWA, ...) ship with NO
OpenAPI/Swagger spec and their real endpoints are triggered by client-side JS
(search boxes, login forms) that a static crawler often won't discover.
Rather than fail silently, --auto fingerprints the target and seeds its
well-known endpoints directly.
"""

from dataclasses import dataclass
from typing import Optional

import httpx


@dataclass
class KnownApp:
    """A fingerprinted training app and its well-known testable endpoints."""
    app_id: str
    name: str
    # (method, path, body, content_type) — body/content_type only for POST/PUT
    endpoints: list[tuple]


KNOWN_APPS: dict[str, KnownApp] = {
    "juice-shop": KnownApp(
        app_id="juice-shop",
        name="OWASP Juice Shop",
        endpoints=[
            # Classic UNION-based SQLi in product search
            ("GET", "/rest/products/search?q=apple", None, None),
            # Auth-bypass SQLi in login (' OR 1=1-- style)
            ("POST", "/rest/user/login",
             '{"email":"test@test.com","password":"test"}', "application/json"),
            # Other commonly-tested REST endpoints
            ("GET", "/rest/products/reviews?id=1", None, None),
            ("GET", "/rest/user/whoami", None, None),
            ("GET", "/api/Feedbacks?rating=1", None, None),
            ("GET", "/api/Products?name=1", None, None),
            ("GET", "/rest/user/security-question?email=admin@juice-sh.op", None, None),
            ("POST", "/api/Feedbacks",
             '{"comment":"1","rating":1}', "application/json"),
            ("PUT", "/rest/basket/1",
             '{"id":1}', "application/json"),
        ],
    ),
    "badstore": KnownApp(
        app_id="badstore",
        name="BadStore.net",
        endpoints=[
            # Classic cart SQLi
            ("GET", "/cgi-bin/badstore.cgi?action=cartadd&cartitem=1000", None, None),
            # Search SQLi
            ("GET", "/cgi-bin/badstore.cgi?action=search&searchquery=test", None, None),
            # Login form
            ("GET", "/cgi-bin/badstore.cgi?action=loginregister&email=test@test.com&password=test", None, None),
        ],
    ),
    "dvwa": KnownApp(
        app_id="dvwa",
        name="Damn Vulnerable Web Application",
        endpoints=[
            ("GET", "/vulnerabilities/sqli/?id=1&Submit=Submit", None, None),
            ("GET", "/vulnerabilities/sqli_blind/?id=1&Submit=Submit", None, None),
        ],
    ),
    "webgoat": KnownApp(
        app_id="webgoat",
        name="OWASP WebGoat",
        endpoints=[
            ("GET", "/WebGoat/SqlInjection/attack5a?account=Smith", None, None),
        ],
    ),
}


def fingerprint(site: str, timeout: float = 10.0, headers: Optional[dict] = None) -> Optional[str]:
    """
    Probe a target for signatures of well-known vulnerable training apps.
    Returns the app_id (e.g. "juice-shop") or None if unrecognized.
    """
    site = site.rstrip("/")
    with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
        # Juice Shop: /rest/admin/application-version is unique to this app
        # and returns {"version": "..."} with no authentication required.
        try:
            r = client.get(f"{site}/rest/admin/application-version", headers=headers or {})
            if r.status_code == 200 and "version" in r.text.lower():
                return "juice-shop"
        except httpx.HTTPError:
            pass

        # Homepage text fingerprints for apps without a unique API marker
        try:
            r = client.get(site, headers=headers or {})
            body = r.text.lower()
            if "badstore.net" in body or "badstore" in body:
                return "badstore"
            if "damn vulnerable web application" in body or "dvwa" in body:
                return "dvwa"
            if "webgoat" in body:
                return "webgoat"
            if "juice shop" in body or "juice-sh.op" in body:
                return "juice-shop"
        except httpx.HTTPError:
            pass

    return None


def get_seed_urls(site: str, app_id: str) -> list[tuple]:
    """
    Return (method, full_url, body, content_type) tuples for a known app's
    well-known endpoints, ready to feed into the scanner.
    """
    app = KNOWN_APPS.get(app_id)
    if not app:
        return []
    site = site.rstrip("/")
    return [(method, f"{site}{path}", body, ct) for method, path, body, ct in app.endpoints]
