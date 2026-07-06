"""Organic content / endpoint discovery (directory brute-forcing).

Probes a built-in (or user-supplied) wordlist of common web/API paths against
the target to discover endpoints WITHOUT any per-app hardcoding — so injectable
routes like ``/api/products/search`` or ``/api/testimonials/count`` are found
organically rather than seeded.

Key robustness feature: **soft-404 detection**. Single-page apps (Juice Shop,
BrokenCrystals, most React/Angular sites) return ``index.html`` with HTTP 200
for *every* unknown route, so a naive "200 = exists" check yields thousands of
false hits. We first fingerprint the response for a random non-existent path
and only keep candidates whose response differs materially from that soft-404
template.
"""

from __future__ import annotations

import concurrent.futures
import random
import string
from urllib.parse import urljoin, urlparse

import httpx

# API path prefixes to combine with resource names.
_API_PREFIXES = ["api", "rest", "api/v1", "api/v2", "v1", "v2", "graphql", ""]

# Common REST resource / collection names (singular + plural) seen in real apps
# and deliberately-vulnerable targets. Ordered roughly by how often they carry
# injectable input.
_RESOURCES = [
    "products", "product", "users", "user", "search", "testimonials",
    "testimonial", "partners", "partner", "orders", "order", "customers",
    "customer", "items", "item", "categories", "category", "comments",
    "comment", "reviews", "review", "feedbacks", "feedback", "posts", "post",
    "articles", "article", "pages", "page", "news", "events", "event",
    "messages", "message", "notifications", "files", "file", "documents",
    "images", "media", "uploads", "cart", "carts", "basket", "baskets",
    "wishlist", "invoices", "invoice", "payments", "payment", "transactions",
    "accounts", "account", "profile", "profiles", "settings", "config",
    "admin", "auth", "login", "logout", "register", "signup", "session",
    "token", "tokens", "keys", "roles", "permissions", "groups", "teams",
    "companies", "company", "employees", "employee", "tags", "tag", "stats",
    "count", "views", "latest", "featured", "popular", "recent", "all",
    "list", "export", "import", "report", "reports", "logs", "audit",
    "coupons", "discounts", "shipping", "addresses", "address", "cards",
    "wallet", "balance", "history", "activity", "subscriptions", "plans",
]

# Bare web paths (not resource-combined) worth probing directly.
_WEB_PATHS = [
    "admin", "login", "signin", "register", "dashboard", "search",
    "config", "configuration", "settings", "status", "health", "healthz",
    "metrics", "debug", "test", "graphql", "graphiql", "swagger",
    "swagger-ui", "swagger.json", "swagger-json", "openapi.json",
    "api-docs", "api/spec", "spec", ".env", "robots.txt", "sitemap.xml",
    "phpinfo.php", "server-status", "actuator", "actuator/health",
    "cgi-bin", "wp-json", "wp-admin", "administrator", "user", "users",
    "account", "profile", "upload", "uploads", "files", "download",
]


def _rand(n: int = 12) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _fp(resp) -> tuple[int, int]:
    """A coarse response fingerprint (status, length-bucket) for soft-404 diffing."""
    try:
        body_len = len(resp.text)
    except Exception:
        body_len = 0
    # Bucket length to tolerate tiny per-request variance (dates, nonces).
    return (resp.status_code, body_len // 64)


def _candidate_paths(extra_words: list[str] | None) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()

    def add(p: str) -> None:
        p = p.strip("/")
        if p and p not in seen:
            seen.add(p)
            paths.append(p)

    for res in _RESOURCES:
        for pref in _API_PREFIXES:
            add(f"{pref}/{res}" if pref else res)
    for wp in _WEB_PATHS:
        add(wp)
    # A couple of common nested sub-resources on the top collections.
    for res in ("products", "users", "testimonials", "partners", "orders"):
        for sub in ("search", "count", "views", "latest", "all", "1"):
            add(f"api/{res}/{sub}")
            add(f"rest/{res}/{sub}")
    for word in (extra_words or []):
        add(word)
    return paths


def discover_paths(
    base_url: str,
    headers: dict[str, str] | None = None,
    verify_ssl: bool = True,
    proxy: str | None = None,
    timeout: float = 6.0,
    max_workers: int = 40,
    extra_words: list[str] | None = None,
    on_status=None,
) -> list[str]:
    """Brute-force common paths against ``base_url``; return live URLs.

    Live = response materially different from the soft-404 template for a random
    path (different status, or different length bucket for same status).
    """
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}/"
    log = on_status or (lambda _m: None)

    client_kwargs: dict = {"timeout": timeout, "verify": verify_ssl, "follow_redirects": True}
    if proxy:
        client_kwargs["proxy"] = proxy

    # 1. Soft-404 template(s): fingerprint a couple of random non-existent paths.
    soft404: set[tuple[int, int]] = set()
    try:
        with httpx.Client(**client_kwargs) as c:
            for _ in range(2):
                r = c.get(urljoin(root, _rand()), headers=headers or {})
                soft404.add(_fp(r))
    except (httpx.HTTPError, OSError):
        pass

    candidates = _candidate_paths(extra_words)
    total = len(candidates)
    log(f"[*] Content discovery: probing {total} paths "
        f"(soft-404 filtered)...")

    # One shared client (httpx.Client is thread-safe for requests) — avoids
    # building a fresh connection pool per probe.
    shared = httpx.Client(**client_kwargs)

    def check(path: str):
        url = urljoin(root, path)
        try:
            r = shared.get(url, headers=headers or {})
        except (httpx.HTTPError, OSError):
            return None
        if r.status_code in (404, 0):
            return None
        if _fp(r) in soft404:
            return None
        return (url, r.status_code)

    live: list[tuple[str, int]] = []
    done = 0
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = [ex.submit(check, p) for p in candidates]
            for fut in concurrent.futures.as_completed(futures):
                done += 1
                # Heartbeat so a slow/rate-limited target doesn't LOOK hung.
                if done % 150 == 0 or done == total:
                    log(f"    [content discovery] {done}/{total} probed, "
                        f"{len(live)} live so far")
                try:
                    res = fut.result()
                except Exception:
                    res = None
                if res is not None:
                    live.append(res)
    finally:
        shared.close()

    live.sort(key=lambda t: t[0])
    return [u for u, _ in live]
