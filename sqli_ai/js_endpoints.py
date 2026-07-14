"""Organic API-endpoint extraction from JavaScript.

Single-page apps (Angular/React/Vue: OWASP Juice Shop, most modern targets)
build their API calls *at runtime* inside bundled JS, so a DOM/link crawler
never sees routes like ``/rest/products/search?q=`` — they exist only as string
literals inside ``main.js``. This module fetches a page's same-host ``<script
src>`` bundles (plus any inline script) and regex-mines endpoint paths and
fetch/axios/XHR URLs out of them.

This is the LinkFinder / jsluice technique: fully generic, no per-app knowledge.
The same extractor works on any site — it just reads the app's own code to learn
which endpoints (and query params) it talks to.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import httpx

# Quoted string literals that look like an API path: start with "/", contain at
# least one more path segment, and are not a static asset or bare root. Captures
# an optional query string so "/rest/products/search?q=" keeps its param name.
_PATH_LITERAL = re.compile(
    r"""['"`]"""                      # opening quote
    r"""((?:\$\{[^}]*\}|/)*"""        # optional leading ${host}/ interpolations
    r"""/(?:rest|api|graphql|v\d+|cgi-bin|services?|internal|admin)"""  # api-ish root
    r"""[A-Za-z0-9_\-./${}]*"""       # more path (may contain ${...})
    r"""(?:\?[A-Za-z0-9_\-=&%.:+${}]*)?)"""  # optional query string
    r"""['"`]""",                     # closing quote
    re.IGNORECASE,
)

# fetch()/axios.get()/http.get()/XHR.open() call targets, but ONLY when the
# argument is a root-relative path ("/..."). Requiring the leading slash rejects
# the flood of non-URL string args (event names, i18n keys, CSS selectors) that
# a looser pattern would wrongly capture as "/ADDRESS_ADDED"-style junk.
_CALL_TARGET = re.compile(
    r"""(?:fetch|axios(?:\.(?:get|post|put|delete|patch|request))?|"""
    r"""http\.(?:get|post|put|delete|patch)|\.open|url\s*[:=])\s*"""
    r"""\(?\s*['"`](/[^'"`\s)]*)['"`]""",
    re.IGNORECASE,
)

# Any absolute-path literal carrying a query string — a strong injectable signal
# regardless of the path root ("/search?term=", "/list.php?id="). Allows ${...}
# interpolation inside, which is salvaged (stripped) downstream.
_QS_PATH_LITERAL = re.compile(
    r"""['"`](/[A-Za-z0-9_\-./${}]+\?[A-Za-z0-9_\-=&%.:+${}]+)['"`]""",
)

# JS template interpolations to strip so "/${this.host}/rest/products/search?q=${e}"
# salvages to "/rest/products/search?q=". Covers ${...}, #{...}, {{...}}, :param.
_INTERP = re.compile(r"\$\{[^}]*\}|#\{[^}]*\}|\{\{[^}]*\}\}")
_MULTISLASH = re.compile(r"/{2,}")
# After salvage, a real endpoint path contains only URL-safe chars. Anything with
# JS syntax (comma, paren, brace, space, operators, backtick) is a code fragment.
_VALID_PATH = re.compile(r"^/[A-Za-z0-9_\-./%]*$")
_VALID_QKEY = re.compile(r"^[A-Za-z0-9_\-.%\[\]]+$")

_STATIC_RE = re.compile(
    r"\.(?:js|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|mp4|webp|"
    r"webmanifest|json|xml|txt|scss|less)(?:$|\?)",
    re.IGNORECASE,
)

# Path segments that are never an injectable API endpoint.
_NOISE_SEGS = (
    "/assets/", "/static/", "/node_modules/", "/fonts/", "/images/",
    "/img/", "/css/", "/js/", "/vendor/", "/dist/", "//",
)


def _salvage(raw: str) -> str | None:
    """Turn a raw captured literal into a clean root-relative endpoint, or None.

    Strips JS template interpolations (``${...}``), collapses the resulting
    ``//``, then structurally validates the path and query so code fragments
    (commas, parens, operators) are rejected — only genuine endpoints survive.
    """
    raw = _INTERP.sub("", raw).strip()
    if not raw.startswith("/"):
        return None
    path, _, query = raw.partition("?")
    path = _MULTISLASH.sub("/", path) or "/"
    if not _VALID_PATH.match(path):
        return None
    if query:
        # Keep only well-formed key(=value) pairs; drop the value (we inject our
        # own), keep the key so the scanner knows the param name.
        keys = []
        for pair in query.split("&"):
            k = pair.split("=", 1)[0]
            if k and _VALID_QKEY.match(k):
                keys.append(k)
        query = "&".join(f"{k}=1" for k in keys) if keys else ""
    out = path + (f"?{query}" if query else "")
    return out if _plausible_endpoint(out) else None


def _plausible_endpoint(path: str) -> bool:
    """True if ``path`` looks like a real, testable endpoint (not an asset)."""
    bare = path.split("?", 1)[0]
    if not bare.startswith("/") or bare == "/":
        return False
    if _STATIC_RE.search(bare):
        return False
    low = bare.lower()
    if any(seg in low for seg in _NOISE_SEGS):
        return False
    # Must contain at least one letter (drop "/1", "/2" numeric-only unless it
    # carries a query string, which is independently interesting).
    if "?" not in path and not re.search(r"[A-Za-z]", bare):
        return False
    # Every path segment should look like an identifier — this rejects lingering
    # minified-code fragments that slipped through with only URL-safe chars.
    segs = [s for s in bare.split("/") if s]
    if any(len(s) > 40 for s in segs):
        return False
    if len(path) > 180:
        return False
    return True


def extract_endpoints(text: str) -> set[str]:
    """Regex-mine endpoint paths (root-relative, may include a query) from JS/HTML."""
    found: set[str] = set()
    for rx in (_PATH_LITERAL, _QS_PATH_LITERAL, _CALL_TARGET):
        for m in rx.finditer(text):
            clean = _salvage(m.group(1))
            if clean:
                found.add(clean)
    return found


def _script_srcs(html: str) -> list[str]:
    """Extract ``<script src=...>`` values from an HTML page (order preserved)."""
    return re.findall(r"<script[^>]+src=['\"]([^'\"]+)['\"]", html, re.IGNORECASE)


def discover_js_endpoints(
    base_url: str,
    html: str,
    client: httpx.Client,
    headers: dict[str, str] | None = None,
    max_scripts: int = 12,
    max_bytes: int = 3_000_000,
) -> set[str]:
    """Fetch a page's same-host JS bundles and mine API endpoints from them.

    Returns absolute, same-host URLs (each is the app's own declared endpoint,
    with any query string preserved so its param names are known). Bounded to
    ``max_scripts`` bundles and ``max_bytes`` per bundle so a huge vendor blob
    can't stall discovery.
    """
    base_host = urlparse(base_url).netloc
    out: set[str] = set()

    # Inline scripts in the page itself.
    for rel in extract_endpoints(html):
        absu = urljoin(base_url, rel)
        if urlparse(absu).netloc == base_host:
            out.add(absu)

    # External same-host bundles.
    srcs = _script_srcs(html)
    fetched = 0
    for src in srcs:
        if fetched >= max_scripts:
            break
        absu = urljoin(base_url, src)
        if urlparse(absu).netloc != base_host:
            continue  # skip CDNs / third-party
        try:
            r = client.get(absu, headers=headers or {})
        except (httpx.HTTPError, OSError):
            continue
        fetched += 1
        body = r.text
        if len(body) > max_bytes:
            body = body[:max_bytes]
        for rel in extract_endpoints(body):
            eabs = urljoin(base_url, rel)
            if urlparse(eabs).netloc == base_host:
                out.add(eabs)
    return out
