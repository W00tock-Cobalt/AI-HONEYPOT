"""Organic parameter discovery.

Instead of relying only on a static wordlist (`COMMON_PARAMS`) or hardcoded
per-app maps, this module derives candidate injectable parameter names from the
*target's own responses*. That is the "find them organically" approach:

- HTML forms: ``<input>``/``<select>``/``<textarea>``/``<button>`` ``name=``
  attributes and ``<form action=>`` targets.
- Anchor / link / script / img / iframe URLs that carry a query string
  (``?foo=1&bar=2``) — every key becomes a candidate, and the parameterized
  URLs themselves are surfaced as additional targets.
- Inline JavaScript: ``fetch("/api?x=1")``, ``axios.get('...')``, string
  literals containing ``?a=b`` style query fragments, and object keys used in
  request config.
- JSON API responses: object keys (e.g. a listing endpoint that returns
  ``[{"name":..,"price":..}]`` reveals ``name``/``price`` as fields the backend
  understands and may sort/filter on).

The result is a *page-derived wordlist* that adapts to whatever the target
actually exposes — so the scanner works on arbitrary apps without the tests
being baked in.
"""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse

# Parameter names that are never worth injecting (framework/analytics noise).
# Kept intentionally tiny — this is a denylist of obvious junk, NOT a wordlist.
_NOISE_PARAMS = frozenset({
    "csrf", "csrftoken", "csrf_token", "_csrf", "authenticity_token",
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "_", "_ga", "_gid", "fbclid", "gclid", "v", "ver", "version", "cb",
    "cachebuster", "cache", "nocache", "t", "ts", "timestamp", "rand",
})

# A valid HTTP parameter / form field / JSON key name we'd consider injecting.
_NAME_RE = re.compile(r"^[A-Za-z_][\w\-.\[\]]{0,39}$")

# Query fragments embedded anywhere in a response body (JS fetch URLs, hrefs
# written by scripts, etc.): capture the "?a=b&c=d" portion.
_QS_IN_TEXT_RE = re.compile(r"[?&]([A-Za-z_][\w\-.]{0,39})=")

# `paramName:` / `"paramName":` object keys inside inline JS/JSON config that
# sit next to obvious request builders. Broad on purpose but filtered by
# _looks_like_param below.
_JS_KEY_RE = re.compile(r"""['"]?([A-Za-z_][\w\-.]{0,39})['"]?\s*:""")


def _looks_like_param(name: str) -> bool:
    """Heuristic: is this a plausible injectable parameter name?"""
    if not name or not _NAME_RE.match(name):
        return False
    low = name.lower()
    if low in _NOISE_PARAMS:
        return False
    # Pure numbers / single chars that slipped past the regex anchor
    if name.isdigit():
        return False
    return True


class _Form:
    """A parsed HTML form: method, action and its field names."""

    def __init__(self, method: str, action: str) -> None:
        self.method = (method or "GET").upper()
        self.action = action
        self.fields: list[str] = []
        # Pre-filled values (hidden fields, selected options, defaults). These
        # MUST be preserved when submitting — e.g. a CGI's hidden action=register
        # selects which server-side handler runs; overwriting it with a test
        # value would hit the wrong (or no) handler and miss the injection.
        self.values: dict[str, str] = {}


class _FormParser(HTMLParser):
    """Collect forms (method/action/fields) and any query-carrying URLs."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.param_names: list[str] = []
        self.link_urls: list[str] = []   # <a>/<link>/<script src> with a query
        self.forms: list[_Form] = []
        self._seen_names: set[str] = set()
        self._cur: _Form | None = None

    def _add_name(self, name: str | None) -> None:
        if not name or not _looks_like_param(name):
            return
        if self._cur is not None and name not in self._cur.fields:
            self._cur.fields.append(name)
        if name not in self._seen_names:
            self._seen_names.add(name)
            self.param_names.append(name)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        d = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            # A new form starts; close any unterminated previous one.
            self._cur = _Form(d.get("method", "GET"), d.get("action", ""))
            self.forms.append(self._cur)
        elif tag in ("input", "select", "textarea", "button"):
            itype = d.get("type", "").lower()
            if itype in ("submit", "reset", "button", "image"):
                # Buttons don't carry injectable data — skip as candidates
                # but they don't hurt if we only use them for names.
                return
            name = d.get("name") or d.get("id")
            self._add_name(name)
            # Preserve any pre-filled value (hidden fields, defaults) so form
            # submission keeps required selectors (e.g. action=register).
            if name and self._cur is not None:
                val = d.get("value", "")
                if val != "":
                    self._cur.values[name] = val
        elif tag in ("a", "link", "area"):
            href = d.get("href")
            if href and "?" in href:
                self.link_urls.append(href)
        elif tag in ("script", "img", "iframe", "source"):
            src = d.get("src")
            if src and "?" in src:
                self.link_urls.append(src)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._cur = None


def _parse_html(html: str) -> _FormParser:
    parser = _FormParser()
    try:
        parser.feed(html)
    except Exception:
        # Malformed HTML — keep whatever parsed before the error.
        pass
    return parser


class _HiddenFieldParser(HTMLParser):
    """Collect ``name -> value`` for form inputs that already carry a value.

    Used for CSRF/anti-forgery tokens (``user_token``, ``csrf_token``,
    ``authenticity_token``, ``_token`` …) and other pre-filled hidden fields
    that must be echoed back for a login POST to succeed.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in ("input", "textarea"):
            return
        d = {k.lower(): (v or "") for k, v in attrs}
        name = d.get("name")
        if not name:
            return
        itype = d.get("type", "").lower()
        # Skip fields the caller supplies themselves (creds/submit buttons).
        if itype in ("submit", "reset", "button", "image", "file"):
            return
        value = d.get("value", "")
        # Only keep fields that actually have a value (tokens, hidden state).
        if value != "" and name not in self.fields:
            self.fields[name] = value


def hidden_form_fields(html: str) -> dict[str, str]:
    """Return pre-filled form field values (CSRF tokens, hidden state) from HTML.

    This lets a login POST automatically carry anti-CSRF tokens (e.g. DVWA's
    ``user_token``) that a static ``--login-data`` string can't know in advance.
    """
    p = _HiddenFieldParser()
    try:
        p.feed(html or "")
    except Exception:
        pass
    return p.fields


def _params_from_query_strings(text: str) -> list[str]:
    """Pull param names out of any ?a=b&c=d fragments in the text."""
    names: list[str] = []
    seen: set[str] = set()
    for m in _QS_IN_TEXT_RE.finditer(text):
        name = m.group(1)
        if name not in seen and _looks_like_param(name):
            seen.add(name)
            names.append(name)
    return names


def _params_from_json(text: str, limit: int = 60) -> list[str]:
    """Extract object keys from a JSON document (recursively, deduped)."""
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return []

    names: list[str] = []
    seen: set[str] = set()

    def walk(node, depth: int = 0) -> None:
        if len(names) >= limit or depth > 6:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(k, str) and k not in seen and _looks_like_param(k):
                    seen.add(k)
                    names.append(k)
                walk(v, depth + 1)
        elif isinstance(node, list):
            for item in node[:20]:
                walk(item, depth + 1)

    walk(obj)
    return names


def _same_host_abs(raw: str, base_url: str) -> str | None:
    """Resolve ``raw`` against base and return it only if same-host + http(s)."""
    raw = raw.strip()
    if not raw or raw.startswith(("mailto:", "javascript:", "tel:", "#", "data:")):
        return None
    try:
        absu = urljoin(base_url, raw)
    except ValueError:
        return None
    parsed = urlparse(absu)
    if parsed.scheme not in ("http", "https", ""):
        return None
    base_host = urlparse(base_url).netloc
    if parsed.netloc and parsed.netloc != base_host:
        return None
    return absu


def _form_target(form: _Form, base_url: str) -> str | None:
    """Build a scannable GET URL from a form: action + '?field=1&...'.

    Only GET forms are turned into query targets (POST forms are handled by
    the scanner's own POST/body path when the endpoint is scanned). Returns
    ``None`` when there is nothing useful to build.
    """
    if form.method != "GET" or not form.fields:
        return None
    absu = _same_host_abs(form.action or base_url, base_url)
    if not absu:
        return None
    parsed = urlparse(absu)
    existing = parse_qs(parsed.query, keep_blank_values=True)
    for f in form.fields:
        existing.setdefault(f, ["1"])
    from urllib.parse import urlencode, urlunparse
    new_q = urlencode({k: v[0] for k, v in existing.items()})
    return urlunparse(parsed._replace(query=new_q))


def _post_form_targets(parser: "_FormParser", base_url: str) -> list[tuple[str, str, str]]:
    """Build POST scan targets from ``<form method=post>`` elements.

    Returns ``(url, body, content_type)`` tuples where ``body`` pre-fills every
    field with a test value. This is fully organic: it discovers login/cart/
    order/supplier POST forms (and CGI ``?action=`` forms, whose action URL
    already carries the action) on any HTML app, no per-app knowledge needed.
    """
    from urllib.parse import urlencode
    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for form in parser.forms:
        if form.method != "POST" or not form.fields:
            continue
        absu = _same_host_abs(form.action or base_url, base_url)
        if not absu:
            continue
        # Preserve pre-filled/hidden values (e.g. action=register); seed the
        # remaining (injectable) fields with a test value.
        body = urlencode({f: form.values.get(f, "1") for f in form.fields})
        key = absu + "|" + body
        if key not in seen:
            seen.add(key)
            out.append((absu, body, "application/x-www-form-urlencoded"))
    return out


def discover(
    base_url: str,
    body: str,
    content_type: str = "",
    max_params: int = 40,
) -> tuple[list[str], list[str], list[tuple[str, str, str]]]:
    """Discover candidate parameters and scannable targets from a response.

    Returns ``(param_names, target_urls, post_forms)`` where:
      - ``param_names`` are page-derived candidate parameter names to test on
        the CURRENT url (form fields first, then query-string keys, then JSON
        keys), deduped and capped at ``max_params``.
      - ``target_urls`` are additional same-host GET URLs worth scanning that
        the page pointed at: GET-form actions pre-filled with their fields, and
        any anchor/script URL that already carries a query string.
      - ``post_forms`` are ``(url, body, content_type)`` for discovered POST
        forms, so the caller can scan their body params.
    """
    if not body:
        return [], [], []

    ct = (content_type or "").lower()
    ordered: list[str] = []
    seen: set[str] = set()

    def extend(names: list[str]) -> None:
        for n in names:
            if n not in seen:
                seen.add(n)
                ordered.append(n)

    target_urls: list[str] = []
    seen_urls: set[str] = set()
    post_forms: list[tuple[str, str, str]] = []

    def add_url(u: str | None) -> None:
        if u and u not in seen_urls:
            seen_urls.add(u)
            target_urls.append(u)

    looks_json = "json" in ct or body.lstrip()[:1] in ("{", "[")
    if looks_json:
        extend(_params_from_json(body))
    else:
        parser = _parse_html(body)
        extend(parser.param_names)
        # GET forms → scannable "action?field=1" targets
        for form in parser.forms:
            add_url(_form_target(form, base_url))
        # POST forms → POST scan targets with their fields (organic).
        post_forms = _post_form_targets(parser, base_url)
        # Anchor/script URLs carrying a query string → scannable targets
        for raw in parser.link_urls:
            absu = _same_host_abs(raw, base_url)
            if absu and urlparse(absu).query:
                add_url(absu)

    # Query-string fragments live in both HTML (script-built URLs) and JS.
    extend(_params_from_query_strings(body))

    # Param names off any resolved parameterized URL are strong signals too.
    for u in target_urls:
        extend(list(parse_qs(urlparse(u).query, keep_blank_values=True).keys()))

    return ordered[:max_params], target_urls, post_forms
