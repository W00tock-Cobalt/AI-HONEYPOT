"""HTTP probing and parameter injection."""

import json
import time
from copy import deepcopy
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from sqli_ai.models import HttpExchange, InjectionPoint, ParamLocation


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    """Parse a Retry-After header (delta-seconds form) into seconds, or None.

    Only the numeric-seconds form is honored; HTTP-date form is ignored (falls
    back to exponential backoff). Never returns a negative or absurd value.
    """
    if not value:
        return None
    try:
        secs = float(value.strip())
    except (ValueError, AttributeError):
        return None
    if secs < 0:
        return None
    return min(secs, 30.0)

# CGI/web-app action → likely injectable params (for ?action=X style apps like BadStore).
# When katana finds /page.cgi?action=search but no searchquery param in the URL,
# these will be probed first before the generic param wordlist.
_ACTION_PARAM_MAP: dict[str, list[str]] = {
    "search":        ["searchquery", "q", "query", "keyword", "search", "term"],
    "cartadd":       ["cartitem", "item", "itemid", "product", "pid", "qty"],
    "login":         ["email", "username", "user", "password", "pass"],
    "loginregister": ["email", "username", "user", "password"],
    "register":      ["email", "username", "user", "password", "firstname"],
    "viewprevious":  ["email", "user", "orderid", "order_id"],
    "supplierlogin": ["email", "username", "user", "password"],
    "guestbook":     ["message", "name", "email", "comment"],
    "whatsnew":      ["cat", "category", "id", "pid"],
    "myaccount":     ["email", "user", "id"],
}


# Cap on guessed params tried against a generic URL (no existing params, no
# recognised ?action=). Prevents a single slow/SPA URL from ballooning into
# 90+ precheck rounds; COMMON_PARAMS is ordered with the most likely SQLi
# vectors first, so a smaller slice still covers the common cases.
_MAX_GUESS_PARAMS_GENERIC = 25

# Cap on guessed params for a URL that ALREADY carries real params (from a
# spec/crawl). We used to mine the entire wordlist here, which turned a single
# parameterized REST endpoint into ~180 precheck requests (93 params x ~2) and
# dominated scan time. Organic discovery already surfaces the app-specific
# param names, so a focused slice of the most common SQLi vectors is enough.
_MAX_GUESS_PARAMS_PARAMD = 30

# Common HTTP headers that back-ends frequently trust and interpolate into SQL
# (logging, geo/IP lookups, analytics, feature flags). Tested organically as
# injection points so header-based SQLi (e.g. an app that looks up a product by
# a custom header, or logs X-Forwarded-For into a query) is caught without a
# spec. Values are plausible defaults so the request stays well-formed.
_COMMON_INJECTABLE_HEADERS: list[tuple[str, str]] = [
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Forwarded-Host", "localhost"),
    ("Referer", "https://www.google.com/"),
    ("X-Real-IP", "127.0.0.1"),
    ("Client-IP", "127.0.0.1"),
    ("X-Api-Version", "1"),
]


class HttpProbe:
    """Send HTTP requests with payload injection at specific points."""

    def __init__(
        self,
        timeout: float = 15.0,
        verify_ssl: bool = True,
        proxy: Optional[str] = None,
        default_headers: Optional[dict[str, str]] = None,
        cookies: Optional[dict[str, str]] = None,
        max_retries: int = 2,
    ):
        self.timeout = timeout
        self.default_headers = default_headers or {}
        self.cookies = cookies or {}
        # Transient-failure retries. Shared demo hosts (Heroku/Cloud Run dynos,
        # rate-limited instances) throw sporadic 502/503/504, connection resets
        # and timeouts. Treating one of those as a real response poisons the
        # baseline or drops an endpoint, which is THE main cause of run-to-run
        # inconsistency. Retrying transient failures a couple times makes scans
        # deterministic on flaky targets.
        self.max_retries = max_retries
        # Host-wide block detection: a target that keeps returning 403/429 has
        # blocked us (WAF/rate-limit), not hiccupped. Track consecutive blocks so
        # we fail fast instead of burning full backoff on every request, and so
        # the caller can warn loudly. Reset on any normal (<500) response.
        self._consec_block = 0
        self.host_blocked = False
        # Cap the CONNECT phase hard (<=8s) so a dead/stalling host can't burn
        # the full read timeout (×retries) just establishing a TCP connection —
        # a live host connects in well under a second, so this only bites
        # unreachable endpoints (and keeps them from looking like a hang).
        client_kwargs: dict[str, Any] = {
            "timeout": httpx.Timeout(timeout, connect=min(8.0, timeout)),
            "verify": verify_ssl,
            "follow_redirects": True,
        }
        if proxy:
            client_kwargs["proxy"] = proxy
        self._client = httpx.Client(**client_kwargs)

    def close(self):
        self._client.close()

    def extract_injection_points(
        self,
        url: str,
        method: str = "GET",
        data: Optional[str] = None,
        content_type: Optional[str] = None,
        extra_headers: Optional[dict[str, str]] = None,
        test_path: bool = False,
        path_all_segments: bool = False,
        guess_params: Optional[list[str]] = None,
        discovered_params: Optional[list[str]] = None,
        test_headers: bool = False,
    ) -> list[InjectionPoint]:
        """Discover injectable parameters from URL path, query, body, headers.

        ``discovered_params`` are parameter names harvested organically from the
        target's own response (forms/links/JS/JSON) — see param_discovery. They
        are tested with priority over the static wordlist because the target
        itself advertised them, and (unlike guess_params) they are used even
        when generic parameter mining is off.
        """
        points: list[InjectionPoint] = []

        parsed = urlparse(url)

        # sqlmap-style '*' marker: only the marked spot is tested
        if "*" in parsed.path or "*" in (parsed.query or ""):
            points.extend(self._marked_points(parsed))
            if points:
                return points

        query = parse_qs(parsed.query, keep_blank_values=True)
        # `existing` tracks names already added (for dedup). `url_existing`
        # tracks ONLY the URL's real query params — the mining heuristics below
        # key off it so organic additions don't flip a bare endpoint into the
        # "full wordlist" branch.
        url_existing = set(query.keys())
        existing = set(query.keys())
        for name, values in query.items():
            points.append(InjectionPoint(
                name=name,
                location=ParamLocation.QUERY,
                original_value=values[0] if values else "",
            ))

        # Organically discovered params (from the page itself) always get tested
        # as query params when the URL doesn't already carry them — this is the
        # "works on anything" path that doesn't depend on the static wordlist.
        for name in (discovered_params or []):
            if name not in existing:
                existing.add(name)
                points.append(InjectionPoint(
                    name=name,
                    location=ParamLocation.QUERY,
                    original_value="1",
                ))

        # Parameter mining: add common param names the URL doesn't expose.
        if guess_params:
            import re as _re
            # For CGI ?action=X URLs, prioritise the action-specific params first
            am = _re.search(r"[?&]action=([^&]+)", "?" + parsed.query)
            action_val = am.group(1).lower() if am else ""
            priority = _ACTION_PARAM_MAP.get(action_val, [])

            # For bare REST API paths (/api/X, /rest/X) with no existing params,
            # only try a small focused set to avoid 90+ requests per endpoint.
            # The precheck will quickly skip dead ones anyway.
            path_lower = parsed.path.lower()
            is_rest_api = (
                not url_existing  # no real query params on the URL
                and not action_val
                and any(seg in path_lower for seg in ("/api/", "/rest/", "/v1/", "/v2/", "/graphql"))
            )
            if is_rest_api and not priority:
                # Short REST-focused list: search, filter, id, q are most common SQLi vectors
                candidate_params = ["q", "search", "query", "id", "filter", "name",
                                    "email", "username", "orderBy", "sort"]
            elif not url_existing and not action_val:
                # Generic page (no existing params, no known ?action=) — this is
                # usually an SPA route or static-ish page. Cap the guess list so
                # a single URL can't balloon into 90+ precheck rounds; the most
                # common SQLi param names are listed first in COMMON_PARAMS.
                candidate_params = list(guess_params)[:_MAX_GUESS_PARAMS_GENERIC]
            else:
                # URL already has real params (from a spec/crawl). Worth mining,
                # but cap it — organic discovery covers the app-specific names,
                # so a focused slice keeps the request count sane.
                candidate_params = list(guess_params)[:_MAX_GUESS_PARAMS_PARAMD]

            seen_params = set(existing)
            for name in priority + candidate_params:
                if name not in seen_params:
                    seen_params.add(name)
                    points.append(InjectionPoint(
                        name=name,
                        location=ParamLocation.QUERY,
                        original_value="1",
                        mined=True,  # speculative wordlist guess
                    ))

        # Path-segment injection. ID-like segments (numeric /42, UUID/long
        # alphanumeric tokens) are self-evidently injection points — they almost
        # always back a `WHERE id = <seg>` lookup — so they're ALWAYS tested,
        # organically, with no flag required (this is the common REST path-SQLi
        # spot that param/body-only scanners miss). --path / path_all only widen
        # testing to non-ID segments (the last segment, then every segment).
        seen_path_idx = set()
        for p in self._path_points(parsed, all_segments=False, ids_only=True):
            points.append(p)
            seen_path_idx.add(p.path_index)
        if test_path:
            for p in self._path_points(parsed, path_all_segments):
                if p.path_index not in seen_path_idx:
                    points.append(p)

        if data and method.upper() in ("POST", "PUT", "PATCH"):
            ct = (content_type or "").lower()
            if "json" in ct or (data.strip().startswith("{") and data.strip().endswith("}")):
                try:
                    obj = json.loads(data)
                    points.extend(self._json_paths(obj))
                except json.JSONDecodeError:
                    pass
            else:
                form = parse_qs(data, keep_blank_values=True)
                for name, values in form.items():
                    points.append(InjectionPoint(
                        name=name,
                        location=ParamLocation.BODY,
                        original_value=values[0] if values else "",
                    ))

        _skip_headers = {
            "host", "content-length", "content-type", "user-agent",
            "authorization", "accept", "accept-encoding", "connection",
        }
        if extra_headers:
            for name, value in extra_headers.items():
                if name.lower() not in _skip_headers:
                    points.append(InjectionPoint(
                        name=name,
                        location=ParamLocation.HEADER,
                        original_value=value,
                    ))

        # Common trusted headers (organic) — apps often interpolate these into
        # SQL (IP/geo lookups, logging, feature flags). Skip any the caller
        # already supplied to avoid duplicates.
        if test_headers:
            supplied = {n.lower() for n in (extra_headers or {})}
            for hname, hval in _COMMON_INJECTABLE_HEADERS:
                if hname.lower() not in supplied:
                    points.append(InjectionPoint(
                        name=hname,
                        location=ParamLocation.HEADER,
                        original_value=hval,
                    ))

        for name, value in self.cookies.items():
            points.append(InjectionPoint(
                name=name,
                location=ParamLocation.COOKIE,
                original_value=value,
            ))

        return points

    def _path_points(self, parsed, all_segments: bool,
                     ids_only: bool = False) -> list[InjectionPoint]:
        """Treat URL path segments as injection points.

        - ids_only=True: ONLY ID-like segments (numeric, UUID, or long
          alphanumeric token). These are always worth testing — they back
          `WHERE id = <seg>` lookups — so the caller tests them unconditionally.
        - default: ID-like segments plus the last segment.
        - all_segments=True: every segment (request-heavy, opt-in via --path-all).
        """
        points: list[InjectionPoint] = []
        raw = parsed.path.split("/")  # keeps leading '' so indexes map to _inject
        non_empty = [i for i, s in enumerate(raw) if s != ""]
        if not non_empty:
            return points
        last_idx = non_empty[-1]

        def _id_like(seg: str) -> bool:
            # numeric (/42), or UUID/long token with both letters and digits.
            return seg.isdigit() or (
                len(seg) >= 8 and any(c.isdigit() for c in seg)
                and any(c.isalpha() for c in seg)
            )

        for i in non_empty:
            seg = raw[i]
            if ids_only:
                take = _id_like(seg)
            else:
                take = all_segments or _id_like(seg) or i == last_idx
            if take:
                points.append(InjectionPoint(
                    name=f"path[{i}]:{seg[:20]}",
                    location=ParamLocation.PATH,
                    original_value=seg,
                    path_index=i,
                ))
        return points

    def _marked_points(self, parsed) -> list[InjectionPoint]:
        """Handle sqlmap-style '*' injection markers in the URL.

        A '*' means "inject exactly HERE" — so ONLY the path segment(s) or query
        param(s) whose value actually contains '*' are tested, and the '*' is
        stripped from the original value (payloads are appended at that spot).
        The previous version stripped every '*' from the whole query first, which
        made it impossible to tell which param was marked, so it wrongly tested
        ALL params (and lost the surrounding context of the marked value).
        """
        points: list[InjectionPoint] = []
        segments = parsed.path.split("/")
        for i, seg in enumerate(segments):
            if "*" in seg:
                points.append(InjectionPoint(
                    name=f"path[{i}]",
                    location=ParamLocation.PATH,
                    original_value=seg.replace("*", ""),
                    path_index=i,
                ))
        if "*" in (parsed.query or ""):
            # Parse WITHOUT stripping so we can see which value carries the '*'.
            query = parse_qs(parsed.query, keep_blank_values=True)
            for name, values in query.items():
                value = values[0] if values else ""
                if "*" in value:
                    points.append(InjectionPoint(
                        name=name,
                        location=ParamLocation.QUERY,
                        original_value=value.replace("*", ""),
                    ))
        return points

    def _json_paths(self, obj: Any, prefix: str = "") -> list[InjectionPoint]:
        """Extract leaf values from JSON for injection."""
        points = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                path = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    points.extend(self._json_paths(v, path))
                elif isinstance(v, (str, int, float, bool)):
                    points.append(InjectionPoint(
                        name=path.split(".")[-1],
                        location=ParamLocation.JSON,
                        original_value=str(v),
                        json_path=path,
                    ))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                path = f"{prefix}[{i}]"
                if isinstance(item, (dict, list)):
                    points.extend(self._json_paths(item, path))
                elif isinstance(item, (str, int, float, bool)):
                    points.append(InjectionPoint(
                        name=f"[{i}]",
                        location=ParamLocation.JSON,
                        original_value=str(item),
                        json_path=path,
                    ))
        return points

    def send(
        self,
        url: str,
        method: str = "GET",
        data: Optional[str] = None,
        content_type: Optional[str] = None,
        extra_headers: Optional[dict[str, str]] = None,
        inject_point: Optional[InjectionPoint] = None,
        payload: Optional[str] = None,
    ) -> HttpExchange:
        """Send request, optionally injecting payload at a specific point."""
        headers = {**self.default_headers, **(extra_headers or {})}
        cookies = dict(self.cookies)
        body = data
        target_url = url

        if inject_point and payload is not None:
            target_url, headers, cookies, body = self._inject(
                url, method, data, content_type, extra_headers, inject_point, payload
            )

        # Ensure the Content-Type header is actually set on the wire for any
        # request with a body. `content_type` is a Python variable, NOT an HTTP
        # header — without this, POST/PUT JSON bodies were sent with no
        # Content-Type, so servers (e.g. Juice Shop) never parsed them as JSON
        # and injection into body params silently did nothing.
        if body is not None and method.upper() != "GET":
            has_ct = any(k.lower() == "content-type" for k in headers)
            if not has_ct:
                if content_type:
                    headers["Content-Type"] = content_type
                elif body.strip()[:1] in ("{", "["):
                    headers["Content-Type"] = "application/json"
                else:
                    headers["Content-Type"] = "application/x-www-form-urlencoded"

        # Retry loop: transient gateway/upstream failures (502/503/504) and
        # network errors (connection reset/refused, timeout) are retried with a
        # short backoff so a flaky host doesn't produce a bogus baseline or a
        # missed finding. The LAST attempt's result is always returned (so a
        # genuinely-down endpoint still surfaces as an infra error, not a hang).
        attempt = 0
        last_exchange: Optional[HttpExchange] = None
        while True:
            start = time.perf_counter()
            try:
                resp = self._client.request(
                    method=method.upper(),
                    url=target_url,
                    content=body if method.upper() != "GET" else None,
                    headers=headers,
                    cookies=cookies,
                )
                elapsed_ms = (time.perf_counter() - start) * 1000
                last_exchange = HttpExchange(
                    method=method.upper(),
                    url=target_url,
                    status_code=resp.status_code,
                    response_time_ms=elapsed_ms,
                    request_headers=headers,
                    request_body=body,
                    response_headers=dict(resp.headers),
                    response_body=resp.text[:50000],
                    injected_param=inject_point.name if inject_point else None,
                    payload=payload,
                )
                transient = resp.status_code in (502, 503, 504)
                # Rate-limit / WAF block: a 429 or 403 under scan load is almost
                # always throttling, not a real verdict. Treating it as final is
                # THE main cause of intermittent false negatives on shared/flaky
                # hosts (a vulnerable endpoint's quote probe gets a 403 and the
                # finding is silently dropped). Retry these with a longer,
                # Retry-After-aware backoff so the real 200/500 gets observed.
                rate_limited = resp.status_code in (429, 403)
                retry_after = _parse_retry_after(resp.headers.get("retry-after"))
            except httpx.HTTPError as e:
                elapsed_ms = (time.perf_counter() - start) * 1000
                last_exchange = HttpExchange(
                    method=method.upper(),
                    url=target_url,
                    status_code=0,
                    response_time_ms=elapsed_ms,
                    request_headers=headers,
                    request_body=body,
                    response_headers={},
                    response_body=str(e),
                    injected_param=inject_point.name if inject_point else None,
                    payload=payload,
                )
                transient = True
                rate_limited = False
                retry_after = None

            # Track consecutive WAF/rate-limit blocks so a persistently-blocked
            # host fails fast (and the caller can warn loudly) instead of burning
            # backoff on every request.
            status_code = last_exchange.status_code
            if status_code in (403, 429):
                self._consec_block += 1
                if self._consec_block >= 6:
                    self.host_blocked = True
            elif status_code and status_code < 500:
                self._consec_block = 0

            # Retry budget: 429 (genuine rate-limit) gets full patience with
            # Retry-After backoff; 403 is usually a persistent block, so just ONE
            # brief retry; other transient errors use the base budget. Once the
            # host is confirmed blocked, stop retrying blocks entirely.
            max_for_code = self.max_retries + (
                3 if status_code == 429 else (1 if status_code == 403 else 0)
            )
            block_now = status_code in (403, 429)
            if (self.host_blocked and block_now) or not (transient or rate_limited) \
                    or attempt >= max_for_code:
                return last_exchange
            attempt += 1
            if status_code == 429:
                delay = min(retry_after, 8.0) if retry_after is not None \
                    else min(6.0, 0.75 * (2 ** attempt))
                delay += (attempt % 3) * 0.15  # jitter to desync threads
            elif status_code == 403:
                delay = 1.0  # brief single retry — 403 is usually a real block
            else:
                delay = 0.4 * attempt  # 0.4s, 0.8s backoff
            time.sleep(delay)

    def _inject(
        self,
        url: str,
        method: str,
        data: Optional[str],
        content_type: Optional[str],
        extra_headers: Optional[dict[str, str]],
        point: InjectionPoint,
        payload: str,
    ) -> tuple[str, dict, dict, Optional[str]]:
        """Apply payload to the specified injection point."""
        headers = {**self.default_headers, **(extra_headers or {})}
        cookies = dict(self.cookies)
        body = data
        target_url = url

        if point.location == ParamLocation.QUERY:
            parsed = urlparse(url)
            query = parse_qs(parsed.query, keep_blank_values=True)
            query[point.name] = [payload]
            new_query = urlencode(query, doseq=True)
            target_url = urlunparse(parsed._replace(query=new_query))

        elif point.location == ParamLocation.PATH and point.path_index is not None:
            from urllib.parse import quote
            parsed = urlparse(url)
            segments = parsed.path.split("/")
            if 0 <= point.path_index < len(segments):
                segments[point.path_index] = quote(payload, safe="")
                new_path = "/".join(segments)
                target_url = urlunparse(parsed._replace(path=new_path))

        elif point.location == ParamLocation.BODY and data:
            form = parse_qs(data, keep_blank_values=True)
            form[point.name] = [payload]
            body = urlencode(form, doseq=True)

        elif point.location == ParamLocation.JSON and data and point.json_path:
            # deepcopy so injecting one JSON key doesn't contaminate later requests
            import copy
            obj = copy.deepcopy(json.loads(data))
            self._set_json_path(obj, point.json_path, payload)
            body = json.dumps(obj)
            # Content-Type header is set centrally in send() now.

        elif point.location == ParamLocation.HEADER:
            headers[point.name] = payload

        elif point.location == ParamLocation.COOKIE:
            cookies[point.name] = payload

        return target_url, headers, cookies, body

    def _set_json_path(self, obj: Any, path: str, value: str):
        """Set a nested JSON value by dot/bracket path."""
        parts = re_split_path(path)
        current = obj
        for part in parts[:-1]:
            current = current[part]
        current[parts[-1]] = value


def re_split_path(path: str) -> list:
    """Split 'user.name' or 'items[0].id' into navigable parts."""
    import re
    tokens = []
    for segment in path.replace("[", ".[").split("."):
        if segment.startswith("[") and segment.endswith("]"):
            tokens.append(int(segment[1:-1]))
        elif segment:
            tokens.append(segment)
    return tokens
