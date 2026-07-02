"""HTTP probing and parameter injection."""

import json
import time
from copy import deepcopy
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from llmsql.models import HttpExchange, InjectionPoint, ParamLocation

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


class HttpProbe:
    """Send HTTP requests with payload injection at specific points."""

    def __init__(
        self,
        timeout: float = 15.0,
        verify_ssl: bool = True,
        proxy: Optional[str] = None,
        default_headers: Optional[dict[str, str]] = None,
        cookies: Optional[dict[str, str]] = None,
    ):
        self.timeout = timeout
        self.default_headers = default_headers or {}
        self.cookies = cookies or {}
        client_kwargs: dict[str, Any] = {
            "timeout": timeout,
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
    ) -> list[InjectionPoint]:
        """Discover injectable parameters from URL path, query, body, headers."""
        points: list[InjectionPoint] = []

        parsed = urlparse(url)

        # sqlmap-style '*' marker: only the marked spot is tested
        if "*" in parsed.path or "*" in (parsed.query or ""):
            points.extend(self._marked_points(parsed))
            if points:
                return points

        query = parse_qs(parsed.query, keep_blank_values=True)
        existing = set(query.keys())
        for name, values in query.items():
            points.append(InjectionPoint(
                name=name,
                location=ParamLocation.QUERY,
                original_value=values[0] if values else "",
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
                not existing  # no existing query params
                and not action_val
                and any(seg in path_lower for seg in ("/api/", "/rest/", "/v1/", "/v2/", "/graphql"))
            )
            if is_rest_api and not priority:
                # Short REST-focused list: search, filter, id, q are most common SQLi vectors
                candidate_params = ["q", "search", "query", "id", "filter", "name",
                                    "email", "username", "orderBy", "sort"]
            elif not existing and not action_val:
                # Generic page (no existing params, no known ?action=) — this is
                # usually an SPA route or static-ish page. Cap the guess list so
                # a single URL can't balloon into 90+ precheck rounds; the most
                # common SQLi param names are listed first in COMMON_PARAMS.
                candidate_params = list(guess_params)[:_MAX_GUESS_PARAMS_GENERIC]
            else:
                # URL already has real params (from a spec/crawl) — worth the
                # full mining pass since we know this endpoint takes input.
                candidate_params = list(guess_params)

            seen_params = set(existing)
            for name in priority + candidate_params:
                if name not in seen_params:
                    seen_params.add(name)
                    points.append(InjectionPoint(
                        name=name,
                        location=ParamLocation.QUERY,
                        original_value="1",
                    ))

        if test_path:
            points.extend(self._path_points(parsed, path_all_segments))

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

        for name, value in self.cookies.items():
            points.append(InjectionPoint(
                name=name,
                location=ParamLocation.COOKIE,
                original_value=value,
            ))

        return points

    def _path_points(self, parsed, all_segments: bool) -> list[InjectionPoint]:
        """Treat URL path segments as injection points.

        By default only test 'interesting' segments (numeric IDs, or the last
        segment) to avoid request explosion. all_segments tests every segment.
        """
        points: list[InjectionPoint] = []
        raw = parsed.path.split("/")  # keeps leading '' so indexes map to _inject
        non_empty = [i for i, s in enumerate(raw) if s != ""]
        if not non_empty:
            return points
        last_idx = non_empty[-1]

        for i in non_empty:
            seg = raw[i]
            is_numeric = seg.isdigit()
            looks_like_id = is_numeric or (len(seg) >= 8 and any(c.isdigit() for c in seg))
            if all_segments or is_numeric or looks_like_id or i == last_idx:
                points.append(InjectionPoint(
                    name=f"path[{i}]:{seg[:20]}",
                    location=ParamLocation.PATH,
                    original_value=seg,
                    path_index=i,
                ))
        return points

    def _marked_points(self, parsed) -> list[InjectionPoint]:
        """Handle sqlmap-style '*' injection markers in the URL."""
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
            query = parse_qs(parsed.query.replace("*", ""), keep_blank_values=True)
            for name, values in query.items():
                points.append(InjectionPoint(
                    name=name,
                    location=ParamLocation.QUERY,
                    original_value=values[0] if values else "",
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
            return HttpExchange(
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
        except httpx.HTTPError as e:
            elapsed_ms = (time.perf_counter() - start) * 1000
            return HttpExchange(
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
