"""HTTP probing and parameter injection."""

import json
import time
from copy import deepcopy
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from llmsql.models import HttpExchange, InjectionPoint, ParamLocation


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
    ) -> list[InjectionPoint]:
        """Discover injectable parameters from URL, body, headers."""
        points: list[InjectionPoint] = []

        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        for name, values in query.items():
            points.append(InjectionPoint(
                name=name,
                location=ParamLocation.QUERY,
                original_value=values[0] if values else "",
            ))

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

        if extra_headers:
            for name, value in extra_headers.items():
                if name.lower() not in ("host", "content-length", "content-type"):
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

        elif point.location == ParamLocation.BODY and data:
            form = parse_qs(data, keep_blank_values=True)
            form[point.name] = [payload]
            body = urlencode(form, doseq=True)

        elif point.location == ParamLocation.JSON and data and point.json_path:
            obj = json.loads(data)
            self._set_json_path(obj, point.json_path, payload)
            body = json.dumps(obj)
            if not content_type:
                headers["Content-Type"] = "application/json"

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
