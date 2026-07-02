"""OpenAPI / Swagger import — expand a spec into concrete testable targets.

Turns a Swagger/OpenAPI document into a list of SpecTarget objects whose real
parameter names are known, so injectable params like /api/testimonials/count?query=...
are discovered without guessing. Handles both GET (query params) and
POST/PUT/PATCH (JSON request bodies).
"""

import json
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import httpx

# Endpoints where a Swagger/OpenAPI JSON spec is commonly served.
# Covers NestJS, Spring, Django REST, FastAPI, ASP.NET, and generic conventions.
COMMON_SPEC_PATHS = [
    "/swagger-json",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs",
    "/api-docs.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/v1/openapi.json",
    "/api/docs/swagger.json",
    "/docs/swagger.json",
    "/openapi.yaml",
    "/swagger.yaml",
    "/api/schema",
    "/api/schema.json",
    "/rest/openapi.json",
    "/rest/swagger.json",
    "/spec/swagger.json",
    "/.well-known/openapi.json",
]


def _placeholder(param: dict[str, Any]) -> str:
    """Pick a plausible concrete value for a path/query parameter."""
    schema = param.get("schema", {}) or {}
    ptype = schema.get("type") or param.get("type") or "string"
    name = (param.get("name") or "").lower()
    if ptype in ("integer", "number"):
        return "1"
    if "email" in name:
        return "admin@example.com"
    if name in ("id", "uid", "pid", "num", "number"):
        return "1"
    # Use "1" as the default string placeholder rather than "test".
    # "test" as a raw SQL query param triggers baseline errors (e.g. the
    # BrokenCrystals verbatim-SQL endpoint), making injection harder to
    # distinguish from a naturally-broken baseline.
    return "1"


def _base_url(spec: dict[str, Any], spec_url: Optional[str]) -> str:
    """Determine the API base URL from the spec or the spec's own URL."""
    # OpenAPI 3: servers[].url ; Swagger 2: host + basePath + schemes
    servers = spec.get("servers")
    if servers and isinstance(servers, list) and servers[0].get("url"):
        base = servers[0]["url"]
        if base.startswith("http"):
            return base.rstrip("/")
        if spec_url:
            return urljoin(spec_url, base).rstrip("/")

    host = spec.get("host")
    if host:
        scheme = (spec.get("schemes") or ["https"])[0]
        base_path = spec.get("basePath", "")
        return f"{scheme}://{host}{base_path}".rstrip("/")

    if spec_url:
        p = urlparse(spec_url)
        return f"{p.scheme}://{p.netloc}"
    return ""


@dataclass
class SpecTarget:
    """A concrete testable endpoint from an OpenAPI spec."""
    url: str
    method: str = "GET"
    body: Optional[str] = None
    content_type: Optional[str] = None
    inject_headers: Optional[dict[str, str]] = None  # headers to test for injection


def expand_spec(spec: dict[str, Any], spec_url: Optional[str] = None) -> list[SpecTarget]:
    """Expand an OpenAPI/Swagger spec into concrete testable targets."""
    base = _base_url(spec, spec_url)
    targets: list[SpecTarget] = []
    seen: set[str] = set()

    paths = spec.get("paths", {}) or {}
    for raw_path, methods in paths.items():
        if not isinstance(methods, dict):
            continue

        for method, op in methods.items():
            method_lower = method.lower()
            if method_lower not in ("get", "post", "put", "patch"):
                continue
            if not isinstance(op, dict):
                continue

            params = op.get("parameters", []) or []
            if isinstance(methods.get("parameters"), list):
                params = methods["parameters"] + params

            path = raw_path
            query_pairs = []
            inject_headers: dict[str, str] = {}
            for param in params:
                if not isinstance(param, dict):
                    continue
                loc = param.get("in")
                pname = param.get("name")
                if not pname:
                    continue
                val = _placeholder(param)
                if loc == "path":
                    path = path.replace(f"{{{pname}}}", val)
                elif loc == "query":
                    query_pairs.append(f"{pname}={val}")
                elif loc == "header" and pname.lower() not in (
                    "authorization", "content-type", "accept",
                    "content-length", "host", "user-agent",
                ):
                    # Custom headers are common SQLi vectors (e.g. x-product-name)
                    inject_headers[pname] = val

            # Replace any leftover {placeholders}
            while "{" in path and "}" in path:
                start = path.find("{")
                end = path.find("}", start)
                if end == -1:
                    break
                path = path[:start] + "1" + path[end + 1:]

            url = f"{base}{path}"
            if query_pairs:
                url += "?" + "&".join(query_pairs)

            # Build JSON body for POST/PUT/PATCH from requestBody schema
            body = None
            content_type = None
            if method_lower in ("post", "put", "patch"):
                body, content_type = _build_request_body(op)

            key = f"{method_lower}:{url}:{body or ''}:{sorted(inject_headers.items())}"
            if key not in seen:
                seen.add(key)
                targets.append(SpecTarget(
                    url=url,
                    method=method_lower.upper(),
                    body=body,
                    content_type=content_type,
                    inject_headers=inject_headers if inject_headers else None,
                ))

    return targets


def _build_request_body(op: dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """Build a concrete JSON body from a requestBody schema."""
    import json as _json

    rb = op.get("requestBody", {}) or {}
    content = rb.get("content", {}) or {}

    for ct in ("application/json", "text/json", "*/*"):
        schema_wrap = content.get(ct, {})
        if not schema_wrap:
            continue
        schema = schema_wrap.get("schema", {}) or {}
        obj = _schema_to_example(schema)
        if obj is not None:
            return _json.dumps(obj), "application/json"

    return None, None


def _schema_to_example(schema: dict[str, Any], depth: int = 0) -> Any:
    """Recursively build a minimal example from a JSON schema."""
    if depth > 4:
        return None
    if not schema:
        return None

    stype = schema.get("type")
    if stype == "object" or "properties" in schema:
        props = schema.get("properties", {}) or {}
        return {k: _schema_to_example(v, depth + 1) for k, v in props.items()} or {"id": "1"}
    if stype == "array":
        items = schema.get("items", {}) or {}
        return [_schema_to_example(items, depth + 1)]
    if stype == "integer" or stype == "number":
        return 1
    if stype == "boolean":
        return True
    # string default
    name_hint = schema.get("title", "").lower()
    if "email" in name_hint:
        return "admin@example.com"
    if "password" in name_hint:
        return "password"
    return "1"


class SpecProbeResult:
    """Diagnostics for one attempted Swagger/OpenAPI path."""
    __slots__ = ("path", "status", "reason")

    def __init__(self, path: str, status: int, reason: str):
        self.path = path
        self.status = status
        self.reason = reason


# Populated by the most recent load_openapi() call so callers can inspect
# exactly what was tried and why it did or didn't work — no silent failures.
last_probe_log: list[SpecProbeResult] = []


def load_openapi(
    source: str,
    timeout: float = 15.0,
    headers: Optional[dict[str, str]] = None,
    verify_ssl: bool = True,
) -> list[SpecTarget]:
    """
    Load an OpenAPI/Swagger spec from a URL or local file and expand it.

    'source' may be a full spec URL, a local path, or a base site URL
    (in which case common spec paths are probed). After calling this,
    inspect `llmsql.openapi.last_probe_log` for a full diagnostic trail
    of every path tried and its outcome.
    """
    # Mutate the existing list in place (not rebind) so callers who imported
    # `last_probe_log` by name still see updates after this call returns.
    last_probe_log.clear()

    spec: Optional[dict[str, Any]] = None
    spec_url: Optional[str] = None

    # Local file?
    if not source.startswith("http"):
        with open(source) as f:
            spec = json.load(f)
        return expand_spec(spec, None)  # type: ignore[return-value]

    client = httpx.Client(timeout=timeout, verify=verify_ssl, follow_redirects=True)
    spec_urls_gql: list[str] = []
    try:
        # If the source already looks like a spec endpoint, fetch it directly
        candidates = [source]
        parsed = urlparse(source)
        looks_like_spec = any(
            source.rstrip("/").endswith(p) for p in
            ("swagger-json", "swagger.json", "openapi.json", "api-docs", ".yaml")
        )
        if not looks_like_spec:
            root = f"{parsed.scheme}://{parsed.netloc}"
            candidates = [root + p for p in COMMON_SPEC_PATHS]

        for cand in candidates:
            try:
                resp = client.get(cand, headers=headers or {})
            except httpx.HTTPError as e:
                last_probe_log.append(SpecProbeResult(cand, 0, f"request failed: {e}"))
                continue

            if resp.status_code != 200:
                last_probe_log.append(
                    SpecProbeResult(cand, resp.status_code, "non-200 response")
                )
                continue

            text = resp.text.strip()

            # Try JSON first; fall back to YAML if pyyaml is available
            data = None
            if text.startswith("{") or text.startswith("["):
                try:
                    data = resp.json()
                except (json.JSONDecodeError, ValueError):
                    pass
            if data is None and (text.startswith("openapi:") or text.startswith("swagger:")):
                try:
                    import yaml  # type: ignore[import]
                    data = yaml.safe_load(text)
                except (ImportError, Exception):
                    pass

            if data is None:
                last_probe_log.append(
                    SpecProbeResult(cand, resp.status_code, "200 but not parseable JSON or YAML")
                )
                continue

            if "paths" not in data:
                last_probe_log.append(
                    SpecProbeResult(cand, resp.status_code, "valid JSON but no 'paths' key")
                )
                continue

            spec = data
            spec_url = cand
            last_probe_log.append(SpecProbeResult(cand, resp.status_code, "valid OpenAPI spec found"))
            break
        # GraphQL probe — client still open here
        if spec_url:
            parsed_spec = urlparse(spec_url)
            gql_root = f"{parsed_spec.scheme}://{parsed_spec.netloc}"
            for gql_path in ["/graphql", "/api/graphql", "/gql"]:
                gql_url = gql_root + gql_path
                try:
                    r = client.post(
                        gql_url,
                        json={"query": "{__typename}"},
                        headers={**(headers or {}), "Content-Type": "application/json"},
                    )
                    if r.status_code < 500 and (
                        "data" in r.text or "errors" in r.text
                    ):
                        # GraphQL is live — add a minimal introspection target.
                        # Do NOT add app-specific queries here; let param mining
                        # discover injectable fields on the target naturally.
                        spec_urls_gql.append(gql_url)
                        break
                except (httpx.HTTPError, OSError):
                    continue
    finally:
        client.close()

    if not spec:
        return []
    targets = expand_spec(spec, spec_url)
    for gql_url in spec_urls_gql:
        # Add a generic GraphQL endpoint for param-mining / injection tests.
        # A bare POST target lets the scanner discover injectable fields via
        # --guess-params rather than hard-coding app-specific query names.
        targets.append(SpecTarget(
            url=gql_url,
            method="POST",
            body='{"query":"{__typename}"}',
            content_type="application/json",
        ))
    return targets
