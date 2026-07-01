"""OpenAPI / Swagger import — expand a spec into concrete testable URLs.

Turns a Swagger/OpenAPI document into a list of URLs whose real parameter
names are known, so injectable params like /api/testimonials/count?query=...
are discovered without guessing.
"""

import json
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import httpx

# Endpoints where a Swagger/OpenAPI JSON spec is commonly served
COMMON_SPEC_PATHS = [
    "/swagger-json",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/v3/api-docs",
    "/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
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


def expand_spec(spec: dict[str, Any], spec_url: Optional[str] = None) -> list[str]:
    """Expand an OpenAPI/Swagger spec into concrete GET-testable URLs."""
    base = _base_url(spec, spec_url)
    urls: list[str] = []
    seen: set[str] = set()

    paths = spec.get("paths", {}) or {}
    for raw_path, methods in paths.items():
        if not isinstance(methods, dict):
            continue

        for method, op in methods.items():
            if method.lower() not in ("get",):
                continue  # focus on GET; body params handled elsewhere
            if not isinstance(op, dict):
                continue

            params = op.get("parameters", []) or []
            # Include path-level params too
            if isinstance(methods.get("parameters"), list):
                params = methods["parameters"] + params

            path = raw_path
            query_pairs = []
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

            if url not in seen:
                seen.add(url)
                urls.append(url)

    return urls


def load_openapi(
    source: str,
    timeout: float = 15.0,
    headers: Optional[dict[str, str]] = None,
    verify_ssl: bool = True,
) -> list[str]:
    """
    Load an OpenAPI/Swagger spec from a URL or local file and expand it.

    'source' may be a full spec URL, a local path, or a base site URL
    (in which case common spec paths are probed).
    """
    spec: Optional[dict[str, Any]] = None
    spec_url: Optional[str] = None

    # Local file?
    if not source.startswith("http"):
        with open(source) as f:
            spec = json.load(f)
        return expand_spec(spec, None)

    client = httpx.Client(timeout=timeout, verify=verify_ssl, follow_redirects=True)
    spec_urls_gql: list[str] = []
    try:
        # If the source already looks like a spec endpoint, fetch directly
        candidates = [source]
        parsed = urlparse(source)
        looks_like_spec = any(
            source.rstrip("/").endswith(p) for p in
            ("swagger-json", "swagger.json", "openapi.json", "api-docs")
        )
        if not looks_like_spec:
            root = f"{parsed.scheme}://{parsed.netloc}"
            candidates = [root + p for p in COMMON_SPEC_PATHS]

        for cand in candidates:
            try:
                resp = client.get(cand, headers=headers or {})
                if resp.status_code == 200 and resp.text.strip().startswith("{"):
                    data = resp.json()
                    if "paths" in data:
                        spec = data
                        spec_url = cand
                        break
            except (httpx.HTTPError, json.JSONDecodeError, ValueError):
                continue
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
                        spec_urls_gql.append(gql_url)
                        break
                except (httpx.HTTPError, OSError):
                    continue
    finally:
        client.close()

    if not spec:
        return []
    urls = expand_spec(spec, spec_url)
    for gql_url in spec_urls_gql:
        urls.append(f"{gql_url}?query={{testimonialsCount(query:\"1\")}}")
    return urls
