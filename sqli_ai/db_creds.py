"""Default-credentials check keyed by the detected database type.

Once SQLi-AI fingerprints the backend DBMS (from error messages / findings), the
database server itself is often reachable on its standard port and still using
vendor-default credentials (postgres/postgres, root with an empty password, sa,
...). This module turns the known DB type into a targeted check:

    detected DBMS  ->  standard port(s)  ->  vendor-default credential list

For each candidate it does a TCP reachability probe first (cheap, no auth), then
— when an optional driver is installed — actually attempts the login. When no
driver is present it still reports the open port and the exact credentials worth
trying, so the check degrades gracefully instead of doing nothing.

This is an ACTIVE check against a database port (a distinct action from HTTP
scanning), so the CLI gates it behind an explicit --db-creds flag.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Optional

# Standard listening ports per DBMS. SQLite is file-based (no network port) and
# is intentionally absent.
DB_PORTS: dict[str, list[int]] = {
    "postgresql": [5432],
    "mysql": [3306],
    "mariadb": [3306],
    "mssql": [1433],
    "microsoft sql server": [1433],
    "oracle": [1521],
    "mongodb": [27017],
    "redis": [6379],
    "db2": [50000],
    "cockroachdb": [26257],
}

# Vendor-default / extremely-common credential pairs per DBMS. Ordered most
# likely first. Empty-password entries use "".
DEFAULT_CREDS: dict[str, list[tuple[str, str]]] = {
    "postgresql": [
        ("postgres", "postgres"), ("postgres", ""), ("postgres", "admin"),
        ("postgres", "password"), ("postgres", "root"), ("admin", "admin"),
    ],
    "mysql": [
        ("root", ""), ("root", "root"), ("root", "password"), ("root", "toor"),
        ("root", "mysql"), ("admin", "admin"), ("mysql", "mysql"),
    ],
    "mariadb": [
        ("root", ""), ("root", "root"), ("root", "password"), ("mariadb", "mariadb"),
    ],
    "mssql": [
        ("sa", ""), ("sa", "sa"), ("sa", "Password123"), ("sa", "password"),
        ("sa", "sql"), ("sa", "admin"),
    ],
    "oracle": [
        ("system", "oracle"), ("system", "manager"), ("sys", "oracle"),
        ("scott", "tiger"), ("dbsnmp", "dbsnmp"), ("system", "system"),
    ],
    "mongodb": [
        ("admin", "admin"), ("root", "root"), ("mongo", "mongo"),
    ],
    "redis": [
        ("", ""), ("", "redis"), ("", "password"),
    ],
}

# db_type aliases -> canonical key used in the tables above.
_ALIAS = {
    "mariadb": "mysql",   # same wire protocol/creds
    "microsoft sql server": "mssql",
    "sqlserver": "mssql",
    "postgres": "postgresql",
    "pgsql": "postgresql",
}


@dataclass
class CredResult:
    """Outcome of the default-cred check for one (host, port, dbms)."""
    host: str
    port: int
    db_type: str
    reachable: bool                       # TCP port open?
    tested: bool = False                  # did we actually attempt logins?
    working: list[tuple[str, str]] = field(default_factory=list)  # creds that logged in
    candidates: list[tuple[str, str]] = field(default_factory=list)  # creds worth trying
    note: str = ""                        # human-readable status


def _canon(db_type: str) -> str:
    d = (db_type or "").strip().lower()
    return _ALIAS.get(d, d)


def _port_open(host: str, port: int, timeout: float) -> bool:
    """Cheap TCP connect probe — is anything listening on host:port?"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


# --- per-DBMS login attempts (optional drivers; import lazily) ---------------

def _try_postgres(host: str, port: int, user: str, pw: str, timeout: float) -> Optional[bool]:
    """True/False if a driver is available; None if no driver installed."""
    try:
        import psycopg2  # type: ignore
    except ImportError:
        try:
            import psycopg  # psycopg3  # type: ignore
        except ImportError:
            return None
        try:
            conn = psycopg.connect(
                host=host, port=port, user=user, password=pw,
                dbname="postgres", connect_timeout=int(max(1, timeout)),
            )
            conn.close()
            return True
        except Exception:
            return False
    try:
        conn = psycopg2.connect(
            host=host, port=port, user=user, password=pw,
            dbname="postgres", connect_timeout=int(max(1, timeout)),
        )
        conn.close()
        return True
    except Exception:
        return False


def _try_mysql(host: str, port: int, user: str, pw: str, timeout: float) -> Optional[bool]:
    try:
        import pymysql  # type: ignore
    except ImportError:
        return None
    try:
        conn = pymysql.connect(
            host=host, port=port, user=user, password=pw,
            connect_timeout=int(max(1, timeout)),
        )
        conn.close()
        return True
    except Exception:
        return False


def _try_redis(host: str, port: int, user: str, pw: str, timeout: float) -> Optional[bool]:
    """Redis AUTH over a raw socket — no driver needed. Empty pw means the
    server has no auth (a finding in itself)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if pw:
                s.sendall(f"AUTH {pw}\r\n".encode())
            else:
                s.sendall(b"PING\r\n")
            resp = s.recv(128)
            # +PONG / +OK => success; -NOAUTH/-ERR => needs/failed auth
            return resp.startswith(b"+")
    except (OSError, socket.timeout):
        return False


_PROBERS = {
    "postgresql": _try_postgres,
    "mysql": _try_mysql,
    "redis": _try_redis,
}


def check_default_creds(
    host: str,
    db_type: str,
    timeout: float = 4.0,
    ports: Optional[list[int]] = None,
) -> list[CredResult]:
    """Probe the DBMS's standard port(s) and attempt vendor-default logins.

    Returns one CredResult per (port) tried. Never raises for a normal
    unreachable host — that is reported via CredResult.reachable=False.
    """
    canon = _canon(db_type)
    results: list[CredResult] = []

    port_list = ports or DB_PORTS.get(canon) or DB_PORTS.get(db_type.strip().lower(), [])
    if not port_list:
        results.append(CredResult(
            host=host, port=0, db_type=db_type, reachable=False,
            note=f"No standard network port known for '{db_type}' "
                 f"(file-based or unsupported) — nothing to probe.",
        ))
        return results

    creds = DEFAULT_CREDS.get(canon, [])
    prober = _PROBERS.get(canon)

    for port in port_list:
        if not _port_open(host, port, timeout):
            results.append(CredResult(
                host=host, port=port, db_type=db_type, reachable=False,
                candidates=creds,
                note=f"Port {port} closed/filtered — DB not exposed to the network.",
            ))
            continue

        if prober is None:
            results.append(CredResult(
                host=host, port=port, db_type=db_type, reachable=True,
                candidates=creds,
                note=(f"Port {port} OPEN but no {canon} driver installed to test "
                      f"logins. Install the optional driver, or try these creds "
                      f"manually."),
            ))
            continue

        working: list[tuple[str, str]] = []
        driver_missing = False
        for user, pw in creds:
            ok = prober(host, port, user, pw, timeout)
            if ok is None:
                driver_missing = True
                break
            if ok:
                working.append((user, pw))
        if driver_missing:
            results.append(CredResult(
                host=host, port=port, db_type=db_type, reachable=True,
                candidates=creds,
                note=f"Port {port} OPEN but the {canon} driver is not installed.",
            ))
        else:
            results.append(CredResult(
                host=host, port=port, db_type=db_type, reachable=True,
                tested=True, working=working, candidates=creds,
                note=(f"Port {port} OPEN — {len(working)} default credential(s) "
                      f"accepted." if working else
                      f"Port {port} OPEN — no default credentials accepted "
                      f"(tested {len(creds)})."),
            ))
    return results
