"""Tamper / evasion transforms for WAF bypass (sqlmap-style)."""

import random
import re
from urllib.parse import quote


def _space2comment(payload: str) -> str:
    """Replace spaces with inline comments: SELECT/**/1."""
    return payload.replace(" ", "/**/")


def _space2plus(payload: str) -> str:
    """Replace spaces with '+' (query-string space)."""
    return payload.replace(" ", "+")


def _randomcase(payload: str) -> str:
    """Randomize case of SQL keywords/letters: SeLeCt."""
    def swap(m):
        return "".join(
            c.upper() if random.random() > 0.5 else c.lower() for c in m.group(0)
        )
    return re.sub(r"[A-Za-z]+", swap, payload)


def _upper(payload: str) -> str:
    return payload.upper()


def _urlencode(payload: str) -> str:
    """Percent-encode everything (single encode)."""
    return quote(payload, safe="")


def _doubleurlencode(payload: str) -> str:
    """Double percent-encode (defeats single-decode WAFs)."""
    return quote(quote(payload, safe=""), safe="")


def _charencode(payload: str) -> str:
    """Percent-encode only the 'dangerous' characters."""
    out = []
    for ch in payload:
        if ch in "'\"=<>()% ;-":
            out.append("%{:02x}".format(ord(ch)))
        else:
            out.append(ch)
    return "".join(out)


def _versioned_comment(payload: str) -> str:
    """MySQL versioned comments around keywords: /*!50000SELECT*/."""
    keywords = ["SELECT", "UNION", "AND", "OR", "WHERE", "FROM", "ORDER"]
    result = payload
    for kw in keywords:
        result = re.sub(
            rf"\b{kw}\b",
            f"/*!50000{kw}*/",
            result,
            flags=re.IGNORECASE,
        )
    return result


def _space2multi(payload: str) -> str:
    """Replace spaces with alternate whitespace (tab / newline)."""
    return payload.replace(" ", random.choice(["\t", "\n", "\x0b", "\x0c"]))


def _inline_case_comment(payload: str) -> str:
    """Combine comment-spacing with random case (stacked evasion)."""
    return _randomcase(_space2comment(payload))


TAMPERS = {
    "space2comment": _space2comment,
    "space2plus": _space2plus,
    "space2multi": _space2multi,
    "randomcase": _randomcase,
    "upper": _upper,
    "urlencode": _urlencode,
    "doubleurlencode": _doubleurlencode,
    "charencode": _charencode,
    "versionedcomment": _versioned_comment,
    "comment_case": _inline_case_comment,
}

# A sensible chain to try automatically when a WAF is detected
AUTO_TAMPER_CHAIN = [
    "space2comment",
    "randomcase",
    "charencode",
    "doubleurlencode",
    "versionedcomment",
    "comment_case",
]


def available() -> list[str]:
    return sorted(TAMPERS.keys())


def apply_tamper(payload: str, techniques: list[str]) -> str:
    """Apply a chain of tamper techniques in order."""
    result = payload
    for name in techniques:
        fn = TAMPERS.get(name)
        if fn:
            result = fn(result)
    return result


def tamper_variants(payload: str, techniques: list[str]) -> list[str]:
    """
    Produce one tampered variant per technique (not chained), plus the chained
    result. Used to probe which evasion a WAF is vulnerable to.
    """
    variants = []
    seen = set()
    for name in techniques:
        fn = TAMPERS.get(name)
        if not fn:
            continue
        try:
            v = fn(payload)
        except Exception:
            continue
        if v and v != payload and v not in seen:
            seen.add(v)
            variants.append(v)
    return variants
