"""Response comparison engine (sqlmap-style).

llmsql historically compared responses by byte length, which is crude: two
pages can share a length yet differ completely, and any page with a timestamp
or CSRF token looks "different" on every request. This module ports the two
ideas that make sqlmap/Ghauri boolean detection reliable:

1. **Similarity ratio** — compare page *content* with difflib's
   ``SequenceMatcher`` (0.0 = totally different, 1.0 = identical) instead of
   raw length.
2. **Dynamic-content removal** — send the same request twice, diff the two
   responses to locate the parts that change on their own (timestamps, nonces,
   tokens), and strip those regions before every comparison. This means a page
   with minor dynamic noise is still testable (we remove the noise) rather than
   discarded outright.

Thresholds mirror sqlmap's: a TRUE page should be ~identical to the original
(ratio ≥ UPPER_RATIO_BOUND) while a FALSE page should differ
(ratio ≤ LOWER_RATIO_BOUND), and an ambiguous ratio is judged against the
established match ratio with DIFF_TOLERANCE.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher

# sqlmap's bounds (lib/core/settings.py)
LOWER_RATIO_BOUND = 0.02
UPPER_RATIO_BOUND = 0.98
DIFF_TOLERANCE = 0.05
# Context length captured around a dynamic region so it can be re-located.
DYNAMICITY_MARK_LENGTH = 32
# Below this ratio between two IDENTICAL requests, the page is "heavily dynamic"
# and even after stripping we can't trust a content comparison.
HEAVILY_DYNAMIC_BOUND = 0.90
# Content-ratio comparison is unreliable on very short bodies (e.g. a 1-byte
# "1"): a single differing char swings the ratio between 0.0 and 1.0, producing
# false positives. Require at least this many chars before trusting the ratio.
MIN_STABLE_PAGE = 24


def ratio(a: str | None, b: str | None) -> float:
    """Content-similarity ratio of two strings in [0.0, 1.0]."""
    if a is None or b is None:
        return 0.0
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    try:
        return round(SequenceMatcher(None, a, b, autojunk=False).quick_ratio(), 3)
    except (TypeError, MemoryError):
        # Fall back to a length ratio if difflib chokes (huge/binary pages)
        la, lb = len(a), len(b)
        m = max(la, lb)
        return round(min(la, lb) / m, 3) if m else 1.0


def find_dynamic_markers(page_a: str, page_b: str) -> list[tuple[str, str]]:
    """Locate dynamic regions by diffing two responses to the SAME request.

    Returns a list of ``(prefix, suffix)`` context markers bracketing each
    region that differs between the two pages — i.e. the bits that change on
    their own. Mirrors sqlmap's ``findDynamicContent``.
    """
    markers: list[tuple[str, str]] = []
    if not page_a or not page_b or page_a == page_b:
        return markers
    try:
        blocks = SequenceMatcher(None, page_a, page_b, autojunk=False).get_matching_blocks()
    except (TypeError, MemoryError):
        return markers

    # Regions of page_a BETWEEN consecutive matching blocks are dynamic.
    for i in range(len(blocks) - 1):
        a0, _b0, size = blocks[i]
        start = a0 + size            # end of this matching block in page_a
        end = blocks[i + 1][0]       # start of next matching block in page_a
        if end > start:
            prefix = page_a[max(0, start - DYNAMICITY_MARK_LENGTH):start]
            suffix = page_a[end:end + DYNAMICITY_MARK_LENGTH]
            if prefix or suffix:
                markers.append((prefix, suffix))
    return markers


def remove_dynamic(page: str | None, markers: list[tuple[str, str]]) -> str:
    """Strip dynamic regions from ``page`` using markers from
    :func:`find_dynamic_markers`, so comparisons ignore the noise."""
    if not page or not markers:
        return page or ""
    for prefix, suffix in markers:
        try:
            if prefix and suffix:
                page = re.sub(
                    re.escape(prefix) + r".*?" + re.escape(suffix),
                    prefix + suffix, page, count=1, flags=re.DOTALL,
                )
            elif prefix:
                page = re.sub(
                    re.escape(prefix) + r".*$", prefix, page, count=1, flags=re.DOTALL,
                )
            elif suffix:
                page = re.sub(
                    r"^.*?" + re.escape(suffix), suffix, page, count=1, flags=re.DOTALL,
                )
        except re.error:
            continue
    return page
