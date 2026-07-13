# SQLi-AI - AI-powered SQL injection scanner

## What it does well

SQLi-AI's genuine value is as a **discovery and parameter-mining layer** that feeds sqlmap:

1. **Organic discovery** — mines parameter names *and follow-up targets from the target's own responses* (HTML forms, links, JS `fetch()` URLs, JSON keys). A bare `-u https://site` reaches the vulnerable `/search?searchquery=` a homepage form points at — no baked-in endpoint list, works on any app. On by default; disable with `--no-organic`.
2. **OpenAPI/Swagger import** — gets every endpoint *with real param names* (e.g. `?query=` on `/api/testimonials/count`) that a crawler won't see
3. **Liveness filter** — drops dead/403 endpoints before sqlmap wastes time on them
4. **Parameter mining** — tries common param names on bare URLs (fallback wordlist)
5. **POST body expansion** — emits POST endpoints with concrete JSON bodies

Then it hands confirmed findings to **sqlmap** for actual exploitation.

## Injection vectors it tests

Beyond query/body/JSON params, SQLi-AI covers the vectors commodity scanners miss:

- **URL path segments** — `WHERE id=<seg>` lookups (`/api/user/1`), ID-like segments always tested
- **HTTP headers** — auth/token headers (`X-Auth-Token`, `Authorization`) and entity-name headers (`x-product-name`, `x-username`) that get interpolated into SQL
- **JWT `kid` header** — a SQL payload inside the `kid` claim of a bearer token, on JWT/auth-validation endpoints (key looked up by `kid` in SQL); boolean status oracle, self-declines when the DB is offline
- **GraphQL arguments** — introspects `/graphql` and injects into every String mutation/query argument (bypasses REST WAF rules)
- **Raw SQL/XPath executors** — endpoints that run a param verbatim (`?query=`, `?sql=`, `?xpath=`) confirmed via a reflected-marker-in-SQL-error test
- **Auth-bypass** — `' OR '1'='1'--` on login/credential fields

## Default-credentials check

Once the DBMS is fingerprinted, `--db-creds` probes its standard port for
vendor-default credentials (postgres/postgres, root with empty password, `sa`,
...). Uses optional DB drivers (`psycopg`, `PyMySQL`; Redis needs none) when
installed, otherwise reports the open port and the exact credentials to try.
SQLite and file-based backends are skipped. Opt-in (it actively touches a DB port).

## For broad vulnerability scanning (dozens of findings)

SQLi-AI is a SQL injection tool. For all injection types (XSS, RCE, XXE, SSTI, XPath, LDAP, command injection), use nuclei:

```bash
nuclei -u https://target/ -t ~/nuclei-templates/ \
  -tags sqli,xss,xxe,ssti,lfi,rce -severity critical,high
```

## AI usage

The LLM (Ollama by default, or any OpenAI-compatible backend via `--base-url`)
is used in two places, and it's visible in the output:

1. **Near-miss assist (during the scan):** when a parameter *reacts* to
   injection but the deterministic engine can't confirm it, the LLM is asked for
   a few targeted payloads for that exact context.
2. **AI analysis (after confirmation):** every confirmed finding gets an AI
   impact / exploitation / remediation writeup, shown in the PoC panel and saved
   to the JSON report (`ai_analysis`). This runs *after* deterministic
   confirmation, so it never changes detection results.

Detection itself is deterministic (heuristics) for reliability. Disable the LLM
with `--no-llm`; it also auto-falls back to heuristics if the model is slow or
unreachable (per-call timeout + circuit breaker).

## Quick start

```bash
pip install httpx rich python-dotenv

# Install Ollama (one-time): https://ollama.com
# SQLi-AI auto-starts ollama serve and pulls llama3.2 on first run

# ZERO-CONFIG: just point it at a site. Auto-discovery (Swagger probe + app
# fingerprint + crawl), organic param discovery, param mining, and ALL injection
# types (error/boolean/time/NoSQL/auth-bypass) are ON BY DEFAULT.
python -m sqli_ai -u https://target/

# Same for a whole list — threads auto-scale, findings grouped per host
python -m sqli_ai -l urls.txt

# Opt OUT of pieces if you need to trim: --no-auto --no-guess-params --no-organic

# Quick local testing: ./scan bakes in --no-llm --no-auto --db-creds
./scan https://target/api/endpoint     # one URL
./scan -l urls.txt                     # a list (extra flags pass through)

# Full pipeline: discover, scan, hand to sqlmap
python -m sqli_ai -u https://target/ \
  --then-sqlmap --ask \
  --sqlmap-profile exploit --sqlmap-timeout 300 \
  -o report.json -v

# Just let sqlmap do everything (simpler for known apps)
sqlmap -u "https://target/" --crawl=3 --forms --batch \
  --level=5 --risk=3 --random-agent --threads=10
```

## Pipeline (when SQLi-AI adds value)

```
katana/OpenAPI → SQLi-AI (liveness + param discovery) → sqlmap (exploit)
```

```bash
# Crawl first
katana -u https://target/ -jc -silent | sort -u \
  | python -m sqli_ai --stdin --guess-params --then-sqlmap --ask

# Or from OpenAPI spec (best for REST APIs with Swagger)
python -m sqli_ai --openapi https://target/ \
  --guess-params --then-sqlmap --ask -v
```

## CLI reference

```
-u, --url              Target URL
-l, --list FILE        URL list file
--stdin                Read URLs from stdin (pipe from katana/gau)
--openapi SRC          Import Swagger/OpenAPI spec
--guess-params         Mine common param names (query,id,search,...)
--param-wordlist FILE  Custom param wordlist
--no-organic           Disable organic param/target discovery from responses
                       (on by default: forms, links, JS, JSON keys)
--crawl                Run katana on each seed to discover URLs (any run, not
                       just --auto; crawls authenticated with --cookie/--login)
--crawl-depth N        katana crawl depth for --auto/--crawl (default 3)
--path                 Test URL path segments too (auto-enabled when a URL has
                       an ID-like path segment, e.g. /api/user/1, and no query)
--fast                 Error-based payloads only (quick triage)
--payloads MODE        {sqlmap|embedded|error|boolean|union|time|stacked}
--sleep N              Sleep seconds for time-based payloads (default 3)
-t, --threads N        Concurrent targets
--timeout SECS         HTTP timeout (default 15)
--tamper LIST          WAF evasion (space2comment,randomcase,...)
--no-auto-tamper       Disable auto WAF detection/evasion
--list-tamper          Show tamper techniques
--then-sqlmap          Run sqlmap on confirmed findings after scan
--ask                  Prompt before launching sqlmap
--sqlmap-profile       {stealth,normal,aggressive,exploit,nuclear}
--sqlmap-timeout SECS  Kill sqlmap after N seconds per target
--sqlmap-menu          Interactive profile/flag selection
--db-creds             After scan, probe each detected DBMS's port for
                       vendor-default credentials (opt-in; touches a DB port)
--db-creds-timeout N   Per-connection timeout for --db-creds (default 4s)
--grab-cookie [URL]    Auto-capture session cookie
--login-url/--login-data  POST credentials to get session
--include-404          Test auth-gated/dead endpoints too
--no-llm               Heuristic-only, no AI
--model                Ollama model (default: llama3.2)
--ollama-host          Ollama URL (default: localhost:11434)
-o, --output           Save JSON report
-v, --verbose          Show all requests
--show-response        Print response snippet per payload (debug)
```

## Ethical use

Authorized security testing only.

## License

MIT
