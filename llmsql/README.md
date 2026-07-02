# LLMSQL - AI-powered SQL injection scanner

## What it does well

LLMSQL's genuine value is as a **discovery and parameter-mining layer** that feeds sqlmap:

1. **Organic discovery** — mines parameter names *and follow-up targets from the target's own responses* (HTML forms, links, JS `fetch()` URLs, JSON keys). A bare `-u https://site` reaches the vulnerable `/search?searchquery=` a homepage form points at — no baked-in endpoint list, works on any app. On by default; disable with `--no-organic`.
2. **OpenAPI/Swagger import** — gets every endpoint *with real param names* (e.g. `?query=` on `/api/testimonials/count`) that a crawler won't see
3. **Liveness filter** — drops dead/403 endpoints before sqlmap wastes time on them
4. **Parameter mining** — tries common param names on bare URLs (fallback wordlist)
5. **GraphQL probe** — detects and adds GraphQL injection points
6. **POST body expansion** — emits POST endpoints with concrete JSON bodies

Then it hands confirmed findings to **sqlmap** for actual exploitation.

## For broad vulnerability scanning (dozens of findings)

LLMSQL is a SQL injection tool. For all injection types (XSS, RCE, XXE, SSTI, XPath, LDAP, command injection), use nuclei:

```bash
nuclei -u https://target/ -t ~/nuclei-templates/ \
  -tags sqli,xss,xxe,ssti,lfi,rce -severity critical,high
```

## Quick start

```bash
pip install httpx rich python-dotenv

# Install Ollama (one-time): https://ollama.com
# LLMSQL auto-starts ollama serve and pulls llama3.2 on first run

# Full pipeline: discover via OpenAPI, scan, hand to sqlmap
python -m llmsql \
  --openapi https://target/ \
  --guess-params --fast -t 8 \
  --then-sqlmap --ask \
  --sqlmap-profile exploit --sqlmap-timeout 300 \
  -o report.json -v

# Just let sqlmap do everything (simpler for known apps)
sqlmap -u "https://target/" --crawl=3 --forms --batch \
  --level=5 --risk=3 --random-agent --threads=10
```

## Pipeline (when LLMSQL adds value)

```
katana/OpenAPI → LLMSQL (liveness + param discovery) → sqlmap (exploit)
```

```bash
# Crawl first
katana -u https://target/ -jc -silent | sort -u \
  | python -m llmsql --stdin --guess-params --then-sqlmap --ask

# Or from OpenAPI spec (best for REST APIs with Swagger)
python -m llmsql --openapi https://target/ \
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
--path                 Test URL path segments too
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
