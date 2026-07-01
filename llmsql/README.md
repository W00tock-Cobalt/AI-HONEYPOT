# LLMSQL - AI-powered SQL injection scanner

LLMSQL is a **sqlmap alternative that uses an LLM** to analyze HTTP responses, craft payloads, and adapt its testing strategy in real time.

**Default backend: Ollama** — runs locally in the background, no API keys, fully offline.

## Quick start

```bash
pip install httpx rich python-dotenv

# Install Ollama (one-time): https://ollama.com
# LLMSQL auto-starts `ollama serve` and pulls the model on first run

python -m llmsql -u "http://testphp.vulnweb.com/artists.php?artist=1"
```

That's it. No `OPENAI_API_KEY` needed.

## Ollama background behavior

On every scan, LLMSQL automatically:

1. **Checks** if Ollama is running at `http://127.0.0.1:11434`
2. **Starts** `ollama serve` in the background if not
3. **Pulls** the model (default: `llama3.2`) if not installed
4. **Runs** the AI-guided scan against your target

```bash
# Use a different local model
python -m llmsql -u "http://target?id=1" --model qwen2.5-coder:7b

# Ollama already running — skip auto-start
python -m llmsql -u "http://target?id=1" --no-start-ollama

# Heuristic-only (no LLM at all)
python -m llmsql -u "http://target?id=1" --no-llm

# Remote OpenAI-compatible backend instead of Ollama
python -m llmsql -u "http://target?id=1" \
  --base-url https://api.openai.com/v1 \
  --api-key sk-... \
  --model gpt-4o-mini
```

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_HOST` | `http://127.0.0.1:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `llama3.2` | Default model to pull/use |
| `LLMSQL_MODEL` | — | Alias for model override |

## CLI options (sqlmap-familiar)

```
-u, --url              Target URL (required)
--data                 POST body (form or JSON)
--method               HTTP method (default: GET)
-H, --header           Extra headers
--cookie               Cookie string
-p, --param            Test specific parameter only
--level                1=quick, 2=normal, 3=deep
--path                 Test URL path segments (auto-on for crawl input)
--path-all             Test every path segment, not just IDs/last
--no-path              Disable path-segment testing
--guess-params         Mine common param names on each URL (query,q,id,...)
--param-wordlist FILE  Custom parameter-name wordlist
--openapi SRC          Import Swagger/OpenAPI spec (URL/file/site root)
--timeout SECS         HTTP request timeout for LLMSQL's own requests (default 15)
--sqlmap-timeout SECS  Max seconds per sqlmap target before kill/skip (0 = none)
--tamper LIST          Evasion chain applied to payloads (space2comment,...)
--no-auto-tamper       Don't auto-try evasion when a WAF/block is detected
--list-tamper          List available tamper techniques
--include-404          Test even auth-gated/dead baselines (401/403/404/405)
-t, --threads N        Scan N targets concurrently
--fast                 Skip per-param LLM suggestion (heuristics + confirm only)
--probe / --no-probe   Liveness pre-filter (httpx-style, auto-on for crawls)
--include-404          Test endpoints even if baseline is 404/405
--model                Ollama model (default: llama3.2)
--ollama-host          Ollama URL (default: localhost:11434)
--no-start-ollama      Don't auto-start Ollama background service
--no-pull              Don't auto-pull missing model
--no-llm               Heuristic-only, no AI
--base-url             Use remote LLM instead of Ollama
--api-key              API key for remote backend
-o, --output           Save JSON report
-v, --verbose          Show all requests
```

## Why sqlmap fails where LLMSQL helps

| Scenario | sqlmap | LLMSQL |
|----------|--------|--------|
| Custom/generic error pages | Misses SQL errors buried in HTML | LLM interprets response semantics |
| JSON REST APIs | Poor JSON body support | Native JSON path injection |
| WAF blocking | Fixed bypass list | LLM adapts encoding/bypass payloads |
| Boolean blind SQLi | Template-based | LLM compares response diffs intelligently |
| Unknown DB backend | Manual `--dbms` flag | LLM infers DB from error context |
| Offline / no API keys | N/A | Ollama runs locally in background |

## How it works

```
┌─────────┐    baseline     ┌──────────┐
│ Target  │ ◄────────────── │ HttpProbe│
└─────────┘                 └────┬─────┘
     ▲                           │
     │  inject payload           │ response
     │                           ▼
     │                    ┌─────────────┐     ┌──────────────┐
     └────────────────────│   Scanner   │────►│ Ollama (bg)  │
                          └──────┬──────┘     │ llama3.2     │
                                 │            └──────────────┘
                                 ▼
                          ┌─────────────┐
                          │  Detector   │
                          │ (heuristic) │
                          └─────────────┘
```

## Architecture

```
llmsql/
  __main__.py      CLI + Ollama startup
  ollama.py        Background service manager
  scanner.py       Scan orchestration loop
  agent.py         LLM client (Ollama default)
  http_probe.py    HTTP client + parameter injection
  detector.py      Heuristic SQL error/timing detection
  payloads.py      Seed payloads + LLM system prompts
```

## Finding hidden parameters (the hard part)

Most injectable bugs live in a parameter the crawler never sees. Example:
`GET /api/testimonials/count?query=<SQL>` — a crawl of the site only finds
`/api/testimonials/count`, with no `?query`. LLMSQL has three ways to recover
the real parameter names:

```bash
# 1. Import the API spec (best) — pulls every endpoint WITH its params.
#    Works against an exposed Swagger/OpenAPI doc or a site root.
python -m llmsql --openapi https://target/ -v
python -m llmsql --openapi https://target/swagger-json -v

# 2. Parameter mining — try a built-in wordlist of common names
#    (query, q, id, search, cat, filter, sort, ...).
python -m llmsql -u "https://target/api/testimonials/count" --guess-params -v

# 3. Custom wordlist
python -m llmsql -u "https://target/api/x" --param-wordlist params.txt -v
```

With `--openapi`, an exposed spec (very common — see Swagger UIs) turns into a
full, precise target list including `?query=`, path IDs, etc. This is how a
tester who read the Swagger doc finds `/api/testimonials/count?query=...`.

## Recommended pipeline (chain with sqlmap)

LLMSQL is best used as the **recon + orchestration** layer that feeds
**sqlmap** (the proven exploitation engine). Full chain:

```
katana ──► httpx ──► llmsql (discover+auth) ──► sqlmap (exploit)
 crawl     alive?      params/openapi/cookie      dump DB
```

```bash
# 1+2+3+4 in one line: crawl -> (llmsql liveness is built in) -> sqlmap targets
katana -u https://target/ -jc -silent | sort -u \
  | python -m llmsql --stdin --guess-params --grab-cookie --sqlmap

# then run the emitted command
sqlmap -m llmsql-sqlmap-urls.txt --batch --random-agent --level 3 --risk 2

# or let llmsql launch sqlmap for you
python -m llmsql --openapi https://target/ --guess-params --grab-cookie --run-sqlmap
```

### sqlmap intensity profiles

Pick how aggressive sqlmap should be with `--sqlmap-profile`:

| Profile | Flags | Use |
|---------|-------|-----|
| `stealth` | level 1, risk 1, delay, safe techniques | avoid WAF/rate limits |
| `normal` (default) | level 3, risk 2, 4 threads | balanced |
| `aggressive` | level 5, risk 3, 10 threads | maximum detection |
| `exploit` | aggressive + `--dbs --tables --dump-all` | auto-enumerate & dump |
| `nuclear` | all techniques + tamper suite + `-a --dump-all` | everything, fully automatic |

```bash
# Fully automatic exploitation + data dump
python -m llmsql --openapi https://target/ --guess-params --run-sqlmap \
  --sqlmap-profile exploit

# Interactively choose the profile and edit the exact flags before running
python -m llmsql --openapi https://target/ --run-sqlmap --sqlmap-menu

# Add/override any sqlmap flags on top of a profile
python -m llmsql -u "https://target/x?id=1" --run-sqlmap \
  --sqlmap-profile aggressive --sqlmap-args "--dbms=postgresql -p id --dump -T users"
```

Ctrl+C during a run is passed to sqlmap's own `[C]ontinue/[Q]uit` menu (LLMSQL
ignores the signal so it won't crash the run).

### Scan with both (recommended for large target lists)

`--then-sqlmap` runs LLMSQL's fast error-based scan first, then launches sqlmap
**only on the URLs LLMSQL confirmed injectable** — so you don't blast all N
endpoints at level 5. This also covers verbatim-SQL bugs (like BrokenCrystals
`?query=`) that sqlmap's heuristics sometimes dismiss but LLMSQL catches.

```bash
python -m llmsql --openapi https://target/ --guess-params \
  --then-sqlmap --sqlmap-profile exploit --sqlmap-timeout 300
```

`--sqlmap-timeout` caps each sqlmap target (here 5 min) so one slow endpoint
can't hang the whole run — it's killed (with its children) and the run moves on.
Without a timeout, Ctrl+C is passed to sqlmap's interactive menu instead.

Flow: `discover -> liveness -> LLMSQL scan -> sqlmap -p <param> on real hits`.
For each confirmed finding LLMSQL builds a focused sqlmap command (`-p` for
query/body params, a `*` URI marker for path params) and runs it. sqlmap output
lands in `~/.local/share/sqlmap/output/<host>/`.

You don't strictly need all four tools — LLMSQL already does liveness probing
(httpx's role) and can crawl input from katana OR import an OpenAPI spec. A
minimal chain is just **llmsql --openapi ... --run-sqlmap**.

## Sessions & cookies

```bash
# Grab the target's Set-Cookie session automatically and reuse it
python -m llmsql --openapi https://target/ --grab-cookie

# Log in first, then use the resulting session cookie
python -m llmsql -u "https://target/api/x?id=1" \
  --login-url https://target/api/auth/login \
  --login-data '{"user":"admin","password":"admin"}'

# Or pass a known cookie / bearer token
python -m llmsql --openapi https://target/ \
  --cookie "connect.sid=s%3A..." -H "Authorization: Bearer <jwt>"
```

Captured cookies flow into both the LLMSQL scan and the sqlmap handoff command.

## WAF / filter evasion

If a WAF blocks payloads (baseline `200` but injected `403/406/429`), LLMSQL
detects it and automatically retries with tamper/evasion variants
(comment-spacing, random case, char-encoding, double URL-encoding, MySQL
versioned comments). You can also force a chain:

```bash
python -m llmsql -u "https://target/x?id=1" --tamper space2comment,randomcase
python -m llmsql --list-tamper          # see all techniques
```

Endpoints whose baseline is `401`/`403` are treated as auth-gated and skipped;
supply credentials to test them:

```bash
python -m llmsql --openapi https://target/ \
  -H "Authorization: Bearer <token>" --cookie "connect.sid=..."
```

## Crawl + scan (katana / gau)

REST apps are mostly path-based, so crawl broadly and let LLMSQL test path
segments. Dead URLs are auto-filtered with a built-in liveness probe.

```bash
# Broad JS crawl, dedupe, scan with 10 threads in fast mode
katana -u https://target/ -jc -silent | sort -u \
  | python -m llmsql --stdin -t 10 --fast -o report.json

# Only URLs that look injectable
katana -u https://target/ -jc -silent | grep -E '\?|/api/' \
  | python -m llmsql --stdin -t 10 -v
```

Speed tips:
- `--fast` — skip the slow per-parameter LLM suggestion, keep LLM confirmation
- `-t/--threads` — scan many targets in parallel
- liveness probe + baseline-404 skip drop dead endpoints automatically
- `--no-llm` — pure heuristic mode, fastest, no model calls

## Ethical use

For **authorized security testing only**. Only scan systems you own or have explicit permission to test.

## License

MIT
