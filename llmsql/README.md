# LLMSQL - AI-powered SQL injection scanner

LLMSQL is a **sqlmap alternative that uses an LLM** to analyze HTTP responses, craft payloads, and adapt its testing strategy in real time.

Traditional tools like sqlmap rely on static payload lists and regex matching. That breaks down on modern apps with custom error handling, WAFs, JSON APIs, and opaque responses. LLMSQL sends each request/response pair to an LLM that reasons about whether SQL injection is present and what to try next.

## Why sqlmap fails where LLMSQL helps

| Scenario | sqlmap | LLMSQL |
|----------|--------|--------|
| Custom/generic error pages | Misses SQL errors buried in HTML | LLM interprets response semantics |
| JSON REST APIs | Poor JSON body support | Native JSON path injection |
| WAF blocking | Fixed bypass list | LLM adapts encoding/bypass payloads |
| Boolean blind SQLi | Template-based | LLM compares response diffs intelligently |
| Unknown DB backend | Manual `--dbms` flag | LLM infers DB from error context |

## Quick start

```bash
# Install deps (from repo root)
pip install httpx rich python-dotenv

# Basic scan (needs OPENAI_API_KEY for AI mode)
export OPENAI_API_KEY=sk-...
python -m llmsql -u "http://testphp.vulnweb.com/artists.php?artist=1"

# POST form
python -m llmsql -u "http://target/search" --method POST --data "q=test"

# JSON API
python -m llmsql -u "http://target/api/users" \
  --method POST \
  --data '{"id": 1, "name": "admin"}' \
  -H "Content-Type: application/json"

# Heuristic-only (no LLM, fully offline)
python -m llmsql -u "http://target/page?id=1" --no-llm

# Custom LLM backend (Ollama, LiteLLM, Azure, etc.)
python -m llmsql -u "http://target/page?id=1" \
  --base-url http://localhost:11434/v1 \
  --api-key ollama \
  --model llama3
```

## CLI options (sqlmap-familiar)

```
-u, --url          Target URL (required)
--data             POST body (form or JSON)
--method           HTTP method (default: GET)
-H, --header       Extra headers (repeatable)
--cookie           Cookie string
-p, --param        Test specific parameter only
--level            1=quick, 2=normal, 3=deep
--risk             1=safe, 3=aggressive payloads
--max-attempts     Payloads per parameter
--api-key          LLM API key
--base-url         OpenAI-compatible API URL
--model            LLM model name
--no-llm           Heuristic-only, no AI
-o, --output       Save JSON report
--batch            Non-interactive
-v, --verbose      Show all requests
```

## How it works

```
┌─────────┐    baseline     ┌──────────┐
│ Target  │ ◄────────────── │ HttpProbe│
└─────────┘                 └────┬─────┘
     ▲                           │
     │  inject payload           │ response
     │                           ▼
     │                    ┌─────────────┐     ┌─────────┐
     └────────────────────│   Scanner   │────►│ LLM     │
                          └──────┬──────┘     │ Agent   │
                                 │            └────┬────┘
                                 │                 │
                                 ▼                 ▼
                          ┌─────────────┐   next payload /
                          │  Detector   │   confirm/skip
                          │ (heuristic) │
                          └─────────────┘
```

1. **Discover** injection points (query params, POST fields, JSON paths, headers, cookies)
2. **Baseline** — capture normal response
3. **Seed payloads** — classic SQLi probes + LLM-suggested payloads for this specific target
4. **Analyze** — heuristic scoring (SQL errors, timing, body diffs) + LLM reasoning
5. **Adapt** — LLM generates next payload based on what worked/failed
6. **Confirm** — LLM validates findings before reporting

## Output

Terminal report with severity, injection type, payload, and evidence. JSON export for CI/CD or agent pipelines:

```bash
python -m llmsql -u "http://target?id=1" -o report.json
```

## Architecture

```
llmsql/
  __main__.py      CLI entry point
  scanner.py       Scan orchestration loop
  agent.py         OpenAI-compatible LLM backend
  http_probe.py    HTTP client + parameter injection
  detector.py      Heuristic SQL error/timing detection
  payloads.py      Seed payloads + LLM system prompts
  models.py        Data structures
  report.py        Terminal + JSON output
```

## Ethical use

For **authorized security testing only**. Only scan systems you own or have explicit permission to test.

## License

MIT
