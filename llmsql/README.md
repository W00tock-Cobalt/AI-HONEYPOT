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

## Ethical use

For **authorized security testing only**. Only scan systems you own or have explicit permission to test.

## License

MIT
