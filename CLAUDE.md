# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project does

Automated pipeline that reads cybersecurity RSS feeds from Miniflux, summarizes each article with a local LLM (Ollama), and generates a daily Threat Intelligence report in Markdown and HTML.

## Commands

```bash
python pipeline.py                    # full run
python pipeline.py --dry-run          # fetch only, no Ollama calls
python pipeline.py --limit 20         # cap at 20 articles
python pipeline.py --report-only      # re-generate report from today's cache JSON
python pipeline.py --no-mark-read     # skip marking articles as read in Miniflux
python setup_check.py                 # environment diagnostics
```

Install deps: `pip install -r requirements.txt`

## Infrastructure (Proxmox)

- **LXC 111 — ollama**: 4 cores, 10 GB RAM (CPU-only) — Ollama server
- **LXC 112 — miniflux**: Miniflux RSS reader on port 8080

Ollama systemd override required on LXC 111:
```
Environment="OLLAMA_HOST=0.0.0.0:11434"
Environment="OLLAMA_KEEP_ALIVE=10m"
Environment="OLLAMA_MAX_LOADED_MODELS=1"
```

## Models

| Stage | Model | RAM | Thinking |
|-------|-------|-----|----------|
| Stage 2: per-article JSON extraction | `qwen3.5:4b` | ~3.2 GB | `think=False` |
| Stage 3: consolidated report | `qwen3.5:9b` | ~7.2 GB | `think=True` |

**Sequential swap**: models are never loaded simultaneously. Ollama auto-evicts when RAM is needed. To force early eviction after Stage 2, pass `keep_alive=0` on the last Stage 2 call (not currently implemented).

`PARALLEL_WORKERS=2` for Stage 2: 2 × 3.2 GB = ~6.4 GB peak, within the 10 GB limit.

## Pipeline architecture

```
Miniflux API (unread articles)
     │
     ▼ extractor.py
  1. Feed content (if len > 300 chars)
  2. Trafilatura web scrape fallback
  3. BeautifulSoup fallback
  4. Title-only last resort
  → Truncated to ~800 tokens (4 chars ≈ 1 token)

     │ (PARALLEL_WORKERS=2 threads)
     ▼ analyzer.py → qwen3.5:4b (think=False, num_ctx=2048)
  Extracts JSON: threat_type, severity, actors, CVEs, IOCs → ArticleSummary
  Cached to: reports/summaries-cache-YYYY-MM-DD.json

     │ (model swap)
     ▼ analyzer.py → qwen3.5:9b (think=True, num_ctx=16384)
  Receives all summaries sorted by severity_score (desc)
  Generates Markdown report

     ▼ reporter.py
  reports/threat-briefing-YYYY-MM-DD.{md,html}
```

## Non-obvious implementation details

**`think` parameter**: qwen3.5 models support `options={"think": False}` via the Ollama Python client to disable chain-of-thought. Stage 2 disables it for cleaner JSON output; Stage 3 enables it for better report synthesis. The pipeline strips any residual `<think>...</think>` blocks via regex before using the output.

**Cache/resume**: Stage 2 writes `summaries-cache-YYYY-MM-DD.json` before Stage 3 runs. `--report-only` loads this cache and skips Stages 1–2. Cache loading uses `s.__dict__.update(d)` which is order-dependent — construct the `ArticleSummary` first with required fields, then update.

**`FEED_CATEGORIES` filter**: takes category title strings (e.g. `"Vulnerability"`), not IDs. Filtering happens in `pipeline.py:stage1_fetch` after fetching from Miniflux, not at the API level.

**Miniflux auth**: `MinifluxClient` prefers `MINIFLUX_API_TOKEN` (header `X-Auth-Token`) over username/password. Set `MINIFLUX_API_TOKEN` in `config.py` for production use.

**`jinja2` in `requirements.txt` is unused**: `reporter.py` implements its own `markdown_to_html_body()` converter without Jinja2. Do not add Jinja2 rendering without removing the custom converter.

**Stale model names**: `README.md` and the HTML footer in `reporter.py` still reference "Mistral 7B + Phi-4" — the actual models are `qwen3.5:4b` and `qwen3.5:9b`.

## Configuration (`config.py`)

Before first use, set:
- `OLLAMA_HOST` — IP of LXC 111
- `MINIFLUX_URL` — IP/port of LXC 112 (or `localhost:8080` if running on LXC 112)
- `MINIFLUX_PASSWORD` or `MINIFLUX_API_TOKEN`

Key tunable values: `MAX_ARTICLES`, `PARALLEL_WORKERS`, `SUMMARY_CTX`, `REPORT_CTX`, `OLLAMA_TIMEOUT` (default 180 s; Stage 3 with thinking may need more).

## Cron (LXC 112)

```cron
30 6 * * * root cd /opt/threat-pipeline && source venv/bin/activate && python pipeline.py >> /var/log/threat-pipeline.log 2>&1
```
