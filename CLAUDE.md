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

**Sequential swap**: `unload_model()` in `analyzer.py` makes an explicit `keep_alive=0` call after Stage 2 completes to force eviction of the 4b model before Stage 3 loads the 9b.

**`PARALLEL_WORKERS=1`**: CPU-only Ollama serializes requests to the same model. With 2 workers, the second request queues behind the first and its httpx timeout fires before Ollama starts processing it. Only raise this if running with GPU or a truly concurrent Ollama setup.

## Pipeline architecture

```
Miniflux API (unread articles, ordered by published_at desc)
     │
     ▼ extractor.py
  1. Feed content if has_full_content(min_length)
  2. Trafilatura web scrape fallback
  3. BeautifulSoup fallback
  4. Title-only last resort
  → Truncated to ~800 tokens (4 chars ≈ 1 token)

     │ (PARALLEL_WORKERS=1)
     ▼ analyzer.py → qwen3.5:4b (think=False, num_ctx=2048)
  Extracts JSON: threat_type, severity, actors, CVEs, IOCs → ArticleSummary
  On JSONDecodeError: 1 automatic retry before discarding
  Cached to: reports/summaries-cache-YYYY-MM-DD.json

     │ (unload_model: explicit keep_alive=0 to free RAM)
     ▼ analyzer.py → qwen3.5:9b (think=True, num_ctx=16384, stream=True)
  Receives all summaries sorted by severity_score (desc)
  Generates Markdown report via streaming (logs progress every 100 tokens)

     ▼ reporter.py
  reports/threat-briefing-YYYY-MM-DD.{md,html}
  pipeline.log written to OUTPUT_DIR (not the working directory)
```

## Non-obvious implementation details

**`think` and `keep_alive` are top-level `chat()` params**: in the Ollama Python client they are NOT inside the `options` dict — they are direct keyword arguments to `client.chat()`. `options` only accepts model parameters (temperature, num_ctx, num_thread, etc.).

**`timeout` goes to the Client constructor**: `ollama.Client(host=..., timeout=N)` passes the value to httpx. Passing it anywhere else has no effect. For streaming (Stage 3), timeout applies between chunks — not to the total generation — so long thinking runs don't time out as long as the model keeps producing tokens.

**Separate timeouts per stage** (`config.py`):
- `SUMMARY_TIMEOUT = 240` — qwen3.5:4b without thinking, ~2 min per article on i7-10510U
- `REPORT_TIMEOUT = 900` — applies between streaming chunks; actual generation can take 30-60 min

**Stage 3 uses streaming**: `generate_report()` uses `stream=True` to avoid a single-response timeout on long generations. Tokens are accumulated and joined before stripping `<think>` blocks. Without streaming, a 2000-token report at 1 tok/sec would need a 2000s timeout.

**Cache/resume**: Stage 2 writes `summaries-cache-YYYY-MM-DD.json` before Stage 3 runs. `--report-only` loads this cache and skips Stages 1–2. Useful when tweaking the Stage 3 prompt or if Stage 3 failed — no need to re-run the 30+ min of summaries.

**`FEED_CATEGORIES` filter**: takes category title strings (e.g. `"Vulnerability"`), not IDs. Filtering happens in `pipeline.py:stage1_fetch` after fetching from Miniflux, not at the API level. High-volume feeds (MSRC: 2975 entries, Black Hills: 909) will dominate the batch without this filter or a prior mass mark-as-read.

**Miniflux auth**: `MinifluxClient` prefers `MINIFLUX_API_TOKEN` (header `X-Auth-Token`) over username/password. `setup_check.py` also respects this — it uses the token if configured.

**`has_full_content(min_length)`**: method on `Article`, not a property. Accepts the same `min_length` passed to `extract_article_text()` so both checks use the same threshold from `config.MIN_CONTENT_LENGTH`.

## Configuration (`config.py`)

Before first use, set:
- `OLLAMA_HOST` — IP of LXC 111
- `MINIFLUX_URL` — IP/port of LXC 112 (or `localhost:8080` if running on LXC 112)
- `MINIFLUX_PASSWORD` or `MINIFLUX_API_TOKEN`

Key tunable values:

| Variable | Default | Notes |
|----------|---------|-------|
| `MAX_ARTICLES` | 120 | Hard cap per run |
| `PARALLEL_WORKERS` | 1 | Keep at 1 for CPU-only |
| `SUMMARY_TIMEOUT` | 240 | Seconds; per-article Stage 2 |
| `REPORT_TIMEOUT` | 2400 | Seconds between stream chunks Stage 3; first chunk can take 20-30 min on CPU-only (model load) |
| `REPORT_THINKING` | True | Set to False for faster testing |
| `FEED_CATEGORIES` | None | List of category names to filter, or None for all. Override via `--categories` CLI. |

## Cron (LXC 112)

```cron
0 3 * * * root cd /opt/threat-pipeline && source venv/bin/activate && python pipeline.py >> /var/log/threat-pipeline.log 2>&1
```

Timing on i7-10510U (CPU-only):
- Stage 2: ~1.75 min/article → 120 artículos ≈ 3.5 horas
- Stage 3: `think=False` → ~15–20 min para cualquier volumen de artículos
- Total: ~3.75 horas → cron a las 03:00 deja el reporte listo ~06:45, antes de las 08:00.
