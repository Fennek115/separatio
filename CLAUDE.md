# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project does

Automated pipeline that reads cybersecurity RSS feeds from Miniflux, summarizes each article with a local LLM (Ollama) or cloud provider (Claude, OpenAI, Gemini), and generates a daily Threat Intelligence report in Markdown, HTML, and/or PDF.

## Commands

```bash
python pipeline.py                    # full run
python pipeline.py --dry-run          # fetch only, no LLM calls
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

| Stage | Model (Ollama default) | RAM | Thinking |
|-------|------------------------|-----|----------|
| Stage 2: per-article JSON extraction | `qwen3.5:4b` | ~3.2 GB | `think=False` |
| Stage 3–4: phase reports + synthesis | `qwen3.5:9b` | ~7.2 GB | `think=False` |

**Sequential swap**: `unload_model()` in `analyzer.py` makes an explicit `keep_alive=0` call after Stage 2 completes to force eviction of the 4b model before Stage 3 loads the 9b.

**`PARALLEL_WORKERS=1`**: CPU-only Ollama serializes requests to the same model. With 2 workers, the second request queues behind the first and its httpx timeout fires before Ollama starts processing it. Only raise this if running with GPU or a truly concurrent Ollama setup.

**Multi-provider**: `PROVIDER` in `config.py` selects `"ollama"` | `"claude"` | `"openai"` | `"gemini"`. Cloud providers can use per-phase model routing (e.g. Sonnet for vulnerability, Haiku for general). API keys read from env vars `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`.

## Pipeline architecture

```
Miniflux API (unread articles, ordered by published_at desc)
     │
     ▼ Stage 1 — extractor.py
  1. Feed content if has_full_content(min_length)
  2. Trafilatura web scrape fallback
  3. BeautifulSoup fallback
  4. Title-only last resort
  → Truncated to ARTICLE_MAX_TOKENS (~800 Ollama / ~2000-3000 cloud)
  → NO_SCRAPE_DOMAINS bypasses web fetch for sites that block scrapers

     │ (PARALLEL_WORKERS=1)
     ▼ Stage 2 — analyzer.py → qwen3.5:4b (think=False, num_ctx=2048)
  Extracts JSON: threat_type, severity, actors, CVEs, IOCs → ArticleSummary
  On JSONDecodeError: 1 automatic retry before discarding
  Cached to: reports/summaries-cache-YYYY-MM-DD.json
  → unload_model(): explicit keep_alive=0 to free RAM before Stage 3

     │
     ▼ Stage 2.5 — correlator.py  [no LLM — deterministic]
  Cross-references CVEs, actors, IOCs across all summaries:
  - corroborated_cves: CVEs in ≥2 independent sources
  - kev_active_cves: CVEs present in CISA KEV feed (actively exploited)
  - poc_available_cves: CVEs from Exploit-DB / Sploitus / ZDI feeds
  - epss_scores: probability scores from FIRST.org EPSS API
  - trending_actors: actors in ≥2 sources
  - corroborated_iocs: IOCs in ≥2 sources (defang-normalized)
  → CorrelationContext.format_for_prompt() injects verified facts into Stage 3

     │
     ▼ Stage 2.6 — history.py  [no LLM — deterministic]
  Appends compact daily record to reports/history.json (~200 bytes/day)
  Builds TrendingContext from last TREND_WINDOW_DAYS (default 14) days:
  - returning_actors: actors active in ≥2 days of the window
  - new_actors: actors seen today but absent from the window
  - recurring_cves: CVEs also seen in ≥2 prior days
  - threat_type_delta: % change vs. window average (only if ≥20%)
  → TrendingContext.format_for_prompt() injected into threat_intel phase

     │
     ▼ Stage 2.7 — enrichment.py + enrichers/  [pluggable, fault-tolerant]
  Cross-references the day's IOCs against external reputation sources:
  - IpsumEnricher    — IPs in aggregated public blocklists (IPsum, no key)
  - OpenPhishEnricher— phishing URLs/domains (OpenPhish feed, no key)
  - IpReputationEnricher — IPs via the ipcheck library (AbuseIPDB/VT/GreyNoise/
                       OTX/URLhaus/ThreatFox/Shodan); needs keys, OFF by default
  → EnrichmentContext.format_for_prompt() appended to CorrelationContext
    .extra_blocks (so it reaches Stage 3 without changing analyzer.py signatures)
  → Whole stage wrapped in try/except in pipeline.stage27_enrich: never aborts
    the run. Add a source = new enrichers/*.py subclass + register in
    build_enrichers() + toggle in config.ENRICHERS (no pipeline/analyzer edits).

     │ (PHASE_REPORTS=True — default)
     ▼ Stage 3 — 4 sequential specialized phases (qwen3.5:9b, stream=True)
  Articles routed by Miniflux category via PHASE_CATEGORY_MAP:
  ┌─────────────────┬────────────────────────────────────────────────┐
  │ Phase           │ Miniflux categories / receives                 │
  ├─────────────────┼────────────────────────────────────────────────┤
  │ vulnerability   │ Vulnerability — gets CorrelationContext        │
  │ threat_intel    │ Threat Intel, Hacking & Research               │
  │                 │   — gets CorrelationContext + TrendingContext   │
  │ latam           │ LATAM                                          │
  │ general         │ Cibersecurity                                  │
  └─────────────────┴────────────────────────────────────────────────┘
  Each phase: top N articles by severity_score + correlation block in prompt

     │
     ▼ Stage 4 — synthesis (qwen3.5:9b)
  Receives all 4 phase outputs as input
  Generates executive cross-domain summary (PHASE_MAX_TOKENS["synthesis"])

     ▼ reporter.py
  reports/threat-briefing-YYYY-MM-DD.{md,html,pdf}
  pipeline.log written to OUTPUT_DIR (not the working directory)
```

## Non-obvious implementation details

**Enrichment (Stage 2.7) injects via `CorrelationContext.extra_blocks`**: rather than threading a new param through `generate_report`/`generate_phase_report`, `stage27_enrich` appends the enrichment prompt block to `correlation.extra_blocks`, which `format_for_prompt()` renders at the end. This keeps `analyzer.py` signatures untouched. Enrichment only reaches phases that already receive `correlation` (vulnerability, threat_intel).

**`ip_reputation` enricher imports ipcheck by path**: `enrichers/ip_reputation.py` does `sys.path.insert(config.IPCHECK_DIR)` then `import ip_enricher` — the two local repos stay decoupled (no packaging/install). It paces VirusTotal (sleeps `ENRICH_VT_SLEEP`s only after an IP reaches Level 3) and caps calls at `ENRICH_MAX_IPS`.

**Paths are anchored to `PROJECT_ROOT`** (`config.py`): `OUTPUT_DIR`/`HISTORY_FILE` are absolute (`Path(__file__).parent`). Running from any cwd (cron) yields the same locations — previously relative paths scattered reports and silently reset trending history.

**`history.json` is written atomically** (`history.save_history`): temp file + `fsync` + `os.replace`. Safe against crashes/concurrent runs.

**Network calls retry with backoff** (`net.request_with_retry`): used by `MinifluxClient` and the KEV/EPSS fetches. Retries on `ConnectionError`/`Timeout`/429/5xx only; no new dependency (not `tenacity`).

**Stage 2 fail-fast**: `stage2_summarize` aborts if ≥`STAGE2_FAIL_FAST_THRESHOLD` (0.5) of articles fail to summarize — avoids burning hours on Stage 3 to emit an empty report when the LLM provider is down.

**Tests**: `python3 -m pytest tests/ -q` (deterministic, no network — HTTP monkeypatched). See `IMPROVEMENTS.md` for the full review and the roadmap of pending large refactors (provider abstraction, Jinja2 reporter, pipeline split).

**`think` and `keep_alive` are top-level `chat()` params**: in the Ollama Python client they are NOT inside the `options` dict — they are direct keyword arguments to `client.chat()`. `options` only accepts model parameters (temperature, num_ctx, num_thread, etc.).

**`timeout` goes to the Client constructor**: `ollama.Client(host=..., timeout=N)` passes the value to httpx. Passing it anywhere else has no effect. For streaming (Stage 3–4), timeout applies between chunks — not to the total generation — so long thinking runs don't time out as long as the model keeps producing tokens.

**Separate timeouts per stage** (`config.py`):
- `SUMMARY_TIMEOUT = 240` — qwen3.5:4b without thinking, ~2 min per article on i7-10510U
- `REPORT_TIMEOUT = 2400` — applies between streaming chunks; first chunk can take 20-30 min on CPU-only (model load)

**Stage 3–4 use streaming**: `generate_report()` uses `stream=True` to avoid a single-response timeout on long generations. Tokens are accumulated and joined before stripping `<think>` blocks.

**Cache/resume**: Stage 2 writes `summaries-cache-YYYY-MM-DD.json` before Stages 2.5–4 run. `--report-only` loads this cache and skips Stages 1–2. Useful when tweaking Stage 3 prompts or if Stage 3 failed.

**`PHASE_REPORTS=False` (legacy mode)**: skips the 4-phase split and runs a single consolidated prompt (Stage 3 only, no Stage 4). Use for Ollama CPU-only when RAM or time is constrained.

**Correlator is deterministic — no LLM**: `correlator.py` only does exact ID matching. CVE normalization (`CVE-XXXX-YYYY` uppercase), IOC defanging (`evil[.]com` → `evil.com`, `hxxp://` → `http://`), and actor deduplication are all regex/string ops. Never passes data to Ollama.

**EPSS chunking**: FIRST.org EPSS API accepts up to ~400 CVEs per request. `correlator.py` chunks in batches of 400 to avoid URL length limits.

**History file never rotates**: `history.json` grows at ~200 bytes/day (~73 KB/year). The LLM always receives a fixed-size window (`TREND_WINDOW_DAYS`), not the full file.

**`FEED_CATEGORIES` filter**: takes category title strings (e.g. `"Vulnerability"`), not IDs. Filtering happens in `pipeline.py:stage1_fetch` after fetching from Miniflux, not at the API level.

**`PER_FEED_LIMIT`**: caps articles per feed before the global `MAX_ARTICLES` cap. Prevents high-volume feeds (MSRC: ~2975 entries, Black Hills: ~909) from monopolizing the batch.

**Miniflux auth**: `MinifluxClient` prefers `MINIFLUX_API_TOKEN` (header `X-Auth-Token`) over username/password. `setup_check.py` also respects this.

**`has_full_content(min_length)`**: method on `Article`, not a property. Accepts the same `min_length` passed to `extract_article_text()` so both checks use the same threshold from `config.MIN_CONTENT_LENGTH`.

## Configuration (`config.py`)

Before first use, set:
- `PROVIDER` — `"ollama"` (default) or cloud provider
- `OLLAMA_HOST` — IP of LXC 111 (if using Ollama)
- `MINIFLUX_URL` — IP/port of LXC 112 (or `localhost:8080` if running on LXC 112)
- `MINIFLUX_PASSWORD` or `MINIFLUX_API_TOKEN`
- API key env var if using a cloud provider

Key tunable values:

| Variable | Default | Notes |
|----------|---------|-------|
| `MAX_ARTICLES` | 120 | Hard cap per run |
| `PER_FEED_LIMIT` | 10 | Max articles per feed (prevents monopolization) |
| `PARALLEL_WORKERS` | 1 | Keep at 1 for CPU-only |
| `SUMMARY_TIMEOUT` | 240 | Seconds; per-article Stage 2 |
| `REPORT_TIMEOUT` | 2400 | Seconds between stream chunks Stage 3–4 |
| `REPORT_THINKING` | False | Set to True only when testing with thinking-capable models |
| `FEED_CATEGORIES` | None | List of category names to filter, or None for all |
| `PHASE_REPORTS` | True | False = legacy single-prompt mode (Ollama CPU-only) |
| `PHASE_MODELS` | all None | Per-phase model overrides; None falls back to `REPORT_MODEL` |
| `PHASE_MAX_TOKENS` | see config | Per-phase output token limits (vulnerability: 4500, synthesis: 2000, …) |
| `PHASE_ARTICLE_LIMITS` | see config | Top-N articles per phase (vulnerability: 50, threat_intel: 35, …) |
| `TREND_WINDOW_DAYS` | 14 | Days of history sent to LLM for trending context |
| `HISTORY_FILE` | `./reports/history.json` | Append-only daily record |
| `CISA_KEV_URL` | cisa.gov feed | Fetched each run to flag actively exploited CVEs |
| `EPSS_API_URL` | first.org API | CVE exploitation probability scores |
| `KEV_FETCH_TIMEOUT` | 15 | Seconds for KEV + EPSS HTTP requests |
| `NO_SCRAPE_DOMAINS` | vulners, sploitus, wiz.io | Domains that block scrapers — use RSS content only |
| `STAGE2_FAIL_FAST_THRESHOLD` | 0.5 | Abort if ≥ this fraction of summaries fail |
| `ENRICHMENT_ENABLED` | True | Master switch for Stage 2.7 |
| `ENRICHERS` | ipsum/openphish on, ip_reputation off | Per-enricher toggles |
| `IPSUM_MIN_SCORE` | 3 | Min public blocklists reporting an IP to flag it |
| `IPCHECK_DIR` | path to ipcheck repo | For the `ip_reputation` enricher |
| `ENRICH_MAX_IPS` / `ENRICH_VT_SLEEP` | 25 / 15 | API-IP cap / VT pacing (Level-3 IPs) |

## Cron (LXC 112)

```cron
0 3 * * * root cd /opt/threat-pipeline && source venv/bin/activate && python pipeline.py >> /var/log/threat-pipeline.log 2>&1
```

Timing on i7-10510U (CPU-only):
- Stage 2: ~1.75 min/article → 120 articles ≈ 3.5 hours
- Stage 2.5–2.6: <30 seconds (HTTP fetch KEV/EPSS + local computation)
- Stage 3–4: `think=False` → ~15–20 min for any article volume
- Total: ~3.75 hours → cron at 03:00 leaves report ready ~06:45, before 08:00
