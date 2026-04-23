# Separatio

> *"Separa terram ab igne, subtile a spisso, suaviter cum magno ingenio."*
> *— Tabula Smaragdina*

**Separatio** is the alchemical stage of separation — distilling the subtle from the gross, the signal from the noise. The Emerald Tablet describes it as the foundational act of transformation: before you can synthesize, you must first separate.

Applied to cybersecurity intelligence: the daily flood of security publications contains both gold and dross. This pipeline performs the separation automatically — ingesting curated sources, discarding what is redundant or low-signal, and distilling what remains into a structured daily briefing.

No data leaves your infrastructure. No external APIs. Local LLM, self-hosted RSS reader, your hardware.

---

## What it produces

Two daily reports generated in Markdown and HTML:

- **Vulnerability Briefing** — CVEs of the day, affected systems, CVSS context, CISA KEV correlation, patch priority ranking
- **Threat Intelligence Digest** — APT activity, ransomware campaigns, actor tracking, LATAM context, executive summary

---

## Pipeline

```
Miniflux RSS (unread articles, sorted by published_at desc)
     │
     ▼  Stage 1 — extractor.py
  Content extraction chain:
    1. RSS full-text  (if ≥ MIN_CONTENT_LENGTH chars)
    2. Trafilatura web scrape fallback
    3. BeautifulSoup fallback
    4. Title-only last resort
  Per-feed cap (PER_FEED_LIMIT) — prevents high-volume feeds from monopolizing the batch
  Truncated to ~800 tokens before Stage 2

     │  (PARALLEL_WORKERS=1, CPU-only)
     ▼  Stage 2 — analyzer.py → qwen3.5:4b  (think=False, ~1.75 min/article on i7-10510U)
  Extracts JSON: threat_type, severity, actors, CVEs, IOCs → ArticleSummary
  Cached to: reports/summaries-cache-YYYY-MM-DD.json

     │  (unload_model: explicit keep_alive=0 to free RAM before model swap)
     ▼  Stage 2.5 — correlator.py
  CVE deduplication across sources, CISA KEV lookup, PoC signal detection

     ▼  Stage 3 — analyzer.py → qwen3.5:9b  (think=False, streaming)
  Pre-computed analytics injected into prompt:
    severity distribution, top CVEs by mention count, priority article list
  This replaces what the model would reason about in <think>,
  enabling think=False without quality loss

     ▼  reporter.py
  reports/vuln-briefing-YYYY-MM-DD.{md,html}
  reports/threat-digest-YYYY-MM-DD.{md,html}
  reports/threat-briefing-YYYY-MM-DD.{md,html}   ← combined fallback
```

---

## Infrastructure

Runs on Proxmox with two LXC containers:

| LXC | Role | Specs |
|-----|------|-------|
| 111 | Ollama (CPU-only) | 4 cores i7-10510U, 10 GB RAM |
| 112 | Miniflux + Pipeline | RSS reader on port 8080 |

**Sequential model swap**: qwen3.5:4b (~3.2 GB, Stage 2) is explicitly unloaded via `keep_alive=0` before qwen3.5:9b (~7.2 GB, Stage 3) loads. Peak RAM: 7.2 GB — within the 10 GB LXC budget.

---

## Setup

```bash
pip install -r requirements.txt
```

Pull models in Ollama (LXC 111):
```bash
ollama pull qwen3.5:4b   # Stage 2 — per-article extraction (~3.2 GB RAM)
ollama pull qwen3.5:9b   # Stage 3 — consolidated report   (~7.2 GB RAM)
```

Edit `config.py`:
```python
OLLAMA_HOST       = "http://<IP_LXC_111>:11434"
MINIFLUX_URL      = "http://localhost:8080"
MINIFLUX_API_TOKEN = "your-api-token"   # Settings → API Keys in Miniflux UI
```

Import feeds into Miniflux: Settings → OPML → Import `threat-analysis-feeds.opml`

Verify connectivity:
```bash
python setup_check.py
```

---

## Usage

```bash
python pipeline.py                    # full run — all categories, up to MAX_ARTICLES
python pipeline.py --limit 5          # quick end-to-end test (5 articles)
python pipeline.py --dry-run          # Stage 1 only — fetch and extract, no Ollama calls
python pipeline.py --report-only      # skip Stages 1–2, regenerate report from today's cache
python pipeline.py --no-mark-read     # don't mark articles as read in Miniflux after processing
python pipeline.py --categories "Vulnerability"
python pipeline.py --categories "Threat Intel,Cibersecurity"
```

### Flag reference

| Flag | What it does |
|------|-------------|
| `--limit N` | Cap the run at N articles. Useful for testing without waiting 3+ hours. |
| `--dry-run` | Runs Stage 1 (fetch + extract) but skips all Ollama calls. Reports are filled with `[DRY RUN]` placeholders. Good for verifying feed connectivity. |
| `--report-only` | Skips Stages 1 and 2 entirely. Loads the existing `summaries-cache-YYYY-MM-DD.json` and re-runs Stage 3. Use this when you want to tweak the report prompt or if Stage 3 failed — no need to redo 3+ hours of per-article summaries. |
| `--no-mark-read` | Processes articles normally but does not mark them as read in Miniflux. Articles will appear again on the next run. Useful for testing or re-processing. |
| `--categories` | Comma-separated list of OPML category names to include. Overrides `FEED_CATEGORIES` in `config.py` at runtime — no file edit needed. See category rotation below. |

### `--categories` and feed coverage

With 39 feeds, `PER_FEED_LIMIT=10`, and `MAX_ARTICLES=120`, a single run covers roughly 12 feeds (~30% of the total). Running the same categories every day means the same feeds get processed repeatedly while others are skipped.

The `--categories` flag solves this by letting each cron job target a specific slice:

```bash
# Each job covers one category — different days, full weekly coverage
python pipeline.py --categories "Vulnerability"
python pipeline.py --categories "Threat Intel"
python pipeline.py --categories "Cibersecurity"
python pipeline.py --categories "Hacking & Research,LATAM"
```

Available category names (must match OPML exactly):
- `Vulnerability`
- `Threat Intel`
- `Cibersecurity`
- `Hacking & Research`
- `LATAM`

---

## Feed philosophy

Sources are selected by three criteria, in order:

1. **Original research** — primary sources only; no aggregators of aggregators
2. **Scrape-ability** — preference for full RSS content; title-only feeds included only when they provide unique CVE/exploit correlation signal (Exploit-DB, Sploitus, ZDI)
3. **Signal uniqueness** — if two feeds cover the same stories, the lower-signal one is cut

**39 curated sources** across 5 categories. The separatio was applied to the sources themselves:

| Category | Feeds | Cut | Reason |
|----------|-------|-----|--------|
| Cibersecurity | 7 | 4 | Truncated with 403 errors; duplicates of higher-signal sources |
| Hacking & Research | 6 | 2 | High-volume tutorial content; low-frequency web-only scope |
| LATAM | 5 | 1 | Corporate IT news with minimal security signal |
| Threat Intel | 12 | 5 | Overlapping coverage; weekly digest of sources already ingested directly |
| Vulnerability | 9 | 3 | Blocked URLs; duplicated by CISA + Tenable + GitHub Security |

---

## Category rotation (recommended cron on LXC 112)

With CPU-only hardware (~1.75 min/article in Stage 2), full coverage requires rotating
categories across days. Each run fits within ~3.5h and completes before 06:00:

```cron
0 2 * * 1,3,5  root cd /opt/threat-pipeline && source venv/bin/activate && python pipeline.py --categories "Vulnerability" >> /var/log/threat-pipeline.log 2>&1
0 2 * * 2,4    root cd /opt/threat-pipeline && source venv/bin/activate && python pipeline.py --categories "Threat Intel" >> /var/log/threat-pipeline.log 2>&1
0 3 * * 6      root cd /opt/threat-pipeline && source venv/bin/activate && python pipeline.py --categories "Cibersecurity" >> /var/log/threat-pipeline.log 2>&1
0 3 * * 0      root cd /opt/threat-pipeline && source venv/bin/activate && python pipeline.py --categories "Hacking & Research,LATAM" >> /var/log/threat-pipeline.log 2>&1
```

---

## Configuration

Key variables in `config.py`:

| Variable | Default | Notes |
|----------|---------|-------|
| `OLLAMA_HOST` | `http://<IP>:11434` | LXC 111 |
| `MINIFLUX_URL` | `http://localhost:8080` | LXC 112 |
| `MAX_ARTICLES` | 120 | Hard cap per run (context window ~140 max for qwen3.5:9b) |
| `PER_FEED_LIMIT` | 10 | Prevents high-volume feeds (MSRC: 2975 entries) from dominating |
| `REPORT_THINKING` | False | Disabled; pre-computed analytics injected instead |
| `FEED_CATEGORIES` | None | Override with `--categories` CLI arg |
| `PARALLEL_WORKERS` | 1 | Keep at 1 for CPU-only Ollama |
