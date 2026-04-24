# Separatio

> *"Separa terram ab igne, subtile a spisso, suaviter cum magno ingenio."*
> *— Tabula Smaragdina*

**Separatio** is the alchemical stage of separation — distilling the subtle from the gross, the signal from the noise. The Emerald Tablet describes it as the foundational act of transformation: before you can synthesize, you must first separate.

Applied to cybersecurity intelligence: the daily flood of security publications contains both gold and dross. This pipeline performs the separation automatically — ingesting curated sources, discarding what is redundant or low-signal, and distilling what remains into a structured daily briefing.

Runs fully local with Ollama by default. Optionally routes Stage 2 and Stage 3 to Claude, OpenAI, or Gemini APIs — a single config change, no code modifications required.

---

## What it produces

Two daily reports in Markdown, HTML, and optionally PDF:

- **Vulnerability Briefing** — CVEs of the day, affected systems, CISA KEV + EPSS correlation, technical analysis per critical CVE, patch priority ranking
- **Threat Intelligence Digest** — APT activity, ransomware campaigns, actor tracking (with persistence history), corroborated IOCs, LATAM context, executive summary

Reports are generated as separate files (`vuln-briefing-*`, `threat-digest-*`) and a combined fallback (`threat-briefing-*`).

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
  Truncated to ARTICLE_MAX_TOKENS before Stage 2
    → Ollama: 800 tokens (fits 2K context window)
    → Cloud providers: 2000–3000 tokens (captures IOCs and TTPs from full article body)

     │  (PARALLEL_WORKERS=1, CPU-only)
     ▼  Stage 2 — analyzer.py → LLM  (per-article JSON extraction)
  Extracts: threat_type, severity, actors, CVEs, affected_systems, IOCs → ArticleSummary
  On JSONDecodeError: 1 automatic retry before discarding
  Cached to: reports/summaries-cache-YYYY-MM-DD.json

     │  (Ollama only: explicit keep_alive=0 to free RAM before model swap)
     ▼  Stage 2.5 — correlator.py  (deterministic, no LLM)
  - CVE deduplication: flags CVEs mentioned in ≥2 independent sources
  - CISA KEV lookup: identifies CVEs with confirmed active exploitation
  - EPSS lookup (FIRST.org): probability of exploitation in the next 30 days per CVE
  - PoC signal detection: Exploit-DB / Sploitus / ZDI feed hits
  - IOC correlation: IPs, domains, hashes seen in ≥2 independent sources
  - Actor trending: threat groups mentioned in ≥2 independent sources

     ▼  Stage 2.6 — history.py  (deterministic, no LLM)
  - Appends compact daily record to reports/history.json (~200 bytes/day)
  - Computes trending context over TREND_WINDOW_DAYS (default: 14 days):
      returning actors (active in ≥2 days) vs. new actors (first appearance)
      recurring CVEs (mentioned on ≥2 days this week)
      threat type trend (% change vs. window average, only changes ≥20%)
  - LLM always receives a fixed-size window block — prompt size never grows

     ▼  Stage 3 — analyzer.py → LLM  (consolidated report)
  Pre-computed context injected into prompt:
    - severity distribution, top CVEs by mention count, priority article list
    - verified correlations: KEV + EPSS scores, corroborated CVEs, PoC signals
    - corroborated IOCs, trending actors
    - historical trending: persistent vs. emerging actors, recurring CVEs

     ▼  reporter.py
  reports/vuln-briefing-YYYY-MM-DD.{md,html,pdf}
  reports/threat-digest-YYYY-MM-DD.{md,html,pdf}
  reports/threat-briefing-YYYY-MM-DD.{md,html,pdf}   ← combined fallback
```

---

## Prerequisites

- Python 3.10+
- A running [Miniflux](https://miniflux.app/) instance with an API token
- One of the following LLM backends (see [LLM providers](#llm-providers)):
  - **Ollama** — local, fully private, CPU or GPU
  - **Anthropic / OpenAI / Gemini** — API key required
- *(Optional)* `weasyprint` + system libraries for PDF export

---

## Installation

### 1. Clone and set up the environment

```bash
git clone https://github.com/Fennek115/separatio /opt/threat-pipeline
cd /opt/threat-pipeline

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

#### PDF export dependencies (optional)

`weasyprint` requires a few system libraries on Debian/Ubuntu:

```bash
apt install libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf2.0-0
pip install weasyprint
```

If `weasyprint` is not installed, PDF output is silently skipped — all other formats still work.

### 2. Configure

Edit `config.py` with your environment:

```python
# Choose your LLM provider
PROVIDER = "ollama"   # or: "claude" | "openai" | "gemini"

# Miniflux connection
MINIFLUX_URL       = "http://localhost:8080"
MINIFLUX_API_TOKEN = "your-api-token"   # Settings → API Keys in Miniflux UI

# If using Ollama
OLLAMA_HOST   = "http://192.168.x.x:11434"
SUMMARY_MODEL = "qwen3.5:4b"
REPORT_MODEL  = "qwen3.5:9b"

# If using a cloud provider — set the matching key
ANTHROPIC_API_KEY = ""   # or env var ANTHROPIC_API_KEY
OPENAI_API_KEY    = ""   # or env var OPENAI_API_KEY
GEMINI_API_KEY    = ""   # or env var GEMINI_API_KEY

# Article truncation — increase for cloud providers
ARTICLE_MAX_TOKENS = 800     # Ollama: keep at 800 (fits 2K context)
# ARTICLE_MAX_TOKENS = 2500  # Cloud: captures full IOC lists and TTP details

# Output format
OUTPUT_FORMAT = "both"   # or: "markdown" | "html" | "pdf" | "all" (md+html+pdf)
```

> **Tip:** API keys can be set as environment variables. The config reads them via `os.getenv()`.

### 3. Import feeds

In Miniflux: **Settings → OPML → Import** → select `threat-analysis-feeds.opml`

### 4. Verify connectivity

```bash
python setup_check.py
```

The checker is provider-aware: it verifies Ollama + models when `PROVIDER=ollama`, or the API key + package when using a cloud provider.

### 5. Test run

```bash
python pipeline.py --dry-run          # fetch and extract only, no LLM calls
python pipeline.py --limit 3          # full run with 3 articles
```

---

## Proxmox / LXC setup (Ollama)

This is the reference hardware setup. Skip this section if you are using a cloud provider.

### Infrastructure

| LXC | Role | Specs |
|-----|------|-------|
| 111 | Ollama (CPU-only) | 4 cores i7-10510U, 10 GB RAM |
| 112 | Miniflux + Pipeline | RSS reader on port 8080 |

### LXC 111 — Ollama

Install Ollama:
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Configure the systemd override so Ollama binds to all interfaces:
```bash
mkdir -p /etc/systemd/system/ollama.service.d/
cat > /etc/systemd/system/ollama.service.d/override.conf << 'EOF'
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
Environment="OLLAMA_KEEP_ALIVE=10m"
Environment="OLLAMA_MAX_LOADED_MODELS=1"
EOF

systemctl daemon-reload
systemctl restart ollama
```

Pull the models:
```bash
ollama pull qwen3.5:4b
ollama pull qwen3.5:9b
```

**Sequential model swap**: qwen3.5:4b (~3.2 GB, Stage 2) is explicitly unloaded via `keep_alive=0` before qwen3.5:9b (~7.2 GB, Stage 3) loads. Peak RAM: 7.2 GB — within the 10 GB LXC budget.

### LXC 112 — Pipeline

```bash
apt install python3 python3-venv python3-pip git -y
# Optional: PDF export
apt install libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf2.0-0

git clone <repo-url> /opt/threat-pipeline
cd /opt/threat-pipeline
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Edit `config.py`:
```python
PROVIDER     = "ollama"
OLLAMA_HOST  = "http://192.168.x.x:11434"   # ← IP of LXC 111
MINIFLUX_URL = "http://localhost:8080"
MINIFLUX_API_TOKEN = "your-api-token"
```

Verify:
```bash
python setup_check.py
```

---

## LLM providers

Change `PROVIDER` in `config.py` and set the matching model names — everything else stays the same.

### Ollama (default — fully local)

```python
PROVIDER           = "ollama"
SUMMARY_MODEL      = "qwen3.5:4b"
REPORT_MODEL       = "qwen3.5:9b"
OLLAMA_HOST        = "http://<host>:11434"
ARTICLE_MAX_TOKENS = 800   # keep at 800 for 2K context window
```

Timing on i7-10510U (CPU-only): ~1.75 min/article → 120 articles ≈ 3.5h total.

### Claude (Anthropic)

```bash
pip install anthropic
```

```python
PROVIDER           = "claude"
SUMMARY_MODEL      = "claude-haiku-4-5-20251001"   # fast + cheap for per-article extraction
REPORT_MODEL       = "claude-sonnet-4-6"            # quality report generation
ANTHROPIC_API_KEY  = "sk-ant-..."                   # or env var ANTHROPIC_API_KEY
ARTICLE_MAX_TOKENS = 2500
REPORT_MAX_TOKENS  = 10000
```

### OpenAI

```bash
pip install openai
```

```python
PROVIDER           = "openai"
SUMMARY_MODEL      = "gpt-4o-mini"   # Stage 2
REPORT_MODEL       = "gpt-4o"        # Stage 3
OPENAI_API_KEY     = "sk-..."        # or env var OPENAI_API_KEY
ARTICLE_MAX_TOKENS = 2500
REPORT_MAX_TOKENS  = 10000
```

### Gemini (Google)

```bash
pip install google-generativeai
```

```python
PROVIDER           = "gemini"
SUMMARY_MODEL      = "gemini-2.0-flash"   # Stage 2
REPORT_MODEL       = "gemini-2.5-pro"     # Stage 3
GEMINI_API_KEY     = "AIza..."            # or env var GEMINI_API_KEY
ARTICLE_MAX_TOKENS = 2500
REPORT_MAX_TOKENS  = 10000
```

### Provider comparison

| Provider | Stage 2 (120 articles) | Stage 3 | Privacy | Approx. cost/run |
|----------|------------------------|---------|---------|------------------|
| Ollama | ~3.5h (CPU-only) | ~20–30 min | Full — data stays local | Free |
| Claude | ~2 min | ~30 sec | Articles sent to Anthropic | ~$0.05–0.10 |
| OpenAI | ~2 min | ~30 sec | Articles sent to OpenAI | ~$0.05–0.15 |
| Gemini | ~2 min | ~30 sec | Articles sent to Google | ~$0.01–0.05 |

Cloud providers use direct API calls (no streaming). Ollama uses streaming in Stage 3 to avoid timeout on long CPU-only generations.

---

## Usage

```bash
python pipeline.py                              # full run
python pipeline.py --limit 5                    # quick end-to-end test (5 articles)
python pipeline.py --dry-run                    # Stage 1 only — no LLM calls
python pipeline.py --report-only                # skip Stages 1–2, regenerate report from today's cache
python pipeline.py --no-mark-read               # don't mark articles as read in Miniflux
python pipeline.py --categories "Vulnerability"
python pipeline.py --categories "Threat Intel,Cibersecurity"
```

### Flag reference

| Flag | What it does |
|------|-------------|
| `--limit N` | Cap the run at N articles. Useful for testing without waiting 3+ hours. |
| `--dry-run` | Runs Stage 1 (fetch + extract) but skips all LLM calls. Reports are filled with `[DRY RUN]` placeholders. Good for verifying feed connectivity. |
| `--report-only` | Skips Stages 1 and 2 entirely. Loads `summaries-cache-YYYY-MM-DD.json` and re-runs Stage 3. Use this when tweaking the report prompt or if Stage 3 failed — no need to redo hours of per-article summaries. |
| `--no-mark-read` | Processes articles normally but does not mark them as read in Miniflux. Useful for testing or re-processing. Note: articles are marked as read by default after Stage 2 so they are not re-processed in the next daily run. |
| `--categories` | Comma-separated list of OPML category names. Overrides `FEED_CATEGORIES` in `config.py` at runtime. |

### `--categories` and feed rotation

With 39 feeds, `PER_FEED_LIMIT=10`, and `MAX_ARTICLES=120`, a single run covers roughly 12 feeds. Running the same categories every day means the same feeds get processed repeatedly while others are skipped.

The `--categories` flag enables day-by-day rotation for full weekly coverage:

```bash
python pipeline.py --categories "Vulnerability"
python pipeline.py --categories "Threat Intel"
python pipeline.py --categories "Cibersecurity"
python pipeline.py --categories "Hacking & Research,LATAM"
```

Available category names (must match OPML exactly):
`Vulnerability` · `Threat Intel` · `Cibersecurity` · `Hacking & Research` · `LATAM`

---

## Cron (LXC 112)

For CPU-only hardware (~1.75 min/article in Stage 2), rotating categories keeps each run within ~3.5h:

```cron
0 2 * * 1,3,5  root cd /opt/threat-pipeline && source venv/bin/activate && python pipeline.py --categories "Vulnerability" >> /var/log/threat-pipeline.log 2>&1
0 2 * * 2,4    root cd /opt/threat-pipeline && source venv/bin/activate && python pipeline.py --categories "Threat Intel" >> /var/log/threat-pipeline.log 2>&1
0 3 * * 6      root cd /opt/threat-pipeline && source venv/bin/activate && python pipeline.py --categories "Cibersecurity" >> /var/log/threat-pipeline.log 2>&1
0 3 * * 0      root cd /opt/threat-pipeline && source venv/bin/activate && python pipeline.py --categories "Hacking & Research,LATAM" >> /var/log/threat-pipeline.log 2>&1
```

For cloud providers (Stage 2 takes ~2 min total), a single daily cron at any hour covers all feeds.

---

## Configuration reference

All settings live in `config.py`.

### LLM

| Variable | Default | Notes |
|----------|---------|-------|
| `PROVIDER` | `"ollama"` | `ollama` \| `claude` \| `openai` \| `gemini` |
| `SUMMARY_MODEL` | `"qwen3.5:4b"` | Model for Stage 2 — set to match your provider |
| `REPORT_MODEL` | `"qwen3.5:9b"` | Model for Stage 3 — set to match your provider |
| `ANTHROPIC_API_KEY` | `""` | Required when `PROVIDER=claude` |
| `OPENAI_API_KEY` | `""` | Required when `PROVIDER=openai` |
| `GEMINI_API_KEY` | `""` | Required when `PROVIDER=gemini` |
| `OLLAMA_HOST` | `"http://<IP>:11434"` | Required when `PROVIDER=ollama` |

### Fetch & extraction

| Variable | Default | Notes |
|----------|---------|-------|
| `MAX_ARTICLES` | `120` | Hard cap per run |
| `PER_FEED_LIMIT` | `10` | Prevents high-volume feeds (MSRC: 2975 entries) from dominating |
| `FEED_CATEGORIES` | `None` | List of category names, or `None` for all. Override with `--categories`. |
| `ARTICLE_MAX_TOKENS` | `800` | Content sent per article to Stage 2. Set to 2000–3000 for cloud providers to capture full IOC lists. |
| `MIN_CONTENT_LENGTH` | `200` | Discard articles with fewer than N characters of extractable content |
| `PARALLEL_WORKERS` | `1` | Keep at 1 for CPU-only Ollama |

### Timeouts

| Variable | Default | Notes |
|----------|---------|-------|
| `SUMMARY_TIMEOUT` | `240` | Seconds per article (Stage 2) |
| `REPORT_TIMEOUT` | `2400` | Seconds between stream chunks (Stage 3, Ollama only) |
| `REPORT_MAX_TOKENS` | `10000` | Max output tokens for the report. Use 3500–4000 for Ollama CPU-only. |

### Correlations (Stage 2.5)

| Variable | Default | Notes |
|----------|---------|-------|
| `CISA_KEV_URL` | CISA feed URL | CVEs with confirmed active exploitation |
| `EPSS_API_URL` | FIRST.org API | Exploitation probability scores — no API key required |
| `KEV_FETCH_TIMEOUT` | `15` | Seconds for KEV and EPSS lookups |

### Historical trending (Stage 2.6)

| Variable | Default | Notes |
|----------|---------|-------|
| `HISTORY_FILE` | `"./reports/history.json"` | Compact daily records (~200 bytes/day, ~73 KB/year). Never needs rotation. |
| `TREND_WINDOW_DAYS` | `14` | Days of history used to compute trending. The LLM always receives a fixed-size block regardless of total history length. |

### Output

| Variable | Default | Notes |
|----------|---------|-------|
| `OUTPUT_DIR` | `"./reports"` | Directory for all output files |
| `OUTPUT_FORMAT` | `"both"` | `"markdown"` \| `"html"` \| `"both"` (md+html) \| `"pdf"` \| `"all"` (md+html+pdf) |
| `SPLIT_REPORTS` | `True` | Generate separate `vuln-briefing-*` and `threat-digest-*` files |
| `REPORT_LANGUAGE` | `"español"` | Language for the generated report |

---

## Feed philosophy

Sources are selected by three criteria, in order:

1. **Original research** — primary sources only; no aggregators of aggregators
2. **Scrape-ability** — preference for full RSS content; title-only feeds included only when they provide unique CVE/exploit correlation signal (Exploit-DB, Sploitus, ZDI)
3. **Signal uniqueness** — if two feeds cover the same stories, the lower-signal one is cut

**39 curated sources** across 5 categories:

| Category | Feeds | Cut | Reason |
|----------|-------|-----|--------|
| Cibersecurity | 7 | 4 | Truncated with 403 errors; duplicates of higher-signal sources |
| Hacking & Research | 6 | 2 | High-volume tutorial content; low-frequency web-only scope |
| LATAM | 5 | 1 | Corporate IT news with minimal security signal |
| Threat Intel | 12 | 5 | Overlapping coverage; weekly digest of sources already ingested directly |
| Vulnerability | 9 | 3 | Blocked URLs; duplicated by CISA + Tenable + GitHub Security |
