# Separatio

> *"Separa terram ab igne, subtile a spisso, suaviter cum magno ingenio."*
> *— Tabula Smaragdina*

**Separatio** is the alchemical stage of separation — distilling the subtle from the gross, the signal from the noise. The Emerald Tablet describes it as the foundational act of transformation: before you can synthesize, you must first separate.

Applied to cybersecurity intelligence: the daily flood of security publications contains both gold and dross. This pipeline performs the separation automatically — ingesting curated sources, discarding what is redundant or low-signal, and distilling what remains into a structured daily briefing.

Runs fully local with Ollama by default. Optionally routes Stage 2 and Stage 3 to Claude, OpenAI, or Gemini APIs — a single config change, no code modifications required.

---

## What it produces

**Daily report** (`PHASE_REPORTS = True`, default for cloud providers) — five sections assembled into a single document:

| Section | Content |
|---------|---------|
| **Resumen Ejecutivo** | Alert level, #1 priority action, cross-domain correlations, strategic recommendation for the week |
| **Vulnerability Briefing** | CVE table with CVSS / EPSS / CISA KEV status, technical analysis per critical CVE, patch priority list with source links |
| **Threat Intelligence Digest** | APT campaigns, actor profiles (MITRE TTPs, attribution confidence), corroborated IOCs, SOC detection recommendations |
| **Contexto Regional LATAM** | Regional incidents by country/sector, global threats with LATAM exposure probability |
| **Panorama General** | Cybersecurity news headlines, industry trends, regulatory updates |

**IOC Export** — always written, regardless of `OUTPUT_FORMAT`:
- `iocs-YYYY-MM-DD.csv` — one row per unique IOC: `date, ioc, type, severity, title, feed, cves`
- `iocs-YYYY-MM-DD.json` — same data grouped by type (`ip` / `domain` / `sha256` / `sha1` / `md5` / `url` / `other`)

**Weekly digest** (run with `--weekly`):
- Consolidated week-over-week view: CVE trends, most active actors, dominant TTPs, LATAM context, recommendations for the next 7 days

**Legacy mode** (`PHASE_REPORTS = False`) — single combined prompt, produces `vuln-briefing-*` + `threat-digest-*` split files. Recommended for Ollama CPU-only.

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

     ▼  Semantic dedup (pipeline.py, no LLM)
  Groups summaries that share ≥2 CVEs with Jaccard similarity ≥0.4
  Keeps the highest-severity entry per group; merges IOCs and actors
  Reduces Stage 3 prompt size when the same CVE is covered by multiple feeds

  Cached to: reports/summaries-cache-YYYY-MM-DD.json
  IOC export: reports/iocs-YYYY-MM-DD.{csv,json}

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

     ▼  Stage 3 — analyzer.py → LLM  (multi-phase, PHASE_REPORTS=True)
  4 sequential specialized calls, each with domain-expert system prompt:
    3A. Vulnerability  → CVE analyst persona (KEV/EPSS context injected)
    3B. Threat Intel   → APT analyst persona (correlations + trending injected)
    3C. LATAM          → regional analyst persona
    3D. General        → news editor persona
  Phase routing: PHASE_CATEGORY_MAP in config.py
    → new Miniflux feeds route automatically by category
    → unknown categories fall back to General with no code changes

     ▼  Stage 4 — analyzer.py → LLM  (master synthesis)
  Receives all 4 phase outputs as input.
  Produces: alert level, #1 priority, cross-domain correlations, strategic recommendation.

     ▼  reporter.py
  OUTPUT_DIR/YYYY-MM-DD/
  ├── threat-briefing-YYYY-MM-DD.pdf      ← final deliverable (all sections)
  ├── summaries-cache-YYYY-MM-DD.json     ← article cache for --report-only / --weekly
  ├── reports/
  │   ├── threat-briefing-YYYY-MM-DD.md
  │   └── threat-briefing-YYYY-MM-DD.html
  └── iocs/
      ├── iocs-YYYY-MM-DD.csv
      └── iocs-YYYY-MM-DD.json

  Legacy mode (PHASE_REPORTS=False):
  OUTPUT_DIR/YYYY-MM-DD/reports/
  ├── vuln-briefing-YYYY-MM-DD.{md,html}
  ├── threat-digest-YYYY-MM-DD.{md,html}
  └── threat-briefing-YYYY-MM-DD.{md,html,pdf}

─────────── Weekly (--weekly) ───────────
  Loads last N days of summaries-cache-*.json from dated subfolders
     ▼  analyzer.py → LLM (single consolidated prompt)
  OUTPUT_DIR/YYYY-WXX/
  ├── weekly-briefing-YYYY-WXX.pdf
  ├── reports/weekly-briefing-YYYY-WXX.{md,html}
  └── iocs/iocs-YYYY-WXX.{csv,json}
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

Edit `config.py`. The minimum required settings depend on your backend:

**Ollama (local)**
```python
PROVIDER      = "ollama"
OLLAMA_HOST   = "http://192.168.x.x:11434"
SUMMARY_MODEL = "qwen3.5:4b"
REPORT_MODEL  = "qwen3.5:9b"
PHASE_REPORTS = False   # single-prompt mode for CPU-only hardware

MINIFLUX_URL       = "http://localhost:8080"
MINIFLUX_API_TOKEN = "your-api-token"
```

**OpenAI**
```python
PROVIDER           = "openai"
OPENAI_API_KEY     = "sk-..."      # or: export OPENAI_API_KEY=sk-...
SUMMARY_MODEL      = "gpt-4.1-mini"   # 200K TPM, 1M ctx — fits 120 articles in Stage 2
REPORT_MODEL       = "gpt-4.1"
ARTICLE_MAX_TOKENS = 2500
PARALLEL_WORKERS   = 8
PHASE_REPORTS      = True

PHASE_MODELS = {
    "vulnerability": "gpt-4.1",
    "threat_intel":  "gpt-4.1",
    "latam":         "gpt-4.1-mini",
    "general":       "gpt-4.1-mini",
    "synthesis":     "gpt-4.1",
}

MINIFLUX_URL       = "http://localhost:8080"
MINIFLUX_API_TOKEN = "your-api-token"
```

**Claude (Anthropic)**
```python
PROVIDER           = "claude"
ANTHROPIC_API_KEY  = "sk-ant-..."  # or: export ANTHROPIC_API_KEY=sk-ant-...
SUMMARY_MODEL      = "claude-haiku-4-5-20251001"
REPORT_MODEL       = "claude-sonnet-4-6"
ARTICLE_MAX_TOKENS = 2500
PARALLEL_WORKERS   = 8
PHASE_REPORTS      = True

PHASE_MODELS = {
    "vulnerability": "claude-sonnet-4-6",
    "threat_intel":  "claude-sonnet-4-6",
    "latam":         "claude-haiku-4-5-20251001",
    "general":       "claude-haiku-4-5-20251001",
    "synthesis":     "claude-sonnet-4-6",
}

MINIFLUX_URL       = "http://localhost:8080"
MINIFLUX_API_TOKEN = "your-api-token"
```

> **Tip:** API keys can be set as environment variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`). The config reads them via `os.getenv()` — no need to hardcode them in the file.

**Output format** — set in `config.py`:
```python
OUTPUT_FORMAT = "all"   # md + html + pdf  (requires weasyprint)
OUTPUT_FORMAT = "both"  # md + html only   (default)
```

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

This is the reference hardware setup using three dedicated LXC containers on Proxmox. Skip this section if you are using a cloud provider.

### Infrastructure

| Container | Role | Notes |
|-----------|------|-------|
| ollama | Ollama inference server | 10 GB RAM minimum for qwen3.5:9b (~7.2 GB peak) |
| miniflux | Miniflux RSS reader | port 8080 |
| pipeline | Debian — runs this codebase | talks to the other two over the local network |

### ollama container

Use the community-scripts one-liner from the Proxmox host shell:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/ct/ollama.sh)"
```

After creation, configure the systemd override so Ollama binds to all interfaces (not just localhost):

```bash
mkdir -p /etc/systemd/system/ollama.service.d/
cat > /etc/systemd/system/ollama.service.d/override.conf << 'EOF'
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
Environment="OLLAMA_KEEP_ALIVE=10m"
Environment="OLLAMA_MAX_LOADED_MODELS=1"
EOF

systemctl daemon-reload && systemctl restart ollama
```

Pull the models:
```bash
ollama pull qwen3.5:4b
ollama pull qwen3.5:9b
```

**Sequential model swap**: qwen3.5:4b (~3.2 GB, Stage 2) is explicitly unloaded via `keep_alive=0` before qwen3.5:9b (~7.2 GB, Stage 3) loads. Peak RAM usage: ~7.2 GB.

### miniflux container

Use the community-scripts one-liner from the Proxmox host shell:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/ct/miniflux.sh)"
```

After setup, open the Miniflux UI, go to **Settings → API Keys** and create a token for the pipeline. Then import the feed list: **Settings → OPML → Import** → select `threat-analysis-feeds.opml`.

### pipeline container

A standard Debian LXC. Install the pipeline:

```bash
apt install python3 python3-venv python3-pip git -y
# Optional: PDF export system libraries
apt install libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf2.0-0
# Optional: better PDF typography
apt install fonts-ibm-plex

git clone <repo-url> /opt/threat-pipeline
cd /opt/threat-pipeline
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
# Optional: PDF export
pip install weasyprint
```

Edit `config.py` with the IPs of the other two containers:
```python
PROVIDER           = "ollama"
OLLAMA_HOST        = "http://<ollama-container-ip>:11434"
MINIFLUX_URL       = "http://<miniflux-container-ip>:8080"
MINIFLUX_API_TOKEN = "your-api-token"   # from Miniflux Settings → API Keys
```

Verify:
```bash
python setup_check.py
```

---

## LLM providers

Change `PROVIDER` in `config.py` and set the matching model names — everything else stays the same.

### Ollama (default — fully local)

```bash
ollama pull qwen3.5:4b
ollama pull qwen3.5:9b
```

```python
PROVIDER           = "ollama"
OLLAMA_HOST        = "http://<host>:11434"
SUMMARY_MODEL      = "qwen3.5:4b"     # Stage 2 extraction (~3.2 GB RAM)
REPORT_MODEL       = "qwen3.5:9b"     # Stage 3 report   (~7.2 GB RAM)
ARTICLE_MAX_TOKENS = 800              # keep at 800 — fits 2K context window
PARALLEL_WORKERS   = 1               # CPU-only: serialize to avoid timeout
PHASE_REPORTS      = False            # single-prompt mode for CPU-only
```

Timing on i7-10510U (CPU-only): ~1.75 min/article → 120 articles ≈ 3.5h total.

**With GPU** — increase these:
```python
ARTICLE_MAX_TOKENS = 2000    # capture more content per article
PARALLEL_WORKERS   = 3       # GPU handles concurrent inference
PHASE_REPORTS      = True    # enable multi-phase for better quality
# PHASE_MODELS: leave all None → uses REPORT_MODEL for every phase
```

See the [GPU model recommendations table](#ollama-with-gpu) for model sizing by VRAM.

### Claude (Anthropic)

```bash
pip install anthropic
```

```python
PROVIDER           = "claude"
ANTHROPIC_API_KEY  = "sk-ant-..."   # or: export ANTHROPIC_API_KEY=sk-ant-...
SUMMARY_MODEL      = "claude-haiku-4-5-20251001"
REPORT_MODEL       = "claude-sonnet-4-6"
ARTICLE_MAX_TOKENS = 2500
REPORT_MAX_TOKENS  = 10000
PARALLEL_WORKERS   = 8
PHASE_REPORTS      = True

PHASE_MODELS = {
    "vulnerability": "claude-sonnet-4-6",
    "threat_intel":  "claude-sonnet-4-6",
    "latam":         "claude-haiku-4-5-20251001",   # cheaper — shorter output
    "general":       "claude-haiku-4-5-20251001",
    "synthesis":     "claude-opus-4-7",              # deeper cross-domain reasoning
}
```

### OpenAI

```bash
pip install openai
```

```python
PROVIDER           = "openai"
OPENAI_API_KEY     = "sk-..."        # or: export OPENAI_API_KEY=sk-...
SUMMARY_MODEL      = "gpt-4.1-mini"  # 200K TPM, 1M ctx — fits 120 articles in Stage 2
REPORT_MODEL       = "gpt-4.1"
ARTICLE_MAX_TOKENS = 2500
REPORT_MAX_TOKENS  = 10000
PARALLEL_WORKERS   = 8
PHASE_REPORTS      = True

PHASE_MODELS = {
    "vulnerability": "gpt-4.1",
    "threat_intel":  "gpt-4.1",
    "latam":         "gpt-4.1-mini",
    "general":       "gpt-4.1-mini",
    "synthesis":     "gpt-4.1",
}
```

> **Rate limits:** `gpt-4o` on Tier 1 has only 30K TPM — not enough for 120 articles in Stage 2. `gpt-4.1-mini` has 200K TPM and 1M context window, making it the better choice at any tier.

### Gemini (Google)

```bash
pip install google-generativeai
```

```python
PROVIDER           = "gemini"
GEMINI_API_KEY     = "AIza..."       # or: export GEMINI_API_KEY=AIza...
SUMMARY_MODEL      = "gemini-2.0-flash"
REPORT_MODEL       = "gemini-2.5-pro"
ARTICLE_MAX_TOKENS = 2500
REPORT_MAX_TOKENS  = 10000
PARALLEL_WORKERS   = 8
PHASE_REPORTS      = True

PHASE_MODELS = {
    "vulnerability": "gemini-2.5-pro",
    "threat_intel":  "gemini-2.5-pro",
    "latam":         "gemini-2.0-flash",
    "general":       "gemini-2.0-flash",
    "synthesis":     "gemini-2.5-pro",   # 1M context, best cross-domain synthesis
}
```

### Multi-phase reports (cloud providers)

Phases, category routing, and auto-scaling are described in the [Pipeline](#pipeline) section above. The table below covers model selection and token budgets.

#### Recommended models per phase

| Phase | OpenAI | Claude | Gemini | Notes |
|-------|--------|--------|--------|-------|
| Stage 2 — extraction | `gpt-4.1-mini` | `claude-haiku-4-5-20251001` | `gemini-2.0-flash` | High-volume JSON; fast and cheap |
| Vulnerability | `gpt-4.1` | `claude-sonnet-4-6` | `gemini-2.5-pro` | Technical precision for CVE analysis |
| Threat Intel | `gpt-4.1` | `claude-sonnet-4-6` | `gemini-2.5-pro` | Narrative synthesis, actor attribution |
| LATAM | `gpt-4.1-mini` | `claude-haiku-4-5-20251001` | `gemini-2.0-flash` | Regional context; lighter model sufficient |
| General | `gpt-4.1-mini` | `claude-haiku-4-5-20251001` | `gemini-2.0-flash` | News summary; shorter output |
| Stage 4 — synthesis | `gpt-4.1` | `claude-opus-4-7` | `gemini-2.5-pro` | Cross-domain reasoning benefits from the strongest model |

Set these in `PHASE_MODELS` inside `config.py` (comments in the file show the exact values to copy).

#### Recommended output token limits per phase

`PHASE_MAX_TOKENS` controls how long each phase output can be. Longer = more detail but higher cost.

| Phase | Ollama CPU | Ollama GPU | Cloud |
|-------|-----------|-----------|-------|
| `vulnerability` | 1500 | 2000 | 2500 |
| `threat_intel` | 1500 | 2000 | 2500 |
| `latam` | 800 | 1200 | 1500 |
| `general` | 600 | 800 | 1000 |
| `synthesis` | 800 | 1200 | 2000 |

The defaults in `config.py` are set for cloud. For Ollama CPU-only, lower all values by ~40% to reduce generation time.

#### Ollama with GPU

`PHASE_REPORTS = True` also works with Ollama on GPU. Keep all `PHASE_MODELS` as `None` (falls back to `REPORT_MODEL`) and raise `PARALLEL_WORKERS` to 2–4 depending on VRAM:

| VRAM | Recommended model | `PARALLEL_WORKERS` |
|------|------------------|--------------------|
| 12 GB | `qwen3:8b` | 2 |
| 24 GB | `qwen3:14b` or `qwen3:30b` Q4 | 3 |
| 48 GB (2× GPU) | `qwen3:32b` full | 4 |

### Provider comparison

| Provider | Stage 2 (120 articles) | Stage 3+4 (multi-phase) | Privacy | Approx. cost/run |
|----------|------------------------|-------------------------|---------|------------------|
| Ollama (CPU-only) | ~3.5h | ~30–40 min | Full — local | Free |
| Ollama (GPU 24 GB) | ~15 min | ~10–15 min | Full — local | Free |
| Claude | ~2 min | ~1–2 min | Sent to Anthropic | ~$0.30–0.50 |
| OpenAI | ~2 min | ~1–2 min | Sent to OpenAI | ~$0.25–0.50 |
| Gemini | ~2 min | ~1–2 min | Sent to Google | ~$0.10–0.30 |

Cloud providers use direct API calls (no streaming). Ollama uses streaming per phase to avoid timeouts on CPU-only hardware.

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
python pipeline.py --weekly                     # generate weekly digest from last 7 days of cache
python pipeline.py --weekly --weekly-days 5     # use last 5 days instead
```

### Flag reference

| Flag | What it does |
|------|-------------|
| `--limit N` | Cap the run at N articles. Useful for testing without waiting 3+ hours. |
| `--dry-run` | Runs Stage 1 (fetch + extract) but skips all LLM calls. Reports are filled with `[DRY RUN]` placeholders. Good for verifying feed connectivity. |
| `--report-only` | Skips Stages 1 and 2 entirely. Loads `summaries-cache-YYYY-MM-DD.json` and re-runs Stage 3. Also re-exports the IOC files for the day. Use this when tweaking the report prompt or if Stage 3 failed. |
| `--no-mark-read` | Processes articles normally but does not mark them as read in Miniflux. Useful for testing or re-processing. Note: articles are marked as read by default after Stage 2 so they are not re-processed in the next daily run. |
| `--categories` | Comma-separated list of OPML category names. Overrides `FEED_CATEGORIES` in `config.py` at runtime. |
| `--weekly` | Loads the last 7 days of `summaries-cache-*.json` files and generates a consolidated weekly digest. Does not fetch or call the per-article model — only Stage 3 runs. Also exports a weekly IOC file. |
| `--weekly-days N` | Override the number of days for `--weekly` (default: 7). |

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

## Cron (pipeline container)

For CPU-only hardware (~1.75 min/article in Stage 2), rotating categories keeps each run within ~3.5h:

```cron
0 2 * * 1,3,5  root cd /opt/threat-pipeline && source venv/bin/activate && python pipeline.py --categories "Vulnerability" >> /var/log/threat-pipeline.log 2>&1
0 2 * * 2,4    root cd /opt/threat-pipeline && source venv/bin/activate && python pipeline.py --categories "Threat Intel" >> /var/log/threat-pipeline.log 2>&1
0 3 * * 6      root cd /opt/threat-pipeline && source venv/bin/activate && python pipeline.py --categories "Cibersecurity" >> /var/log/threat-pipeline.log 2>&1
0 3 * * 0      root cd /opt/threat-pipeline && source venv/bin/activate && python pipeline.py --categories "Hacking & Research,LATAM" >> /var/log/threat-pipeline.log 2>&1
# Weekly digest every Sunday at 08:00 (after the daily cron has run)
0 8 * * 0      root cd /opt/threat-pipeline && source venv/bin/activate && python pipeline.py --weekly >> /var/log/threat-pipeline.log 2>&1
```

**Cloud providers** — Stage 2+3+4 takes ~5 min total, all categories in one run:

```cron
# Daily report at 07:00 — covers all 39 feeds in a single run
0 7 * * *  root cd /opt/threat-pipeline && source venv/bin/activate && python pipeline.py >> /var/log/threat-pipeline.log 2>&1
# Weekly digest every Monday at 08:00
0 8 * * 1  root cd /opt/threat-pipeline && source venv/bin/activate && python pipeline.py --weekly >> /var/log/threat-pipeline.log 2>&1
```

---

## Output folder structure

Every run creates a dated subfolder under `OUTPUT_DIR`:

```
OUTPUT_DIR/                                  (default: ./reports/)
├── history.json                             long-term trending (~200 bytes/day)
├── pipeline.log                             run logs (appended each run)
│
└── YYYY-MM-DD/                              one folder per daily run
    ├── threat-briefing-YYYY-MM-DD.pdf       final deliverable — all sections
    ├── summaries-cache-YYYY-MM-DD.json      article cache (used by --report-only, --weekly)
    ├── reports/
    │   ├── threat-briefing-YYYY-MM-DD.md
    │   └── threat-briefing-YYYY-MM-DD.html
    └── iocs/
        ├── iocs-YYYY-MM-DD.csv
        └── iocs-YYYY-MM-DD.json

└── YYYY-WXX/                                one folder per weekly run (--weekly)
    ├── weekly-briefing-YYYY-WXX.pdf
    ├── reports/
    │   ├── weekly-briefing-YYYY-WXX.md
    │   └── weekly-briefing-YYYY-WXX.html
    └── iocs/
        ├── iocs-YYYY-WXX.csv
        └── iocs-YYYY-WXX.json
```

**Legacy mode** (`PHASE_REPORTS = False`) — split files are placed in `reports/` alongside the combined report:
```
YYYY-MM-DD/reports/
├── vuln-briefing-YYYY-MM-DD.{md,html}
├── threat-digest-YYYY-MM-DD.{md,html}
└── threat-briefing-YYYY-MM-DD.{md,html}    combined fallback
```

`history.json` and `pipeline.log` stay at `OUTPUT_DIR` root — they accumulate across runs and are never moved into dated subfolders. The `summaries-cache-*.json` files are detected automatically by `--report-only` and `--weekly` — a fallback also finds caches from older flat-structure runs if present.

---

## Configuration reference

All settings live in `config.py`.

### LLM

| Variable | Default | Notes |
|----------|---------|-------|
| `PROVIDER` | `"ollama"` | `ollama` \| `claude` \| `openai` \| `gemini` |
| `SUMMARY_MODEL` | `"qwen3.5:4b"` | Model for Stage 2 — set to match your provider |
| `REPORT_MODEL` | `"qwen3.5:9b"` | Default model for Stage 3/4 phases (overridden per-phase by `PHASE_MODELS`) |
| `PHASE_REPORTS` | `True` | Multi-phase mode. Set `False` for legacy single-prompt (Ollama CPU-only) |
| `PHASE_CATEGORY_MAP` | see config | Maps phase names → Miniflux category names. Unmapped categories → `general` |
| `PHASE_MODELS` | all `None` | Per-phase model override. `None` falls back to `REPORT_MODEL`. See config comments for OpenAI/Claude values. |
| `PHASE_MAX_TOKENS` | see config | Output token limit per phase. See [recommended values by provider](#recommended-output-token-limits-per-phase). |
| `PHASE_ARTICLE_LIMITS` | see config | Max articles sent to each phase prompt (top N by severity) |
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
| `ARTICLE_MAX_TOKENS` | `800` | Content per article sent to Stage 2. Ollama: keep at 800 (2K context). Cloud: set to 2000–3000 to capture full IOC lists and TTP details. |
| `MIN_CONTENT_LENGTH` | `200` | Discard articles with fewer than N characters of extractable content |
| `PARALLEL_WORKERS` | `1` | Ollama CPU-only: keep at 1. Ollama GPU: 2–4. Cloud APIs: 8–12. |

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

IOC files (`iocs-YYYY-MM-DD.csv` and `.json`) are always written regardless of `OUTPUT_FORMAT`. The CSV has columns: `date, ioc, type, severity, title, feed, cves`. The JSON groups IOCs by type (`ip`, `domain`, `sha256`, `sha1`, `md5`, `url`, `other`).

#### PDF export

Set `OUTPUT_FORMAT = "all"` and install the system libraries on the server:

```bash
apt install fonts-ibm-plex   # optional — improves PDF typography (IBM Plex Sans/Mono)
apt install libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf2.0-0
pip install weasyprint
```

The PDF template uses a violet palette (`#7c3aed`) with `TLP:WHITE` labeling in the footer of every page. Without `fonts-ibm-plex` it falls back to Liberation Sans / DejaVu Sans (already installed as weasyprint dependencies).

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
