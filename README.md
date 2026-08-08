# Separatio

> *"Separa terram ab igne, subtile a spisso, suaviter cum magno ingenio."*
> *— Tabula Smaragdina*

Personal threat-intelligence station, packaged as a monorepo with two Python packages
that share one install, one `.env` and one test suite:

| Package | What it is | Docs |
|---|---|---|
| [`separatio/`](separatio/) | The pipeline: reads curated cybersecurity RSS feeds from Miniflux, summarizes and correlates them with an LLM (Claude by default; OpenAI/Gemini/Ollama supported), enriches the day's IOCs against reputation sources, and produces a structured daily threat briefing (Markdown/HTML/PDF + IOC export) | [README](separatio/README.md) |
| [`ipcheck/`](ipcheck/) | Standalone SOC tool and reusable library for tiered IP reputation lookups (AbuseIPDB, VirusTotal, GreyNoise, OTX, URLhaus, ThreatFox, Shodan, ip-api). Also consumed by the pipeline's `ip_reputation` enricher | [README](ipcheck/README.md) |

## Quickstart

```bash
git clone https://github.com/Fennek115/separatio intel
cd intel
python3 -m venv venv
venv/bin/pip install -e '.[dev]'
cp .env.example .env        # fill in your API keys (the file is gitignored)
```

That exposes four console commands inside the venv:

```bash
venv/bin/separatio            # run the daily pipeline (~10 min with a cloud LLM)
venv/bin/separatio --dry-run  # fetch/extract only — no LLM calls, isolated output
venv/bin/separatio-check      # environment diagnostics
venv/bin/ipcheck ips.txt      # standalone IP reputation checker
venv/bin/ipcheck-run x.csv    # Wazuh-export → IP triage orchestrator
```

Tests (deterministic, no network):

```bash
venv/bin/pytest tests/ -q
```

## Repository layout

```
├── pyproject.toml     # both packages, deps and entry points
├── .env.example       # every variable documented; real .env is gitignored
├── separatio/         # the pipeline (stages 1→4 + enrichers)
├── ipcheck/           # IP reputation library + CLI
├── tests/             # test suite for both packages
├── feeds/feeds.opml   # curated feed list (mirror of the Miniflux instance)
└── docs/              # design and planning documents
```

## History

`separatio` and `ipcheck` started as separate repositories; they were merged here
in August 2026 (Separatio's history continues directly, ipcheck's was preserved via
`git subtree`). This is a personal homelab project — issues and PRs are welcome but
it is built first and foremost for its author's daily use.
