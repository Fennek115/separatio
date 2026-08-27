# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project does

Automated pipeline that reads cybersecurity RSS feeds from Miniflux, summarizes each article with a cloud LLM provider (Claude — also supports OpenAI, Gemini, or legacy local Ollama), and generates a daily Threat Intelligence report in Markdown, HTML, and/or PDF.

## Estado actual (2026-08-08) — leer antes de tocar nada

Este paquete es la pieza central de la fase **F0** del proyecto documentado en
`~/Projects/Motherbase/` (leer `ESTADO.md` y `fases/F0-separatio.md` de allá para el plan completo).
Desde el 2026-08-08 vive como paquete `separatio` dentro del **monorepo** `~/Projects/Intel/`
(ver el `CLAUDE.md` de la raíz y `../docs/PLAN-REORDEN.md`).
Regla de ese proyecto que aplica acá: **verificar contra la máquina, no contra el documento.**

Hecho:
- Trabajo de junio (Stage 2.7, `net.py`, tests) commiteado y en `origin/main`.
- `PROVIDER = "claude"` con modelos vigentes (`claude-sonnet-5`, `claude-opus-5`, `claude-haiku-4-5-20251001`). Ollama quedó como legacy: **el CT 111 ya no existe**.
- Los 3 enrichers encendidos; `ipcheck` se importa como paquete del monorepo (**VirusTotal
  activo** desde el `.env` único, 2026-08-08).
- Secretos en el `.env` de la raíz del monorepo; lo cargan los entry points (`pipeline.py`
  y `setup_check.py`) con `load_dotenv()` antes de importar `config`.
- Miniflux (CT 112, `192.168.1.7:8080`): auth por API token (`MINIFLUX_API_TOKEN` en el `.env`). **Los feeds viven bajo el usuario `threat_intel` (id 12), NO bajo `admin`** — el token del `.env` es el de ese usuario (corregido 2026-08-08; con el token de `admin` el pipeline veía 0 feeds). Categorías alineadas con `PHASE_CATEGORY_MAP`: `Cibersecurity` (58), `Hacking & Research` (59), `Threat Intel` (60), `Vulnerability` (61), `LATAM` (62). 40 feeds, 0 errores (verificado por API 2026-08-08); `../feeds/feeds.opml` es el espejo curado (40 entradas).
- Venv en la **raíz del monorepo** (`../venv/`, `pip install -e '.[dev]'`). Los tests viven
  en `../tests/` (24 de ambos paquetes, todos pasan).

Pendiente (en orden):
1. ~~`ANTHROPIC_API_KEY`~~ **En el `.env` desde 2026-08-08** — ojo: es una key temporal de
   prueba que caduca en días; el usuario la va a reemplazar por la definitiva.
2. ~~LATAM sin feeds~~ **Resuelto 2026-08-08**: LATAM (id 62) tiene 6 feeds (CyberSecurity News ES, DragonJAR, El Lado del Mal, Segu-Info, Una Al Día, WeLiveSecurity la-es).
3. ~~`VIRUSTOTAL_API_KEY`~~ **Rescatada 2026-08-08** al `.env` único (fase 4 de
   `../docs/PLAN-REORDEN.md`) — VT activo en el enricher `ip_reputation`. GreyNoise: sin clave
   (no acepta correos Proton).
4. ~~Paso 6 de F0~~ **Completado 2026-08-08**: `setup_check` ✓ → `--dry-run` ✓ (120 arts,
   ruteo OK) → `--limit 5` ✓ → corrida completa ✓ (116 resúmenes, 0 fallos, ~8 min).
   Tres fixes salieron de esa prueba (commiteados y pusheados en `25a000a`):
   - `analyzer.py`: se quitó `temperature` de la rama claude (Sonnet 5/Opus 5 lo rechazan con 400).
   - `analyzer.py`: la respuesta puede empezar con bloques `thinking` (activo por defecto
     en Sonnet 5/Opus 5) — se filtran solo los bloques de texto en vez de `content[0]`.
   - `config.py`: `PHASE_MAX_TOKENS` subidos (16000/12000/8000/3000/4000) — max_tokens ahora
     tapa thinking+texto y los valores viejos truncaban todas las fases al 100%.
   Bugs menores vistos entonces, arreglados 2026-08-09 (F-G G-7 del rework, ver
   `../docs/fases/F-G.md`): enricher OpenPhish fallaba con "Invalid IPv6 URL" ante un `[`
   suelto en el netloc de una URL malformada del feed o de un IOC extraído — perdía la
   fuente entera esa corrida, no sólo la línea puntual (`_safe_netloc()` en
   `enrichers/openphish.py`); warnings "discarding data: None" de trafilatura en Stage 1
   (cosmético — su logger propio bajado a ERROR en `extractor.py`).
5. **Dónde corre y automatización: decisión diferida.** El reorden previo (monorepo +
   packaging) se completó el 2026-08-08; falta solo decidir ubicación (LXC nuevo en
   `motherbase` es lo natural) y timer. No crear CTs ni crons sin esa decisión.
6. Criterio de cierre de F0: dos semanas de informes diarios sin intervención.

## Commands

Desde la raíz del monorepo (`~/Projects/Intel/`), con los entry points del venv:

```bash
venv/bin/separatio                    # full run
venv/bin/separatio --dry-run          # fetch only, no LLM — AISLADO en reports/dryrun/,
                                      #   no marca leídos en Miniflux (fix 2026-08-08)
venv/bin/separatio --limit 20         # cap at 20 articles
venv/bin/separatio --report-only      # re-generate report from today's cache JSON
venv/bin/separatio --no-mark-read     # skip marking articles as read in Miniflux
venv/bin/separatio --last-run         # resumen de la última corrida (F-H; --json = manifiesto)
venv/bin/separatio-check              # environment diagnostics (carga el .env)
```

Install deps: `venv/bin/pip install -e '.[dev]'` en la raíz (deps en `pyproject.toml`).

## Infrastructure (Proxmox host `motherbase`, 192.168.1.200)

- **LXC 112 — miniflux**: Miniflux 2.3.1 on `192.168.1.7:8080`. Pipeline auths with `MINIFLUX_API_TOKEN` (in `~/Projects/Intel/.env`); feeds live under the `threat_intel` user (id 12), not `admin`.
- **LXC 111 — ollama: no longer exists.** Removed after the local-LLM path was discarded (~3.5 h/run on CPU). Any doc mentioning it describes the past.

## Models

Current (cloud, `PROVIDER = "claude"`):

| Stage | Model |
|-------|-------|
| Stage 2: per-article JSON extraction | `claude-haiku-4-5-20251001` |
| Phases vulnerability / threat_intel | `claude-sonnet-5` |
| Phases latam / general | `claude-haiku-4-5-20251001` |
| Stage 4 synthesis | `claude-opus-5` |

**Multi-provider**: `PROVIDER` in `config.py` selects `"ollama"` | `"claude"` | `"openai"` | `"gemini"`. API keys read from env vars `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY` (loaded from `~/Projects/Intel/.env` by `pipeline.py`). **Since F-G/G-5 (2026-08-09, see `../docs/fases/F-G.md`):** the dispatch lives in `separatio/providers/` (`LLMProvider` ABC + one subclass per provider + `get_provider()` factory), not as `if provider == ...` inside `analyzer._llm_chat` anymore — `analyzer.py` just asks the factory and logs usage.

Legacy Ollama notes (only relevant if `PROVIDER = "ollama"` returns): sequential swap via `unload_model()` (`keep_alive=0` after Stage 2); `PARALLEL_WORKERS` must drop back to 1 because CPU-only Ollama serializes requests and the second worker's httpx timeout fires while queued.

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
  - AnciEnricher     — alertas del CSIRT Nacional de Chile (API pública, sin key):
                       notas de la ventana + cruce de IOCs + **cruce de CVEs** con
                       CVSS/EPSS ya calculados. Cliente en `anci_client.py`
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
  reports/YYYY-MM-DD/run-manifest.json   ← F-H: qué corrió, qué falló, qué se recortó
  pipeline.log written to OUTPUT_DIR (rotating: 5 MB × 5 backups)
```

## Non-obvious implementation details

**`runlog.py` es el manifiesto de la corrida (F-H, 2026-08-09)**: singleton de módulo con no-op,
como el `logger` — si nadie llamó a `start_run` (tests, import suelto), cada `record_*` no hace nada
y no falla, así que instrumentar nunca puede romper el pipeline. `main()` está partido en
`main()`/`_run()` para que `finish_run` corra en un `finally` pase lo que pase. Reglas de estado:
`ok` / `degraded` (fuente caída u **omitida**, etapa no crítica fallida, salida truncada → exit 0) /
`failed` (una etapa de `CRITICAL_STAGES` falló o no se generó informe → exit 1). Un enricher que se
salta por falta de key se marca `skipped: <motivo>` y **`run_enrichment` no puede pisarlo con `ok`**:
no lanzar no es lo mismo que haber consultado la fuente. Para agregar un recorte nuevo, una línea:
`runlog.record_drop("donde", shown, total, detail=...)` — si `total <= shown` no registra nada.

**El enricher de ANCI cruza CVEs, no sólo IOCs** (2026-08-19): `Enricher.enrich` sólo recibe el mapa
de IOCs del día, así que para poder decir "el CSIRT nacional emitió alerta por 7 de las CVEs de las
que hablan hoy los feeds" se agregó `EnrichmentContext.cves` — lo puebla `run_enrichment` desde los
resúmenes de Stage 2 y es aditivo: no cambia la firma del ABC ni ningún enricher previo. El cliente
(`anci_client.py`) es un módulo hoja que **no importa `config`**, con caché en disco y sus seis
trampas medidas en el docstring (el listado no viene en orden de publicación, hay rate limit de
Cloudflare, las IPs son del alojamiento y 40 % son del CDN…). Ver `../docs/CAPAS-Y-FUENTES.md`.

**El informe semanal ahora sí corre Stage 2.7** (2026-08-19): `run_weekly` cargaba las cachés de
Stage 2 y se iba derecho a `generate_weekly_report`, así que el informe del lunes era el único sin
enrichment externo. Ahora llama a `stage27_enrich` con `cfg.derive(ANCI_LOOKBACK_HOURS=...)` para
estirar la ventana a la semana, y `build_weekly_prompt` anexa el bloque igual que las fases diarias.

**Enrichment (Stage 2.7) injects via `CorrelationContext.extra_blocks`**: rather than threading a new param through `generate_report`/`generate_phase_report`, `stage27_enrich` appends the enrichment prompt block to `correlation.extra_blocks`, which `format_for_prompt()` renders at the end. This keeps `analyzer.py` signatures untouched. Enrichment only reaches phases that already receive `correlation` (vulnerability, threat_intel).

**`ip_reputation` enricher imports ipcheck as a package** (since 2026-08-08): `enrichers/ip_reputation.py` does `from ipcheck import ip_enricher` (lazy, inside `_load_lib`) — `IPCHECK_DIR` and the `sys.path.insert` hack are gone. It paces VirusTotal (sleeps `ENRICH_VT_SLEEP`s only after an IP reaches Level 3) and caps calls at `ENRICH_MAX_IPS`.

**Paths are anchored to `PROJECT_ROOT`** (`config.py`): `OUTPUT_DIR`/`HISTORY_FILE` are absolute (`Path(__file__).parent`). Running from any cwd (cron) yields the same locations — previously relative paths scattered reports and silently reset trending history.

**`history.json` is written atomically** (`history.save_history`): temp file + `fsync` + `os.replace`. Safe against crashes/concurrent runs.

**Network calls retry with backoff** (`net.request_with_retry`): used by `MinifluxClient` and the KEV/EPSS fetches. Retries on `ConnectionError`/`Timeout`/429/5xx only; no new dependency (not `tenacity`).

**Stage 2 fail-fast**: `stage2_summarize` aborts if ≥`STAGE2_FAIL_FAST_THRESHOLD` (0.5) of articles fail to summarize — avoids burning hours on Stage 3 to emit an empty report when the LLM provider is down.

**Tests**: `venv/bin/pytest tests/ -q` desde la raíz del monorepo — **386**, deterministas y sin red (HTTP monkeypatched). El roadmap de refactors grandes de `../docs/IMPROVEMENTS.md` §6 está **completo**: los cinco (provider abstraction §6.1, reporter con plantillas §6.2, pipeline split §6.3, configuración inyectable §6.4 e IOC export §6.5) se hicieron el 2026-08-09 en F-G.

**La configuración es un objeto, no un módulo global** (F-G/G-2, 2026-08-09): la fuente de verdad es el dataclass congelado `settings.py:Settings` — ahí se editan los valores fijos. `config.py` quedó como fachada de 40 líneas (`SETTINGS = Settings.from_env()` y sus campos como constantes de módulo), así que `config.MAX_ARTICLES` y el `monkeypatch.setattr(config, ...)` de los tests siguen funcionando. **Para código nuevo: recibí un `Settings` por parámetro** (`settings=None` con fallback a `config.SETTINGS`, como hacen las etapas de `pipeline.py`, `build_classifier`, `open_store`, `build_enrichers`, `LocalLists.from_config`). Dos cosas que no se pueden romper sin querer: los campos van en **MAYÚSCULAS** porque `hygiene` y `setup_check` leen por nombre dinámico, y el aislamiento del `--dry-run` ahora sale de `pipeline.settings_for(args)` — antes se mutaba `config.OUTPUT_DIR` en caliente.

**El informe se renderiza con plantillas, no con strings** (F-G/G-6, 2026-08-09): `reporter.py` toma el Markdown del LLM, lo pasa por Python-Markdown (`tables`, `fenced_code`, `toc`, más una extensión propia con dos concesiones al Markdown real del modelo) y lo mete en `separatio/templates/{pdf,web}.html.j2`. Dos cosas no obvias si tocás esto: (1) el índice del PDF numera páginas con `target-counter(attr(href), page)`, así que los `href` del TOC y los `id` de los encabezados **tienen que salir del mismo parseo** —por eso el TOC se construye desde `md.toc_tokens` con el `_slugify` propio inyectado— y si se desincronizan el índice sale sin números **sin fallar el render**; (2) el LLM escribe la tabla pegada al párrafo anterior, y Python-Markdown a secas se la traga dentro del `<p>` — lo arregla `_TableBlankLinePreprocessor`, registrado con prioridad 20 para correr después de `fenced_code` y no tocar los bloques de código.

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

Already set (2026-08-08): `PROVIDER = "claude"`, `MINIFLUX_URL = "http://192.168.1.7:8080"`,
`MINIFLUX_API_TOKEN` y `ANTHROPIC_API_KEY` (⚠️ temporal) from the root `.env`.

Key tunable values:

| Variable | Default | Notes |
|----------|---------|-------|
| `MAX_ARTICLES` | 120 | Hard cap per run |
| `PER_FEED_LIMIT` | 10 | Max articles per feed (prevents monopolization) |
| `PARALLEL_WORKERS` | 8 | Cloud providers; drop to 1 for CPU-only Ollama |
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
| `LOG_MAX_BYTES` / `LOG_BACKUP_COUNT` | 5 MB / 5 | Rotación de `pipeline.log` (F-H) |
| `LOG_LEVEL` | `INFO` | Nivel del root logger; los tokens por llamada salen en INFO desde F-H |
| `ENRICH_PROMPT_MAX_PER_SOURCE` | 25 | Veredictos por fuente que entran al prompt; el resto se registra como recorte |
| `ENRICHMENT_ENABLED` | True | Master switch for Stage 2.7 |
| `ENRICHERS` | all three on | Per-enricher toggles (VT active since 2026-08-08: key in the root `.env`) |
| `ANCI_*` | ver `settings.py` | CSIRT Chile: ventana (26 h; 7 días en `--weekly`), corpus de cruce (90 d), topes de prompt, categorías de documentos, TTL de caché y throttle (2 s **entre peticiones**) |
| `IPSUM_MIN_SCORE` | 3 | Min public blocklists reporting an IP to flag it |
| `ENRICH_MAX_IPS` / `ENRICH_VT_SLEEP` | 25 / 15 | API-IP cap / VT pacing (Level-3 IPs) |

## Scheduling — not decided yet

There is **no cron/timer anywhere** today, on purpose. The monorepo/packaging prerequisite
was completed 2026-08-08; the remaining decision is where it runs (a new LXC on `motherbase`
is the natural choice — see `../docs/PLAN-REORDEN.md` §4 for the EnvironmentFile scheme).
Do not create CTs or crons before that decision. With a cloud provider a full run is
~8–15 min (VT pacing included), so scheduling is cheap once decided.
