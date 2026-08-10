"""
pipeline.py — Orquestador principal del pipeline de análisis de amenazas.

Uso:
    python pipeline.py                  # Ejecutar pipeline completo
    python pipeline.py --dry-run        # Sin llamadas a Ollama (prueba de fetch)
    python pipeline.py --limit 20       # Procesar solo 20 artículos
    python pipeline.py --report-only    # Regenerar informe desde caché JSON
"""

import argparse
import json
import logging
import logging.handlers
import os
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path

from dotenv import load_dotenv

# El .env vive en la raíz del monorepo (un nivel arriba del paquete). Se carga acá,
# en el entrypoint y antes de importar config —no en config.py— para que
# os.getenv() ya vea las claves sin efectos en tiempo de import.
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from separatio import config, runlog
from separatio.settings import Settings
from separatio.miniflux_client import MinifluxClient
from separatio.extractor import extract_article_text, truncate_text
from separatio.analyzer import (ArticleSummary, summarize_article, generate_report,
                      generate_weekly_report, generate_phase_report,
                      generate_synthesis_report, unload_model)
from separatio.correlator import build_correlation_context, CorrelationContext
from separatio.history import load_history, append_daily_record, save_history, build_trending_context, TrendingContext
from separatio.reporter import save_report
# F-G/G-3: lo que antes vivía acá adentro. Se reexporta con el import para que
# `pipeline.dedup_by_cves` / `pipeline.export_iocs` / `pipeline.group_by_phase`
# sigan resolviendo igual que antes.
from separatio.deduplicator import dedup_by_cves
from separatio.ioc_processor import detect_ioc_type, export_iocs
from separatio.router import (CANONICAL_PHASES, CORRELATED_PHASES, group_by_phase,
                              phase_order as _phase_order, receives_correlation,
                              receives_trending)

Path(config.OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=getattr(logging, getattr(config, "LOG_LEVEL", "INFO"), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        # Rotación (F-H): en modo append el log crecía para siempre — 188 KB y
        # subiendo, con todas las corridas mezcladas. 5 MB × 5 backups acota el
        # disco del CT sin dependencias (stdlib).
        logging.handlers.RotatingFileHandler(
            os.path.join(config.OUTPUT_DIR, "pipeline.log"),
            maxBytes=getattr(config, "LOG_MAX_BYTES", 5_242_880),
            backupCount=getattr(config, "LOG_BACKUP_COUNT", 5),
            encoding="utf-8",
        ),
    ],
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# CACHÉ JSON
# ─────────────────────────────────────────────

#: Cómo se resuelve la config cuando no viene inyectada (F-G/G-2).
#: Todas las funciones de este módulo aceptan `settings=None` y caen acá, así el
#: pipeline real pasa siempre el suyo —el de `--dry-run` es otro— y un test puede
#: pasar el que quiera sin tocar el módulo `config`.
def _cfg(settings: Settings | None) -> Settings:
    return settings if settings is not None else config.SETTINGS


def _dated_dir(date_str: str, settings: Settings | None = None) -> str:
    """Carpeta diaria/semanal: OUTPUT_DIR/YYYY-MM-DD/ o OUTPUT_DIR/YYYY-WXX/"""
    safe = date_str.replace(" ", "_").replace("/", "-")
    path = os.path.join(_cfg(settings).OUTPUT_DIR, safe)
    Path(path).mkdir(parents=True, exist_ok=True)
    return path


def _cache_path(date_str: str, settings: Settings | None = None) -> str:
    safe = date_str.replace(" ", "_").replace("/", "-")
    return os.path.join(_dated_dir(date_str, settings), f"summaries-cache-{safe}.json")


def save_summaries_cache(summaries: list[ArticleSummary], date_str: str,
                         settings: Settings | None = None) -> str:
    path = _cache_path(date_str, settings)
    with open(path, "w", encoding="utf-8") as f:
        json.dump([s.__dict__ for s in summaries], f, ensure_ascii=False, indent=2)
    logger.info(f"Caché guardada: {path}")
    return path


def load_summaries_cache(date_str: str,
                         settings: Settings | None = None) -> list[ArticleSummary]:
    path = _cache_path(date_str, settings)
    if not os.path.exists(path):
        # Fallback: estructura plana antigua (OUTPUT_DIR/summaries-cache-DATE.json)
        safe = date_str.replace(" ", "_").replace("/", "-")
        old_path = os.path.join(_cfg(settings).OUTPUT_DIR, f"summaries-cache-{safe}.json")
        if os.path.exists(old_path):
            logger.info(f"Usando caché legacy: {old_path}")
            path = old_path
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    known = ArticleSummary.__dataclass_fields__
    summaries = [ArticleSummary(**{k: v for k, v in d.items() if k in known}) for d in data]
    logger.info(f"Cargados {len(summaries)} resúmenes del caché")
    return summaries


# ─────────────────────────────────────────────
# RESUMEN SEMANAL
# ─────────────────────────────────────────────

def run_weekly(days: int = 7, settings: Settings | None = None) -> None:
    """Carga los últimos N días de caché y genera un briefing semanal."""
    cfg      = _cfg(settings)
    today    = datetime.now().date()
    iso      = datetime.now().isocalendar()
    week_label = f"{iso.year}-W{iso.week:02d}"
    date_str   = datetime.now().strftime("%Y-%m-%d")

    logger.info(f"\n{'═' * 50}")
    logger.info(f"  WEEKLY PIPELINE — {week_label}")
    logger.info(f"{'═' * 50}\n")

    all_summaries: list[ArticleSummary] = []
    dates_found:   list[str]            = []

    for i in range(days):
        day     = today - timedelta(days=i)
        day_str = day.strftime("%Y-%m-%d")
        cache   = _cache_path(day_str, cfg)
        if os.path.exists(cache):
            day_summaries = load_summaries_cache(day_str, cfg)
            all_summaries.extend(day_summaries)
            dates_found.append(day_str)

    if not all_summaries:
        logger.error("No se encontraron cachés en los últimos %d días.", days)
        runlog.expect_no_report(f"sin cachés diarias en los últimos {days} días")
        return

    dates_found.sort()
    logger.info(
        f"  {len(all_summaries)} resumenes de {len(dates_found)} días: "
        f"{dates_found[0]} → {dates_found[-1]}"
    )

    markdown = generate_weekly_report(
        summaries=all_summaries,
        dates=dates_found,
        week_label=week_label,
        model=cfg.REPORT_MODEL,
        ollama_host=cfg.OLLAMA_HOST,
        language=cfg.REPORT_LANGUAGE,
        timeout=cfg.REPORT_TIMEOUT,
        thinking=cfg.REPORT_THINKING,
        num_ctx=cfg.REPORT_CTX,
        num_threads=cfg.OLLAMA_NUM_THREADS,
        max_tokens=cfg.REPORT_MAX_TOKENS,
        provider=cfg.PROVIDER,
    )

    total_feeds = len(set(s.feed_title for s in all_summaries))
    weekly_dir = _dated_dir(week_label, cfg)
    paths = save_report(
        markdown_content=markdown,
        output_dir=weekly_dir,
        date_str=week_label,
        total_articles=len(all_summaries),
        total_feeds=total_feeds,
        fmt=cfg.OUTPUT_FORMAT,
        split=False,
        provider=cfg.PROVIDER,
        filename_prefix="weekly-briefing",
    )

    ioc_paths = export_iocs(all_summaries, week_label, weekly_dir)
    paths.update(ioc_paths)
    _print_result(paths)


# ─────────────────────────────────────────────
# ETAPA 1: FETCH
# ─────────────────────────────────────────────

def stage1_fetch(client: MinifluxClient, limit: int,
                 settings: Settings | None = None) -> list[dict]:
    cfg = _cfg(settings)
    logger.info("═" * 50)
    logger.info("ETAPA 1: Obteniendo artículos de Miniflux")
    logger.info("═" * 50)

    # Fetch a wider pool when per-feed capping is active so high-volume feeds
    # (MSRC: 2975 entries, Black Hills: 909) don't monopolize the global limit.
    per_feed = cfg.PER_FEED_LIMIT
    fetch_limit = min(limit * 5, 1000) if per_feed else limit
    articles = client.get_unread_articles(limit=fetch_limit)
    if not articles:
        logger.warning("No hay artículos no leídos.")
        return []

    if cfg.FEED_CATEGORIES:
        before   = len(articles)
        articles = [a for a in articles if a.feed_category in cfg.FEED_CATEGORIES]
        logger.info(f"Filtro por categorías: {before} → {len(articles)} artículos")

    # "pool" y no "disponibles": con PER_FEED_LIMIT se piden limit*5 entradas a
    # Miniflux, así que esto es el lote consultado, no el total de no leídos.
    runlog.record_count("articulos_pool", len(articles))

    if per_feed:
        counts: dict[str, int] = defaultdict(int)
        capped = []
        for a in articles:   # already sorted by published_at desc from Miniflux
            if counts[a.feed_title] < per_feed:
                capped.append(a)
                counts[a.feed_title] += 1
        logger.info(
            f"Límite por feed ({per_feed}): pool={len(articles)} → {len(capped)} artículos"
        )
        runlog.record_drop("pipeline.stage1_fetch.per_feed",
                           shown=len(capped), total=len(articles))
        runlog.record_drop("pipeline.stage1_fetch.global",
                           shown=min(limit, len(capped)), total=len(capped))
        articles = capped[:limit]

    # Deduplicar por URL — la misma noticia puede aparecer en varios feeds.
    # Mantenemos la primera ocurrencia (ya viene ordenado por published_at desc).
    seen_urls: set[str] = set()
    deduped = []
    for a in articles:
        if a.url not in seen_urls:
            seen_urls.add(a.url)
            deduped.append(a)
    if len(deduped) < len(articles):
        logger.info(f"Deduplicación por URL: {len(articles)} → {len(deduped)} artículos")
    articles = deduped

    logger.info(f"Procesando {len(articles)} artículos...")
    processed = []

    for i, article in enumerate(articles, 1):
        logger.info(f"[{i}/{len(articles)}] Extrayendo: {article.title[:70]}")
        text = extract_article_text(
            article,
            timeout=cfg.HTTP_TIMEOUT,
            min_length=cfg.MIN_CONTENT_LENGTH,
            blocked_domains=cfg.NO_SCRAPE_DOMAINS,
            hard_timeout=cfg.FETCH_HARD_TIMEOUT,
        )
        text = truncate_text(text, max_tokens_approx=cfg.ARTICLE_MAX_TOKENS)
        processed.append({
            "article_id":    article.id,
            "title":         article.title,
            "url":           article.url,
            "feed_title":    article.feed_title,
            "feed_category": article.feed_category,
            "published_at":  article.published_at,
            "content":       text,
        })

    logger.info(f"Etapa 1 completada: {len(processed)} artículos extraídos")
    runlog.record_count("articulos_tomados", len(processed))
    return processed


# ─────────────────────────────────────────────
# ETAPA 2: RESÚMENES
# ─────────────────────────────────────────────

def _summarize_one(item: dict, dry_run: bool,
                   settings: Settings | None = None) -> ArticleSummary:
    cfg = _cfg(settings)
    if dry_run:
        s = ArticleSummary(
            article_id=item["article_id"], title=item["title"],
            url=item["url"], feed_title=item["feed_title"],
            feed_category=item["feed_category"], published_at=item["published_at"],
        )
        s.threat_type    = "Test"
        s.severity       = "Informativa"
        s.severity_score = 1
        s.summary        = f"[DRY RUN] {item['title']}"
        return s

    return summarize_article(
        article_id=item["article_id"],
        title=item["title"],
        content=item["content"],
        feed_title=item["feed_title"],
        feed_category=item["feed_category"],
        url=item["url"],
        published_at=item["published_at"],
        model=cfg.SUMMARY_MODEL,
        ollama_host=cfg.OLLAMA_HOST,
        timeout=cfg.SUMMARY_TIMEOUT,
        thinking=cfg.SUMMARY_THINKING,
        num_ctx=cfg.SUMMARY_CTX,
        num_threads=cfg.OLLAMA_NUM_THREADS,
        max_retries=cfg.MAX_RETRIES,
        provider=cfg.PROVIDER,
        max_tokens=cfg.SUMMARY_MAX_TOKENS,
    )


def stage2_summarize(articles: list[dict], dry_run: bool = False,
                     settings: Settings | None = None) -> list[ArticleSummary]:
    cfg = _cfg(settings)
    logger.info("═" * 50)
    logger.info(f"ETAPA 2: Resumiendo con {cfg.SUMMARY_MODEL}")
    logger.info(f"  Artículos: {len(articles)} | Workers: {cfg.PARALLEL_WORKERS}")
    logger.info("═" * 50)

    summaries: list[ArticleSummary] = []
    failures = 0          # futures que lanzaron excepción o resúmenes con .error
    start = time.time()

    with ThreadPoolExecutor(max_workers=cfg.PARALLEL_WORKERS) as executor:
        futures = {
            executor.submit(_summarize_one, item, dry_run, cfg): item
            for item in articles
        }
        done = 0
        for future in as_completed(futures):
            done += 1
            item = futures[future]
            try:
                summary = future.result()
                summaries.append(summary)
                if summary.error:
                    failures += 1
                elapsed = time.time() - start
                rate    = done / elapsed * 60
                logger.info(
                    f"  [{done}/{len(articles)}] {summary.severity:<12}"
                    f"| {summary.threat_type:<15} | {item['title'][:50]}"
                    f"  (~{rate:.0f} art/min)"
                )
            except Exception as e:
                failures += 1
                logger.error(f"Error en resumen de '{item['title'][:50]}': {e}")

    total_time = time.time() - start
    by_severity: dict[str, int] = {}
    for s in summaries:
        by_severity[s.severity] = by_severity.get(s.severity, 0) + 1

    logger.info(
        f"Etapa 2 completada en {total_time / 60:.1f} min "
        f"({len(summaries)} resúmenes, {failures} fallos) — {by_severity}"
    )
    runlog.record_count("articulos_resumidos", len(summaries) - failures)
    runlog.record_count("articulos_fallidos", failures)
    runlog.record_drop("pipeline.stage2_summarize", kind="failure",
                       shown=len(articles) - failures, total=len(articles))

    # Fail-fast: si demasiados artículos fallaron, casi siempre indica un fallo
    # sistémico (LLM/provider caído, key inválida). Abortar aquí evita gastar
    # horas en Stage 3 para producir un informe vacío o sin sentido.
    threshold = cfg.STAGE2_FAIL_FAST_THRESHOLD
    if not dry_run and articles and failures / len(articles) >= threshold:
        raise RuntimeError(
            f"Stage 2 abortado: {failures}/{len(articles)} resúmenes fallaron "
            f"(≥{threshold:.0%}). Probable fallo del proveedor LLM o credenciales. "
            f"Revisa la conexión a {cfg.PROVIDER} antes de reintentar."
        )
    return summaries


# ─────────────────────────────────────────────
# ETAPA 2.5: CORRELACIONES
# ─────────────────────────────────────────────

def stage25_correlate(summaries: list[ArticleSummary],
                      settings: Settings | None = None) -> CorrelationContext:
    cfg = _cfg(settings)
    logger.info("═" * 50)
    logger.info("ETAPA 2.5: Correlacionando CVEs, actores y KEV")
    logger.info("═" * 50)
    return build_correlation_context(
        summaries=summaries,
        kev_url=cfg.CISA_KEV_URL,
        epss_url=cfg.EPSS_API_URL,
        kev_timeout=cfg.KEV_FETCH_TIMEOUT,
    )


# ─────────────────────────────────────────────
# ETAPA 2.7: ENRICHMENT EXTERNO DE IOCs
# ─────────────────────────────────────────────

def stage27_enrich(summaries: list[ArticleSummary],
                   settings: Settings | None = None):
    """Cruza los IOCs del día contra fuentes externas (IPsum, OpenPhish, ipcheck…)
    y **devuelve** el EnrichmentContext. Toda la etapa es tolerante a fallos:
    nunca aborta el run — devuelve None y el pipeline sigue sin enrichment.

    Hasta F-I el bloque se anexaba a `correlation.extra_blocks` para no tocar las
    firmas de analyzer.py; el efecto colateral era que el enrichment sólo llegaba
    a las fases que ya recibían correlación (vulnerability y threat_intel), y
    LATAM y general nunca veían que una IP del artículo estuviera en una
    blocklist. Ahora es un parámetro propio y llega a las cuatro."""
    cfg = _cfg(settings)
    if not cfg.ENRICHMENT_ENABLED:
        return None
    logger.info("═" * 50)
    logger.info("ETAPA 2.7: Enrichment externo de IOCs")
    logger.info("═" * 50)
    try:
        from separatio.enrichers import build_enrichers
        from separatio.enrichment import run_enrichment

        enrichers = build_enrichers(cfg)
        if not enrichers:
            logger.info("  Enrichment: sin fuentes habilitadas")
            return None
        ctx = run_enrichment(summaries, enrichers, settings=cfg)
        logger.info(
            f"  Enrichment: {len(ctx.verdicts)} veredictos | "
            f"ok={ctx.sources_ok} | fallidas={ctx.sources_failed}"
        )
        return ctx
    except Exception as e:
        logger.warning(f"  Enrichment falló (no crítico, se continúa): {e}")
        runlog.record_failure("stage:2.7-enrichment", e)
        return None


# ─────────────────────────────────────────────
# ETAPA 2.6: HISTÓRICO Y TRENDING
# ─────────────────────────────────────────────

def stage26_history(
    summaries: list[ArticleSummary],
    date_str: str,
    correlation: CorrelationContext,
    settings: Settings | None = None,
) -> TrendingContext:
    cfg = _cfg(settings)
    logger.info("═" * 50)
    logger.info("ETAPA 2.6: Actualizando historial y calculando tendencias")
    logger.info("═" * 50)
    history = load_history(cfg.HISTORY_FILE)
    append_daily_record(history, date_str, summaries, correlation)
    save_history(history, cfg.HISTORY_FILE)
    trending = build_trending_context(history, date_str, cfg.TREND_WINDOW_DAYS,
                                      settings=cfg)
    logger.info(
        f"  Historial: {len(history)} días registrados | "
        f"Ventana: {trending.days_with_data}/{cfg.TREND_WINDOW_DAYS} días con datos | "
        f"Actores persistentes: {len(trending.returning_actors)} | "
        f"Actores nuevos: {len(trending.new_actors)}"
    )
    return trending


# ─────────────────────────────────────────────
# ETAPA 3: INFORME
# ─────────────────────────────────────────────

def stage3_report(summaries: list[ArticleSummary],
                  date_str: str,
                  correlation: CorrelationContext | None = None,
                  trending: TrendingContext | None = None,
                  dry_run: bool = False,
                  enrichment=None,
                  settings: Settings | None = None) -> dict[str, str]:
    cfg = _cfg(settings)
    logger.info("═" * 50)
    logger.info(f"ETAPA 3: Generando informe con {cfg.REPORT_MODEL}")
    logger.info("═" * 50)

    valid = [s for s in summaries if s.error is None]
    errored = len(summaries) - len(valid)
    if errored:
        logger.warning(
            f"  {errored} resúmenes descartados por error de extracción JSON "
            f"(campos vacíos — no aptos para Stage 3)"
        )

    if dry_run:
        markdown = (
            "===VULNERABILITY_BRIEFING===\n"
            f"# Vulnerability Briefing — {date_str}\n\n[DRY RUN]\n\n"
            "===THREAT_INTEL_DIGEST===\n"
            f"# Threat Intelligence Digest — {date_str}\n\n[DRY RUN]\n\n"
            "===END==="
        )
    else:
        logger.info(f"  Enviando {len(valid)} resúmenes válidos al modelo...")
        markdown = generate_report(
            summaries=valid,
            date_str=date_str,
            model=cfg.REPORT_MODEL,
            ollama_host=cfg.OLLAMA_HOST,
            language=cfg.REPORT_LANGUAGE,
            timeout=cfg.REPORT_TIMEOUT,
            thinking=cfg.REPORT_THINKING,
            num_ctx=cfg.REPORT_CTX,
            num_threads=cfg.OLLAMA_NUM_THREADS,
            correlation=correlation,
            trending=trending,
            enrichment=enrichment,
            max_tokens=cfg.REPORT_MAX_TOKENS,
            article_limit=cfg.REPORT_ARTICLE_LIMIT,
            provider=cfg.PROVIDER,
        )

    total_feeds = len(set(s.feed_title for s in summaries))
    return save_report(
        markdown_content=markdown,
        output_dir=_dated_dir(date_str, cfg),
        date_str=date_str,
        total_articles=len(summaries),
        total_feeds=total_feeds,
        fmt=cfg.OUTPUT_FORMAT,
        split=cfg.SPLIT_REPORTS,
        provider=cfg.PROVIDER,
    )


# ─────────────────────────────────────────────
# ETAPA 3 MULTI-FASE + ETAPA 4 SÍNTESIS
# ─────────────────────────────────────────────

# El ruteo (qué artículo va a qué fase, y qué contexto recibe cada una) vive en
# `separatio/router.py` desde F-G/G-3. `CORRELATED_PHASES` se importa arriba y
# se reexporta desde acá por compatibilidad.


def stage3_phases(
    summaries: list[ArticleSummary],
    date_str: str,
    correlation: CorrelationContext | None = None,
    trending: TrendingContext | None = None,
    dry_run: bool = False,
    enrichment=None,
    settings: Settings | None = None,
) -> dict[str, str]:
    """Etapa 3 multi-fase: 4 llamadas LLM especializadas secuenciales."""
    cfg = _cfg(settings)
    logger.info("═" * 50)
    logger.info(f"ETAPA 3 MULTI-FASE — {cfg.REPORT_MODEL}")
    logger.info("═" * 50)

    valid = [s for s in summaries if s.error is None]
    phases = group_by_phase(valid, cfg.PHASE_CATEGORY_MAP)
    phase_order = _phase_order(cfg.PHASE_CATEGORY_MAP)

    phase_models     = cfg.PHASE_MODELS         or {}
    phase_max_tokens = cfg.PHASE_MAX_TOKENS     or {}
    phase_art_limits = cfg.PHASE_ARTICLE_LIMITS or {}

    phase_outputs: dict[str, str] = {}

    # La correlación (KEV/EPSS) sigue yendo sólo a vulnerability y threat_intel;
    # el enrichment, desde F-I, va a las cuatro. Se sigue registrando el recorte
    # de correlación para que el manifiesto no dé a entender que todas las fases
    # ven lo mismo.
    if correlation is not None:
        con_ctx = [p for p in phase_order if receives_correlation(p) and phases.get(p)]
        sin_ctx = [p for p in phase_order if not receives_correlation(p) and phases.get(p)]
        if sin_ctx:
            runlog.record_drop(
                "pipeline.stage3_phases.correlation", kind="filter",
                shown=len(con_ctx), total=len(con_ctx) + len(sin_ctx),
                detail=f"sin correlación KEV/EPSS: {', '.join(sin_ctx)}",
            )

    for phase in phase_order:
        arts = phases.get(phase, [])
        if not arts:
            logger.info(f"  Fase '{phase}': sin artículos — omitida")
            continue

        logger.info(f"  Fase '{phase}': {len(arts)} artículos")

        if dry_run:
            phase_outputs[phase] = (
                f"# {phase.replace('_', ' ').title()} — {date_str}\n\n[DRY RUN]\n"
            )
            continue

        model     = phase_models.get(phase) or cfg.REPORT_MODEL
        max_tok   = phase_max_tokens.get(phase, 2500)
        art_limit = phase_art_limits.get(phase, None)

        phase_outputs[phase] = generate_phase_report(
            phase=phase,
            summaries=arts,
            date_str=date_str,
            model=model,
            ollama_host=cfg.OLLAMA_HOST,
            language=cfg.REPORT_LANGUAGE,
            timeout=cfg.REPORT_TIMEOUT,
            thinking=cfg.REPORT_THINKING,
            num_ctx=cfg.REPORT_CTX,
            num_threads=cfg.OLLAMA_NUM_THREADS,
            max_tokens=max_tok,
            provider=cfg.PROVIDER,
            settings=cfg,
            article_limit=art_limit,
            correlation=correlation if receives_correlation(phase) else None,
            trending=trending       if receives_trending(phase)    else None,
            enrichment=enrichment,
        )

    return phase_outputs


def stage4_synthesis(
    phase_outputs: dict[str, str],
    summaries: list[ArticleSummary],
    date_str: str,
    dry_run: bool = False,
    settings: Settings | None = None,
) -> dict[str, str]:
    """Etapa 4: síntesis maestra cross-domain + ensamblado del informe final."""
    cfg = _cfg(settings)
    logger.info("═" * 50)
    logger.info("ETAPA 4: Síntesis maestra cross-domain")
    logger.info("═" * 50)

    if dry_run:
        synthesis_md = f"# Resumen Ejecutivo — {date_str}\n\n[DRY RUN]\n"
    else:
        phase_models = cfg.PHASE_MODELS or {}
        max_tok      = (cfg.PHASE_MAX_TOKENS or {}).get("synthesis", 1500)
        model        = phase_models.get("synthesis") or cfg.REPORT_MODEL
        synthesis_md = generate_synthesis_report(
            phase_outputs=phase_outputs,
            date_str=date_str,
            total_articles=len(summaries),
            model=model,
            ollama_host=cfg.OLLAMA_HOST,
            language=cfg.REPORT_LANGUAGE,
            timeout=cfg.REPORT_TIMEOUT,
            thinking=cfg.REPORT_THINKING,
            num_ctx=cfg.REPORT_CTX,
            num_threads=cfg.OLLAMA_NUM_THREADS,
            max_tokens=max_tok,
            provider=cfg.PROVIDER,
            settings=cfg,
        )

    # Síntesis al frente, luego las fases en orden canónico. Ojo: acá van sólo
    # las canónicas, no `router.phase_order()` — una clave extra de
    # PHASE_CATEGORY_MAP se genera en Stage 3 pero nunca se ensambló en el
    # informe final. Se preserva tal cual (F-G/G-3 no cambia conducta).
    parts = [synthesis_md]
    for phase in CANONICAL_PHASES:
        if phase in phase_outputs:
            parts.append(phase_outputs[phase])

    combined    = "\n\n---\n\n".join(parts)
    total_feeds = len(set(s.feed_title for s in summaries))
    dated_dir   = _dated_dir(date_str, cfg)

    return save_report(
        markdown_content=combined,
        output_dir=dated_dir,
        date_str=date_str,
        total_articles=len(summaries),
        total_feeds=total_feeds,
        fmt=cfg.OUTPUT_FORMAT,
        split=False,
        provider=cfg.PROVIDER,
    )


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def settings_for(args, base: Settings | None = None) -> Settings:
    """La config efectiva de esta corrida, según los flags de la línea de comandos.

    Hasta F-G/G-2 esto se hacía **mutando el módulo `config`** en caliente
    (`config.OUTPUT_DIR = .../dryrun`), con el efecto colateral de cambiárselo a
    todo el proceso y a cualquiera que lo importara después. Ahora es una función
    pura: entra un `Settings`, sale otro, y el que se pasea por las etapas es el
    que devuelve esto.

    Es función aparte de `main()` a propósito, para poder testear el aislamiento
    del dry-run sin arrancar el pipeline — ver `tests/test_settings.py`.
    """
    cfg = base if base is not None else config.SETTINGS

    if args.categories:
        cfg = cfg.derive(FEED_CATEGORIES=[c.strip() for c in args.categories.split(",")])

    if args.dry_run:
        # Un dry-run escribe los mismos artefactos que una corrida real (informe,
        # caché, history) y por lo tanto PISA los del día si ya corriste. Se aísla
        # todo bajo OUTPUT_DIR/dryrun/, con su propio history.json descartable.
        # (Incidente del 2026-08-08: un dry-run de verificación pisó el informe
        # real, el caché de 116 resúmenes y history.json.)
        out = str(Path(cfg.OUTPUT_DIR) / "dryrun")
        cfg = cfg.derive(OUTPUT_DIR=out,
                         HISTORY_FILE=str(Path(out) / "history.json"))

    return cfg


def main():
    parser = argparse.ArgumentParser(
        description="Pipeline de análisis de amenazas con Miniflux + Ollama"
    )
    parser.add_argument("--dry-run",     action="store_true",
                        help="Sin llamadas a Ollama (prueba de fetch)")
    parser.add_argument("--limit",       type=int, default=config.MAX_ARTICLES,
                        help="Máximo de artículos a procesar")
    parser.add_argument("--report-only", action="store_true",
                        help="Regenerar informe desde caché JSON existente")
    parser.add_argument("--no-mark-read", action="store_true",
                        help="No marcar artículos como leídos en Miniflux")
    parser.add_argument("--categories", type=str, default=None,
                        help='Categorías a procesar, separadas por coma. '
                             'Ej: --categories "Vulnerability,Threat Intel". '
                             'Sobreescribe FEED_CATEGORIES en config.py.')
    parser.add_argument("--weekly",      action="store_true",
                        help="Generar resumen semanal desde los últimos 7 días de caché")
    parser.add_argument("--weekly-days", type=int, default=7,
                        help="Días a incluir en el resumen semanal (default: 7)")
    parser.add_argument("--last-run",    action="store_true",
                        help="Reimprime el resumen de la última corrida y sale")
    parser.add_argument("--json",        action="store_true",
                        help="Con --last-run: escupe el manifiesto crudo")
    args = parser.parse_args()

    cfg = settings_for(args)
    if args.dry_run:
        logger.info("Modo --dry-run: salidas aisladas en %s", cfg.OUTPUT_DIR)

    Path(cfg.OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

    if args.last_run:
        sys.exit(_show_last_run(as_json=args.json, settings=cfg))

    date_str = datetime.now().strftime("%Y-%m-%d")
    mode = ("weekly" if args.weekly else
            "dry-run" if args.dry_run else
            "report-only" if args.report_only else "full")
    label = _week_label() if args.weekly else date_str

    runlog.start_run(date_str, mode)
    logger.info(f"\n{'═' * 50}")
    logger.info(f"  THREAT INTELLIGENCE PIPELINE — {label}  [modo: {mode}]")
    if cfg.FEED_CATEGORIES:
        logger.info(f"  Categorías: {', '.join(cfg.FEED_CATEGORIES)}")
    logger.info(f"{'═' * 50}\n")

    try:
        _run(args, date_str, cfg)
    except Exception as e:
        # Cualquier excepción no atrapada: se anota y se cierra el manifiesto
        # igual — una corrida que revienta también tiene que quedar registrada.
        logger.exception(f"Corrida abortada: {e}")
        runlog.record_failure("pipeline", e)
    finally:
        manifest = runlog.finish_run(Path(_dated_dir(label, cfg)) / runlog.MANIFEST_NAME)
        logger.info("\n" + manifest.summary_text())

    sys.exit(manifest.exit_code())


def _run(args, date_str: str, settings: Settings | None = None) -> None:
    """El cuerpo de la corrida. Separado de main() para que el manifiesto se
    cierre siempre, pase lo que pase acá adentro."""
    cfg = _cfg(settings)
    if args.weekly:
        run_weekly(days=args.weekly_days, settings=cfg)
        return

    if args.report_only:
        logger.info("Modo --report-only: cargando resúmenes desde caché...")
        with runlog.stage("cache"):
            summaries = load_summaries_cache(date_str, cfg)
        runlog.record_count("articulos_cache", len(summaries))
        with runlog.stage("stage2.5"):
            correlation = stage25_correlate(summaries, cfg)
        enrichment = stage27_enrich(summaries, cfg)
        ioc_paths = export_iocs(summaries, date_str, _dated_dir(date_str, cfg), enrichment)
        paths = _report_stages(summaries, date_str, correlation, None, args, enrichment, cfg)
        paths.update(ioc_paths)
        _print_result(paths)
        return

    logger.info("Conectando a Miniflux...")
    try:
        client = MinifluxClient(
            base_url=cfg.MINIFLUX_URL,
            username=cfg.MINIFLUX_USERNAME,
            password=cfg.MINIFLUX_PASSWORD,
            api_token=cfg.MINIFLUX_API_TOKEN,
        )
    except Exception as e:
        logger.error(f"No se pudo conectar a Miniflux: {e}")
        runlog.record_failure("miniflux", e)
        runlog.record_stage("stage1", False, 0.0, f"{type(e).__name__}: {e}")
        return

    with runlog.stage("stage1"):
        articles = stage1_fetch(client, limit=args.limit, settings=cfg)
    if not articles:
        logger.info("No hay artículos para procesar. Saliendo.")
        # Sin artículos no hay informe, pero tampoco hay fallo: se declara para
        # que el status sea `degraded` (exit 0) y no `failed`.
        runlog.expect_no_report("sin artículos nuevos en Miniflux")
        return

    with runlog.stage("stage2"):
        summaries = stage2_summarize(articles, dry_run=args.dry_run, settings=cfg)
    summaries = dedup_by_cves(summaries)
    save_summaries_cache(summaries, date_str, cfg)

    if cfg.MARK_AS_READ and not args.no_mark_read and not args.dry_run:
        client.mark_as_read([a["article_id"] for a in articles])

    if not args.dry_run and cfg.PROVIDER == "ollama":
        unload_model(cfg.SUMMARY_MODEL, cfg.OLLAMA_HOST)

    with runlog.stage("stage2.5"):
        correlation = stage25_correlate(summaries, cfg)
    enrichment = stage27_enrich(summaries, cfg)
    ioc_paths = export_iocs(summaries, date_str, _dated_dir(date_str, cfg), enrichment)
    with runlog.stage("stage2.6"):
        trending = stage26_history(summaries, date_str, correlation, cfg)

    paths = _report_stages(summaries, date_str, correlation, trending, args, enrichment, cfg)
    paths.update(ioc_paths)
    _print_result(paths)


def _report_stages(summaries, date_str, correlation, trending, args,
                   enrichment=None, settings: Settings | None = None) -> dict[str, str]:
    """Etapas 3 y 4 (o la 3 legacy), cronometradas para el manifiesto."""
    cfg = _cfg(settings)
    if cfg.PHASE_REPORTS:
        with runlog.stage("stage3_phases"):
            phase_outputs = stage3_phases(summaries, date_str, correlation, trending,
                                          dry_run=args.dry_run, enrichment=enrichment,
                                          settings=cfg)
        with runlog.stage("stage4"):
            return stage4_synthesis(phase_outputs, summaries, date_str,
                                    dry_run=args.dry_run, settings=cfg)
    with runlog.stage("stage3"):
        return stage3_report(summaries, date_str, correlation, trending,
                             dry_run=args.dry_run, enrichment=enrichment, settings=cfg)


def _week_label() -> str:
    iso = datetime.now().isocalendar()
    return f"{iso.year}-W{iso.week:02d}"


def _show_last_run(as_json: bool = False, settings: Settings | None = None) -> int:
    """`--last-run`: reimprime el resumen de la corrida más reciente sin correr
    nada. Es la forma de saber cómo salió el informe de hoy sin leer el log."""
    out_dir = _cfg(settings).OUTPUT_DIR
    path = runlog.find_latest_manifest(out_dir)
    if path is None:
        print(f"No hay manifiestos en {out_dir} "
              f"(ninguna corrida instrumentada todavía).")
        return 1
    if as_json:
        print(Path(path).read_text(encoding="utf-8"))
        return 0
    manifest = runlog.load_manifest(path)
    print(manifest.summary_text())
    print(f"  ({path})")
    return manifest.exit_code()


def _print_result(paths: dict) -> None:
    runlog.record_report(paths)
    logger.info("\n" + "═" * 50)
    logger.info("  PIPELINE COMPLETADO ✓")
    logger.info("═" * 50)
    for fmt, path in paths.items():
        logger.info(f"  {fmt.upper()}: {os.path.abspath(path)}")
    logger.info("")


if __name__ == "__main__":
    main()
