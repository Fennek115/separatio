"""
pipeline.py — Orquestador principal del pipeline de análisis de amenazas.

Uso:
    python pipeline.py                  # Ejecutar pipeline completo
    python pipeline.py --dry-run        # Sin llamadas a Ollama (prueba de fetch)
    python pipeline.py --limit 20       # Procesar solo 20 artículos
    python pipeline.py --report-only    # Regenerar informe desde caché JSON
"""

import argparse
import csv
import json
import logging
import os
import re
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path

import config
from miniflux_client import MinifluxClient
from extractor import extract_article_text, truncate_text
from analyzer import ArticleSummary, summarize_article, generate_report, generate_weekly_report, unload_model
from correlator import build_correlation_context, CorrelationContext
from history import load_history, append_daily_record, save_history, build_trending_context, TrendingContext
from reporter import save_report

Path(config.OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(
            os.path.join(config.OUTPUT_DIR, "pipeline.log"),
            encoding="utf-8",
        ),
    ],
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# CACHÉ JSON
# ─────────────────────────────────────────────

def _cache_path(date_str: str) -> str:
    safe = date_str.replace(" ", "_").replace("/", "-")
    return os.path.join(config.OUTPUT_DIR, f"summaries-cache-{safe}.json")


def save_summaries_cache(summaries: list[ArticleSummary], date_str: str) -> str:
    Path(config.OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    path = _cache_path(date_str)
    with open(path, "w", encoding="utf-8") as f:
        json.dump([s.__dict__ for s in summaries], f, ensure_ascii=False, indent=2)
    logger.info(f"Caché guardada: {path}")
    return path


def load_summaries_cache(date_str: str) -> list[ArticleSummary]:
    path = _cache_path(date_str)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    known = ArticleSummary.__dataclass_fields__
    summaries = [ArticleSummary(**{k: v for k, v in d.items() if k in known}) for d in data]
    logger.info(f"Cargados {len(summaries)} resúmenes del caché")
    return summaries


# ─────────────────────────────────────────────
# DEDUPLICACIÓN SEMÁNTICA (post Stage 2)
# ─────────────────────────────────────────────

def dedup_by_cves(
    summaries: list[ArticleSummary],
    min_shared: int = 2,
    min_jaccard: float = 0.4,
) -> list[ArticleSummary]:
    """Fusiona resúmenes que cubren el mismo grupo de CVEs."""
    sorted_idx = sorted(range(len(summaries)), key=lambda i: -summaries[i].severity_score)
    absorbed: set[int] = set()

    for pos_a, idx_a in enumerate(sorted_idx):
        if idx_a in absorbed or not summaries[idx_a].cves:
            continue
        cves_a = set(summaries[idx_a].cves)
        for idx_b in sorted_idx[pos_a + 1:]:
            if idx_b in absorbed or not summaries[idx_b].cves:
                continue
            cves_b = set(summaries[idx_b].cves)
            shared = len(cves_a & cves_b)
            if shared < min_shared:
                continue
            if shared / len(cves_a | cves_b) >= min_jaccard:
                absorbed.add(idx_b)
                s_a, s_b = summaries[idx_a], summaries[idx_b]
                s_a.iocs   = list({*s_a.iocs,   *s_b.iocs})[:20]
                s_a.actors = list({*s_a.actors, *s_b.actors})[:10]

    result = [s for i, s in enumerate(summaries) if i not in absorbed]
    if absorbed:
        logger.info(
            f"Dedup semantica (CVE): {len(summaries)} → {len(result)} "
            f"resumenes ({len(absorbed)} consolidados)"
        )
    return result


# ─────────────────────────────────────────────
# EXPORT IOCs
# ─────────────────────────────────────────────

def _detect_ioc_type(ioc: str) -> str:
    ioc = ioc.strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", ioc):
        return "ip"
    if re.match(r"^[0-9a-fA-F]{64}$", ioc):
        return "sha256"
    if re.match(r"^[0-9a-fA-F]{40}$", ioc):
        return "sha1"
    if re.match(r"^[0-9a-fA-F]{32}$", ioc):
        return "md5"
    if ioc.startswith(("http://", "https://")):
        return "url"
    if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", ioc):
        return "domain"
    return "other"


def export_iocs(
    summaries: list[ArticleSummary], date_str: str, output_dir: str
) -> dict[str, str]:
    """Exporta todos los IOCs únicos de los resúmenes a CSV y JSON."""
    rows = []
    for s in summaries:
        for ioc in s.iocs:
            rows.append({
                "date":     date_str,
                "ioc":      ioc.strip(),
                "type":     _detect_ioc_type(ioc),
                "severity": s.severity,
                "title":    s.title,
                "feed":     s.feed_title,
                "cves":     "|".join(s.cves),
            })

    if not rows:
        return {}

    seen: set[str] = set()
    unique = [r for r in rows if r["ioc"] not in seen and not seen.add(r["ioc"])]  # type: ignore[func-returns-value]

    safe_date = date_str.replace(" ", "_").replace("/", "-")
    paths: dict[str, str] = {}

    csv_path = os.path.join(output_dir, f"iocs-{safe_date}.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["date", "ioc", "type", "severity", "title", "feed", "cves"]
        )
        writer.writeheader()
        writer.writerows(unique)
    paths["iocs_csv"] = csv_path

    by_type: dict[str, list] = defaultdict(list)
    for row in unique:
        by_type[row["type"]].append(row)

    json_path = os.path.join(output_dir, f"iocs-{safe_date}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(dict(by_type), f, ensure_ascii=False, indent=2)
    paths["iocs_json"] = json_path

    logger.info(f"IOCs exportados: {len(unique)} unicos → {csv_path}")
    return paths


# ─────────────────────────────────────────────
# RESUMEN SEMANAL
# ─────────────────────────────────────────────

def run_weekly(days: int = 7) -> None:
    """Carga los últimos N días de caché y genera un briefing semanal."""
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
        cache   = _cache_path(day_str)
        if os.path.exists(cache):
            day_summaries = load_summaries_cache(day_str)
            all_summaries.extend(day_summaries)
            dates_found.append(day_str)

    if not all_summaries:
        logger.error("No se encontraron cachés en los últimos %d días.", days)
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
        model=config.REPORT_MODEL,
        ollama_host=getattr(config, "OLLAMA_HOST", ""),
        language=config.REPORT_LANGUAGE,
        timeout=config.REPORT_TIMEOUT,
        thinking=config.REPORT_THINKING,
        num_ctx=config.REPORT_CTX,
        num_threads=getattr(config, "OLLAMA_NUM_THREADS", 0),
        max_tokens=config.REPORT_MAX_TOKENS,
        provider=config.PROVIDER,
    )

    total_feeds = len(set(s.feed_title for s in all_summaries))
    paths = save_report(
        markdown_content=markdown,
        output_dir=config.OUTPUT_DIR,
        date_str=week_label,
        total_articles=len(all_summaries),
        total_feeds=total_feeds,
        fmt=config.OUTPUT_FORMAT,
        split=False,
        provider=config.PROVIDER,
        filename_prefix="weekly-briefing",
    )

    ioc_paths = export_iocs(all_summaries, week_label, config.OUTPUT_DIR)
    paths.update(ioc_paths)
    _print_result(paths)


# ─────────────────────────────────────────────
# ETAPA 1: FETCH
# ─────────────────────────────────────────────

def stage1_fetch(client: MinifluxClient, limit: int) -> list[dict]:
    logger.info("═" * 50)
    logger.info("ETAPA 1: Obteniendo artículos de Miniflux")
    logger.info("═" * 50)

    # Fetch a wider pool when per-feed capping is active so high-volume feeds
    # (MSRC: 2975 entries, Black Hills: 909) don't monopolize the global limit.
    per_feed = getattr(config, "PER_FEED_LIMIT", None)
    fetch_limit = min(limit * 5, 1000) if per_feed else limit
    articles = client.get_unread_articles(limit=fetch_limit)
    if not articles:
        logger.warning("No hay artículos no leídos.")
        return []

    if config.FEED_CATEGORIES:
        before   = len(articles)
        articles = [a for a in articles if a.feed_category in config.FEED_CATEGORIES]
        logger.info(f"Filtro por categorías: {before} → {len(articles)} artículos")

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
            timeout=config.HTTP_TIMEOUT,
            min_length=config.MIN_CONTENT_LENGTH,
            blocked_domains=config.NO_SCRAPE_DOMAINS,
        )
        text = truncate_text(text, max_tokens_approx=config.ARTICLE_MAX_TOKENS)
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
    return processed


# ─────────────────────────────────────────────
# ETAPA 2: RESÚMENES
# ─────────────────────────────────────────────

def _summarize_one(item: dict, dry_run: bool) -> ArticleSummary:
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
        model=config.SUMMARY_MODEL,
        ollama_host=getattr(config, "OLLAMA_HOST", ""),
        timeout=config.SUMMARY_TIMEOUT,
        thinking=config.SUMMARY_THINKING,
        num_ctx=config.SUMMARY_CTX,
        num_threads=getattr(config, "OLLAMA_NUM_THREADS", 0),
        max_retries=config.MAX_RETRIES,
        provider=config.PROVIDER,
    )


def stage2_summarize(articles: list[dict], dry_run: bool = False) -> list[ArticleSummary]:
    logger.info("═" * 50)
    logger.info(f"ETAPA 2: Resumiendo con {config.SUMMARY_MODEL}")
    logger.info(f"  Artículos: {len(articles)} | Workers: {config.PARALLEL_WORKERS}")
    logger.info("═" * 50)

    summaries: list[ArticleSummary] = []
    start = time.time()

    with ThreadPoolExecutor(max_workers=config.PARALLEL_WORKERS) as executor:
        futures = {
            executor.submit(_summarize_one, item, dry_run): item
            for item in articles
        }
        done = 0
        for future in as_completed(futures):
            done += 1
            item = futures[future]
            try:
                summary = future.result()
                summaries.append(summary)
                elapsed = time.time() - start
                rate    = done / elapsed * 60
                logger.info(
                    f"  [{done}/{len(articles)}] {summary.severity:<12}"
                    f"| {summary.threat_type:<15} | {item['title'][:50]}"
                    f"  (~{rate:.0f} art/min)"
                )
            except Exception as e:
                logger.error(f"Error en resumen de '{item['title'][:50]}': {e}")

    total_time = time.time() - start
    by_severity: dict[str, int] = {}
    for s in summaries:
        by_severity[s.severity] = by_severity.get(s.severity, 0) + 1

    logger.info(
        f"Etapa 2 completada en {total_time / 60:.1f} min "
        f"({len(summaries)} resúmenes) — {by_severity}"
    )
    return summaries


# ─────────────────────────────────────────────
# ETAPA 2.5: CORRELACIONES
# ─────────────────────────────────────────────

def stage25_correlate(summaries: list[ArticleSummary]) -> CorrelationContext:
    logger.info("═" * 50)
    logger.info("ETAPA 2.5: Correlacionando CVEs, actores y KEV")
    logger.info("═" * 50)
    return build_correlation_context(
        summaries=summaries,
        kev_url=config.CISA_KEV_URL,
        epss_url=config.EPSS_API_URL,
        kev_timeout=config.KEV_FETCH_TIMEOUT,
    )


# ─────────────────────────────────────────────
# ETAPA 2.6: HISTÓRICO Y TRENDING
# ─────────────────────────────────────────────

def stage26_history(
    summaries: list[ArticleSummary],
    date_str: str,
    correlation: CorrelationContext,
) -> TrendingContext:
    logger.info("═" * 50)
    logger.info("ETAPA 2.6: Actualizando historial y calculando tendencias")
    logger.info("═" * 50)
    history = load_history(config.HISTORY_FILE)
    append_daily_record(history, date_str, summaries, correlation)
    save_history(history, config.HISTORY_FILE)
    trending = build_trending_context(history, date_str, config.TREND_WINDOW_DAYS)
    logger.info(
        f"  Historial: {len(history)} días registrados | "
        f"Ventana: {trending.days_with_data}/{config.TREND_WINDOW_DAYS} días con datos | "
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
                  dry_run: bool = False) -> dict[str, str]:
    logger.info("═" * 50)
    logger.info(f"ETAPA 3: Generando informe con {config.REPORT_MODEL}")
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
            model=config.REPORT_MODEL,
            ollama_host=getattr(config, "OLLAMA_HOST", ""),
            language=config.REPORT_LANGUAGE,
            timeout=config.REPORT_TIMEOUT,
            thinking=config.REPORT_THINKING,
            num_ctx=config.REPORT_CTX,
            num_threads=getattr(config, "OLLAMA_NUM_THREADS", 0),
            correlation=correlation,
            trending=trending,
            max_tokens=config.REPORT_MAX_TOKENS,
            article_limit=getattr(config, "REPORT_ARTICLE_LIMIT", None),
            provider=config.PROVIDER,
        )

    total_feeds = len(set(s.feed_title for s in summaries))
    return save_report(
        markdown_content=markdown,
        output_dir=config.OUTPUT_DIR,
        date_str=date_str,
        total_articles=len(summaries),
        total_feeds=total_feeds,
        fmt=config.OUTPUT_FORMAT,
        split=config.SPLIT_REPORTS,
        provider=config.PROVIDER,
    )


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

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
    args = parser.parse_args()

    if args.categories:
        config.FEED_CATEGORIES = [c.strip() for c in args.categories.split(",")]

    Path(config.OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

    if args.weekly:
        run_weekly(days=args.weekly_days)
        return

    date_str = datetime.now().strftime("%Y-%m-%d")
    logger.info(f"\n{'═' * 50}")
    logger.info(f"  THREAT INTELLIGENCE PIPELINE — {date_str}")
    if config.FEED_CATEGORIES:
        logger.info(f"  Categorías: {', '.join(config.FEED_CATEGORIES)}")
    logger.info(f"{'═' * 50}\n")

    if args.report_only:
        logger.info("Modo --report-only: cargando resúmenes desde caché...")
        summaries   = load_summaries_cache(date_str)
        ioc_paths   = export_iocs(summaries, date_str, config.OUTPUT_DIR)
        correlation = stage25_correlate(summaries)
        paths       = stage3_report(summaries, date_str, correlation, dry_run=args.dry_run)
        paths.update(ioc_paths)
        _print_result(paths)
        return

    logger.info("Conectando a Miniflux...")
    try:
        client = MinifluxClient(
            base_url=config.MINIFLUX_URL,
            username=getattr(config, "MINIFLUX_USERNAME", None),
            password=getattr(config, "MINIFLUX_PASSWORD", None),
            api_token=getattr(config, "MINIFLUX_API_TOKEN", None),
        )
    except Exception as e:
        logger.error(f"No se pudo conectar a Miniflux: {e}")
        sys.exit(1)

    articles = stage1_fetch(client, limit=args.limit)
    if not articles:
        logger.info("No hay artículos para procesar. Saliendo.")
        return

    summaries = stage2_summarize(articles, dry_run=args.dry_run)
    summaries = dedup_by_cves(summaries)
    save_summaries_cache(summaries, date_str)
    ioc_paths = export_iocs(summaries, date_str, config.OUTPUT_DIR)

    if config.MARK_AS_READ and not args.no_mark_read:
        client.mark_as_read([a["article_id"] for a in articles])

    if not args.dry_run and config.PROVIDER == "ollama":
        unload_model(config.SUMMARY_MODEL, config.OLLAMA_HOST)

    correlation = stage25_correlate(summaries)
    trending    = stage26_history(summaries, date_str, correlation)
    paths       = stage3_report(summaries, date_str, correlation, trending, dry_run=args.dry_run)
    paths.update(ioc_paths)
    _print_result(paths)


def _print_result(paths: dict) -> None:
    logger.info("\n" + "═" * 50)
    logger.info("  PIPELINE COMPLETADO ✓")
    logger.info("═" * 50)
    for fmt, path in paths.items():
        logger.info(f"  {fmt.upper()}: {os.path.abspath(path)}")
    logger.info("")


if __name__ == "__main__":
    main()
