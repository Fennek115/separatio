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
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import config
from miniflux_client import MinifluxClient
from extractor import extract_article_text, truncate_text
from analyzer import ArticleSummary, summarize_article, generate_report, unload_model
from correlator import build_correlation_context, CorrelationContext
from reporter import save_report

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
    summaries = []
    for d in data:
        s = ArticleSummary(
            article_id=d["article_id"],
            title=d["title"],
            url=d["url"],
            feed_title=d["feed_title"],
            feed_category=d["feed_category"],
            published_at=d["published_at"],
        )
        s.__dict__.update(d)
        summaries.append(s)
    logger.info(f"Cargados {len(summaries)} resúmenes del caché")
    return summaries


# ─────────────────────────────────────────────
# ETAPA 1: FETCH
# ─────────────────────────────────────────────

def stage1_fetch(client: MinifluxClient, limit: int) -> list[dict]:
    logger.info("═" * 50)
    logger.info("ETAPA 1: Obteniendo artículos de Miniflux")
    logger.info("═" * 50)

    articles = client.get_unread_articles(limit=limit)
    if not articles:
        logger.warning("No hay artículos no leídos.")
        return []

    if config.FEED_CATEGORIES:
        before   = len(articles)
        articles = [a for a in articles if a.feed_category in config.FEED_CATEGORIES]
        logger.info(f"Filtro por categorías: {before} → {len(articles)} artículos")

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
        text = truncate_text(text, max_tokens_approx=800)
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
        ollama_host=config.OLLAMA_HOST,
        timeout=config.SUMMARY_TIMEOUT,
        thinking=config.SUMMARY_THINKING,
        num_ctx=config.SUMMARY_CTX,
        num_threads=config.OLLAMA_NUM_THREADS,
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
        kev_timeout=config.KEV_FETCH_TIMEOUT,
    )


# ─────────────────────────────────────────────
# ETAPA 3: INFORME
# ─────────────────────────────────────────────

def stage3_report(summaries: list[ArticleSummary],
                  date_str: str,
                  correlation: CorrelationContext | None = None,
                  dry_run: bool = False) -> dict[str, str]:
    logger.info("═" * 50)
    logger.info(f"ETAPA 3: Generando informe con {config.REPORT_MODEL}")
    logger.info("═" * 50)

    if dry_run:
        markdown = (
            "===VULNERABILITY_BRIEFING===\n"
            f"# 🔒 Vulnerability Briefing — {date_str}\n\n[DRY RUN]\n\n"
            "===THREAT_INTEL_DIGEST===\n"
            f"# 🕵️ Threat Intelligence Digest — {date_str}\n\n[DRY RUN]\n\n"
            "===END==="
        )
    else:
        logger.info(f"  Enviando {len(summaries)} resúmenes al modelo...")
        markdown = generate_report(
            summaries=summaries,
            date_str=date_str,
            model=config.REPORT_MODEL,
            ollama_host=config.OLLAMA_HOST,
            language=config.REPORT_LANGUAGE,
            timeout=config.REPORT_TIMEOUT,
            thinking=config.REPORT_THINKING,
            num_ctx=config.REPORT_CTX,
            num_threads=config.OLLAMA_NUM_THREADS,
            correlation=correlation,
            max_tokens=config.REPORT_MAX_TOKENS,
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
    args = parser.parse_args()

    Path(config.OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

    date_str = datetime.now().strftime("%Y-%m-%d")
    logger.info(f"\n{'═' * 50}")
    logger.info(f"  THREAT INTELLIGENCE PIPELINE — {date_str}")
    logger.info(f"{'═' * 50}\n")

    if args.report_only:
        logger.info("Modo --report-only: cargando resúmenes desde caché...")
        summaries    = load_summaries_cache(date_str)
        correlation  = stage25_correlate(summaries)
        paths        = stage3_report(summaries, date_str, correlation, dry_run=args.dry_run)
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
    save_summaries_cache(summaries, date_str)

    if config.MARK_AS_READ and not args.no_mark_read:
        client.mark_as_read([a["article_id"] for a in articles])

    if not args.dry_run:
        unload_model(config.SUMMARY_MODEL, config.OLLAMA_HOST)

    correlation = stage25_correlate(summaries)
    paths       = stage3_report(summaries, date_str, correlation, dry_run=args.dry_run)
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
