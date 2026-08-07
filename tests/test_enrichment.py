"""Tests de la capa de enrichment (Stage 2.7) — deterministas, sin red."""

from analyzer import ArticleSummary
from enrichment import (
    Enricher, EnrichmentContext, IocVerdict,
    collect_iocs, ioc_kind, normalize_ioc, run_enrichment,
)


def _summary(aid, feed, iocs):
    return ArticleSummary(article_id=aid, title=f"t{aid}", url="u",
                          feed_title=feed, feed_category="Threat Intel",
                          published_at="", iocs=iocs)


def test_ioc_kind():
    assert ioc_kind("1.2.3.4") == "ip"
    assert ioc_kind("1.2.3.4:8080") == "ip"
    assert ioc_kind("evil.com") == "domain"
    assert ioc_kind("http://evil.com/x") == "url"
    assert ioc_kind("a" * 32) == "hash"
    assert ioc_kind("a" * 64) == "hash"
    assert ioc_kind("notanioc") == "other"


def test_normalize_ioc_defang():
    assert normalize_ioc("evil[.]com") == "evil.com"
    assert normalize_ioc("evil[dot]com") == "evil.com"
    assert normalize_ioc("hxxp://evil.com") == "http://evil.com"
    assert normalize_ioc("  EVIL.com ") == "evil.com"


def test_collect_iocs_dedups_by_feed():
    summaries = [
        _summary(1, "FeedA", ["1.2.3.4", "evil[.]com"]),
        _summary(2, "FeedB", ["1.2.3.4"]),
        _summary(3, "FeedA", ["1.2.3.4"]),  # mismo feed -> no duplica
    ]
    iocs = collect_iocs(summaries)
    assert iocs["1.2.3.4"] == ["FeedA", "FeedB"]
    assert "evil.com" in iocs           # normalizado
    # IOCs triviales (<=4 chars) se descartan
    assert all(len(k) > 4 for k in iocs)


def test_context_prompt_and_export():
    ctx = EnrichmentContext()
    ctx.add(IocVerdict(ioc="1.2.3.4", kind="ip", source="IPsum",
                       label="IP maliciosa", detail="9 listas"))
    block = ctx.format_for_prompt()
    assert "ENRICHMENT EXTERNO" in block and "1.2.3.4" in block and "IPsum" in block
    rows = ctx.export_rows()
    assert rows[0]["ioc"] == "1.2.3.4" and rows[0]["source"] == "IPsum"


def test_run_enrichment_isolates_failures():
    class GoodEnricher(Enricher):
        name = "good"
        def enrich(self, iocs, ctx):
            ctx.add(IocVerdict(ioc="1.2.3.4", kind="ip", source="good", label="x"))

    class BoomEnricher(Enricher):
        name = "boom"
        def enrich(self, iocs, ctx):
            raise RuntimeError("falla simulada")

    summaries = [_summary(1, "FeedA", ["1.2.3.4"])]
    ctx = run_enrichment(summaries, [GoodEnricher(), BoomEnricher()])
    assert "good" in ctx.sources_ok
    assert "boom" in ctx.sources_failed
    assert len(ctx.verdicts) == 1          # el fallo de boom no borró el de good


def test_run_enrichment_no_iocs():
    ctx = run_enrichment([_summary(1, "FeedA", [])], [])
    assert not ctx.has_signals()
