"""Tests de OpenPhishEnricher — deterministas, sin red.

Cubre F-G G-7: una URL malformada (feed o IOC extraído por el LLM) no debe
tirar el enricher entero con `ValueError: Invalid IPv6 URL` de `urlparse`.
"""

import pytest

from separatio.enrichers.openphish import OpenPhishEnricher, _safe_netloc
from separatio.enrichment import EnrichmentContext


class _FakeResponse:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


def test_safe_netloc_tolerates_invalid_ipv6():
    # el patrón real que hace saltar ValueError en urllib.parse
    assert _safe_netloc("http://[::not-valid") == ""
    assert _safe_netloc("http://evil.com/x") == "evil.com"


def test_load_skips_malformed_line_without_failing(monkeypatch):
    enricher = OpenPhishEnricher(url="https://openphish.com/feed.txt")
    feed = "\n".join([
        "http://evil.com/phish",
        "http://[malformed",       # dispararía ValueError sin el guard
        "http://sub.bad.net/login",
    ])
    monkeypatch.setattr(
        "separatio.enrichers.openphish.requests.get",
        lambda url, timeout: _FakeResponse(feed),
    )
    urls, hosts = enricher._load()
    assert "http://evil.com/phish" in urls
    assert "evil.com" in hosts
    assert "sub.bad.net" in hosts


def test_enrich_skips_malformed_ioc(monkeypatch):
    enricher = OpenPhishEnricher(url="https://openphish.com/feed.txt")
    monkeypatch.setattr(
        "separatio.enrichers.openphish.requests.get",
        lambda url, timeout: _FakeResponse("http://evil.com/phish\n"),
    )
    ctx = EnrichmentContext()
    iocs = {"http://[malformed": ["FeedA"], "http://evil.com/phish": ["FeedA"]}
    enricher.enrich(iocs, ctx)   # no debe levantar
    assert any(v.ioc == "http://evil.com/phish" for v in ctx.verdicts)
