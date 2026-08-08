"""Tests del tope duro de reloj en el fetch de Stage 1 (extractor).

Reproduce el cuelgue del 2026-08-08: un fetch que duerme más que el tope
(p.ej. urllib3 respetando un Retry-After enorme) no debe colgar el pipeline.
Sin red: trafilatura/requests monkeypatcheados.
"""

import time

import pytest

from separatio import extractor


def test_hard_timeout_abandons_hung_fetch(monkeypatch):
    """Un fetch colgado se abandona al vencer hard_timeout y devuelve ''."""
    def hung_fetch(url):
        time.sleep(30)   # simula el sleep de Retry-After / servidor que gotea

    monkeypatch.setattr(extractor.trafilatura, "fetch_url", hung_fetch)

    start = time.monotonic()
    result = extractor.fetch_url_content("https://example.com/x",
                                         timeout=15, hard_timeout=1)
    elapsed = time.monotonic() - start

    assert result == ""
    assert elapsed < 5   # volvió por el tope, no por los 30s del sleep


def test_fast_fetch_returns_content(monkeypatch):
    """Un fetch normal devuelve el contenido extraído dentro del tope."""
    monkeypatch.setattr(extractor.trafilatura, "fetch_url",
                        lambda url: "<html>descargado</html>")
    monkeypatch.setattr(extractor.trafilatura, "extract",
                        lambda downloaded, **kw: "contenido " * 30)

    result = extractor.fetch_url_content("https://example.com/x",
                                         timeout=15, hard_timeout=5)
    assert "contenido" in result


def test_hard_timeout_defaults_to_triple_timeout(monkeypatch):
    """Sin hard_timeout explícito, el tope es timeout*3 (no infinito)."""
    def hung_fetch(url):
        time.sleep(30)

    monkeypatch.setattr(extractor.trafilatura, "fetch_url", hung_fetch)

    start = time.monotonic()
    result = extractor.fetch_url_content("https://example.com/x", timeout=1)
    elapsed = time.monotonic() - start

    assert result == ""
    assert elapsed == pytest.approx(3, abs=2)


def test_blocked_domain_skips_fetch(monkeypatch):
    """Dominio bloqueado: ni siquiera se lanza el thread de fetch."""
    def explode(url):
        raise AssertionError("no debería hacer fetch")

    monkeypatch.setattr(extractor.trafilatura, "fetch_url", explode)
    result = extractor.fetch_url_content("https://vulners.com/x",
                                         blocked_domains={"vulners.com"})
    assert result == ""
