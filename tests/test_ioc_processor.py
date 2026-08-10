"""Tests de la clasificación y el export de IOCs (F-G/G-3) — sin red, sobre tmp_path.

El export vive fuera de `pipeline.py` desde G-3 y no depende de `config`: el
destino entra por parámetro, así que se puede ejercitar entero en un tmp_path.
"""

import csv
import json

import pytest

from separatio.analyzer import ArticleSummary
from separatio.ioc_processor import CSV_FIELDS, detect_ioc_type, export_iocs


def mk(i, iocs, cves=(), sev="Alta", cat="Vulnerability"):
    return ArticleSummary(
        article_id=i, title=f"Art {i}", url=f"http://x/{i}", feed_title=f"feed{i}",
        feed_category=cat, published_at="2026-08-09T00:00:00Z",
        severity=sev, severity_score=4, iocs=list(iocs), cves=list(cves),
    )


class FakeEnrichment:
    """El mínimo del EnrichmentContext que consume el export: export_rows()."""

    def __init__(self, rows):
        self._rows = rows

    def export_rows(self):
        return self._rows


# ── clasificación ───────────────────────────────────────────

@pytest.mark.parametrize("ioc,esperado", [
    ("1.2.3.4", "ip"),
    ("1.2.3.4:8080", "ip"),
    ("  1.2.3.4  ", "ip"),          # se trimea antes de clasificar
    ("a" * 32, "md5"),
    ("A" * 32, "md5"),              # hex en mayúsculas también
    ("b" * 40, "sha1"),
    ("d" * 64, "sha256"),
    ("http://evil.com/x", "url"),
    ("https://evil.com", "url"),
    ("evil.com", "domain"),
    ("sub.evil.co.uk", "domain"),
    ("evil[.]com", "other"),        # defangeado: el export no normaliza
    ("hxxp://evil.com", "other"),
    ("z" * 64, "other"),            # 64 chars pero no hex
    ("", "other"),
    ("no-tld", "other"),
])
def test_detect_ioc_type(ioc, esperado):
    assert detect_ioc_type(ioc) == esperado


def test_los_tres_hashes_no_se_colapsan_en_uno():
    """A diferencia de `enrichment.ioc_kind`, que devuelve 'hash' para los tres.

    Son funciones distintas a propósito (ver el docstring del módulo): unificarlas
    cambiaría la columna `type` del CSV que consume un humano.
    """
    from separatio.enrichment import ioc_kind
    assert {detect_ioc_type("a" * 32), detect_ioc_type("a" * 40),
            detect_ioc_type("a" * 64)} == {"md5", "sha1", "sha256"}
    assert {ioc_kind("a" * 32), ioc_kind("a" * 40), ioc_kind("a" * 64)} == {"hash"}


# ── export ──────────────────────────────────────────────────

def test_sin_iocs_no_escribe_nada(tmp_path):
    assert export_iocs([mk(1, [])], "2026-08-09", str(tmp_path)) == {}
    assert not (tmp_path / "iocs").exists()


def test_csv_y_json_con_las_columnas_esperadas(tmp_path):
    paths = export_iocs([mk(1, ["1.2.3.4", "evil.com"], ["CVE-2026-1", "CVE-2026-2"])],
                        "2026-08-09", str(tmp_path))
    assert set(paths) == {"iocs_csv", "iocs_json"}

    with open(paths["iocs_csv"], encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert [r["ioc"] for r in rows] == ["1.2.3.4", "evil.com"]
    assert list(rows[0]) == CSV_FIELDS
    assert rows[0]["type"] == "ip" and rows[1]["type"] == "domain"
    assert rows[0]["cves"] == "CVE-2026-1|CVE-2026-2"       # un string por celda
    assert rows[0]["date"] == "2026-08-09"

    data = json.loads(open(paths["iocs_json"], encoding="utf-8").read())
    assert sorted(data) == ["domain", "ip"]                  # agrupado por tipo


def test_deduplica_ioc_repetido_entre_articulos(tmp_path):
    paths = export_iocs([mk(1, ["1.2.3.4"]), mk(2, ["1.2.3.4", "5.6.7.8"])],
                        "2026-08-09", str(tmp_path))
    with open(paths["iocs_csv"], encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert [r["ioc"] for r in rows] == ["1.2.3.4", "5.6.7.8"]
    assert rows[0]["feed"] == "feed1"        # gana la primera aparición


def test_reputacion_vacia_sin_enrichment(tmp_path):
    """El esquema del CSV no cambia según haya o no Stage 2.7 (G-4)."""
    paths = export_iocs([mk(1, ["1.2.3.4"])], "2026-08-09", str(tmp_path))
    with open(paths["iocs_csv"], encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert rows[0]["reputation"] == ""


def test_reputacion_con_varios_veredictos(tmp_path):
    enr = FakeEnrichment([
        {"ioc": "1.2.3.4", "source": "IPsum", "label": "malicious"},
        {"ioc": "1.2.3.4", "source": "ipcheck", "label": "abusive"},
        {"ioc": "otra.com", "source": "OpenPhish", "label": "phishing"},
    ])
    paths = export_iocs([mk(1, ["1.2.3.4", "evil.com"])], "2026-08-09", str(tmp_path), enr)
    with open(paths["iocs_csv"], encoding="utf-8") as f:
        rows = {r["ioc"]: r for r in csv.DictReader(f)}
    assert rows["1.2.3.4"]["reputation"] == "IPsum:malicious|ipcheck:abusive"
    assert rows["evil.com"]["reputation"] == ""     # veredicto de un IOC ajeno


def test_la_fecha_insegura_no_escapa_del_directorio(tmp_path):
    paths = export_iocs([mk(1, ["1.2.3.4"])], "2026-W32 semana", str(tmp_path))
    assert paths["iocs_csv"].endswith("iocs-2026-W32_semana.csv")
