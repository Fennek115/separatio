"""Tests del dedup semántico por CVEs (F-G/G-3) — deterministas, sin red.

Salió de `pipeline.py`, que no tenía ni un test: hasta G-3 la única red de
seguridad de esta función era comparar informes a ojo.
"""

from separatio.analyzer import ArticleSummary
from separatio.deduplicator import dedup_by_cves


def mk(title, score, cves, iocs=(), actors=(), cat="Vulnerability"):
    return ArticleSummary(
        article_id=abs(hash(title)) % 10_000, title=title, url=f"http://x/{title}",
        feed_title=f"feed-{title}", feed_category=cat, published_at="2026-08-09T00:00:00Z",
        severity_score=score, cves=list(cves), iocs=list(iocs), actors=list(actors),
    )


def titles(summaries):
    return [s.title for s in summaries]


def test_sin_cves_no_fusiona_nada():
    a, b = mk("A", 5, []), mk("B", 4, [])
    assert titles(dedup_by_cves([a, b])) == ["A", "B"]


def test_fusiona_mismo_grupo_de_cves_y_gana_el_de_mayor_severidad():
    alta = mk("alta", 5, ["CVE-2026-1", "CVE-2026-2"])
    baja = mk("baja", 2, ["CVE-2026-1", "CVE-2026-2"])
    # El orden de entrada no manda: gana severity_score, no la posición.
    assert titles(dedup_by_cves([baja, alta])) == ["alta"]


def test_el_absorbido_le_deja_sus_iocs_y_actores_al_superviviente():
    alta = mk("alta", 5, ["CVE-2026-1", "CVE-2026-2"], iocs=["1.2.3.4"], actors=["APT99"])
    baja = mk("baja", 2, ["CVE-2026-1", "CVE-2026-2"], iocs=["5.6.7.8"], actors=["FIN7"])
    (superviviente,) = dedup_by_cves([alta, baja])
    assert sorted(superviviente.iocs) == ["1.2.3.4", "5.6.7.8"]
    assert sorted(superviviente.actors) == ["APT99", "FIN7"]


def test_un_solo_cve_compartido_no_alcanza():
    """min_shared=2 por defecto: una CVE en común es coincidencia, no la misma noticia."""
    a = mk("A", 5, ["CVE-2026-1", "CVE-2026-2"])
    b = mk("B", 4, ["CVE-2026-1", "CVE-2026-9"])
    assert titles(dedup_by_cves([a, b])) == ["A", "B"]


def test_jaccard_bajo_no_fusiona():
    """Comparten 2 CVEs pero el solapamiento es 2/12 = 0.17 < 0.4."""
    a = mk("A", 5, [f"CVE-2026-{i}" for i in range(10)])
    b = mk("B", 4, ["CVE-2026-0", "CVE-2026-1", "CVE-2026-98", "CVE-2026-99"])
    assert titles(dedup_by_cves([a, b])) == ["A", "B"]
    # Con el umbral relajado sí fusiona: la regla es el umbral, no los datos.
    assert titles(dedup_by_cves([a, b], min_jaccard=0.1)) == ["A"]


def test_no_absorbe_dos_veces_el_mismo_resumen():
    a = mk("A", 5, ["CVE-2026-1", "CVE-2026-2"])
    b = mk("B", 4, ["CVE-2026-1", "CVE-2026-2"])
    c = mk("C", 3, ["CVE-2026-1", "CVE-2026-2"])
    assert titles(dedup_by_cves([a, b, c])) == ["A"]


def test_preserva_el_orden_original_de_los_supervivientes():
    """Se recorre por severidad, pero la salida respeta el orden de entrada."""
    x = mk("X", 1, ["CVE-2026-7", "CVE-2026-8"])
    alta = mk("alta", 5, ["CVE-2026-1", "CVE-2026-2"])
    baja = mk("baja", 2, ["CVE-2026-1", "CVE-2026-2"])
    assert titles(dedup_by_cves([x, alta, baja])) == ["X", "alta"]


def test_tope_de_20_iocs_y_10_actores_al_fusionar():
    alta = mk("alta", 5, ["CVE-2026-1", "CVE-2026-2"],
              iocs=[f"1.1.1.{i}" for i in range(18)], actors=[f"A{i}" for i in range(9)])
    baja = mk("baja", 2, ["CVE-2026-1", "CVE-2026-2"],
              iocs=[f"2.2.2.{i}" for i in range(18)], actors=[f"B{i}" for i in range(9)])
    (superviviente,) = dedup_by_cves([alta, baja])
    assert len(superviviente.iocs) == 20
    assert len(superviviente.actors) == 10


def test_lista_vacia():
    assert dedup_by_cves([]) == []
