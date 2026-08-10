"""Tests del ruteo por fases (F-G/G-3) — sin red, con `cat_map` inyectado.

El `cat_map=None` cae a `config.PHASE_CATEGORY_MAP`; acá se pasa explícito para
que los tests no dependan de la config real (mismo patrón que `hygiene`).
"""

from separatio.analyzer import ArticleSummary
from separatio.router import (
    CANONICAL_PHASES, CORRELATED_PHASES, TRENDING_PHASES,
    group_by_phase, phase_order, receives_correlation, receives_trending,
)

CAT_MAP = {
    "vulnerability": ["Vulnerability"],
    "threat_intel":  ["Threat Intel", "Hacking & Research"],
    "latam":         ["LATAM"],
    "general":       ["Cibersecurity"],
}


def mk(title, cat):
    return ArticleSummary(
        article_id=abs(hash(title)) % 10_000, title=title, url=f"http://x/{title}",
        feed_title=f"feed-{title}", feed_category=cat,
        published_at="2026-08-09T00:00:00Z",
    )


def reparto(summaries, cat_map=CAT_MAP):
    return {k: [s.title for s in v] for k, v in group_by_phase(summaries, cat_map).items()}


# ── agrupación ──────────────────────────────────────────────

def test_agrupa_por_categoria_de_miniflux():
    assert reparto([mk("A", "Vulnerability"), mk("B", "LATAM")]) == {
        "vulnerability": ["A"], "latam": ["B"]}


def test_varias_categorias_caen_en_la_misma_fase():
    assert reparto([mk("A", "Threat Intel"), mk("B", "Hacking & Research")]) == {
        "threat_intel": ["A", "B"]}


def test_categoria_no_mapeada_cae_en_general():
    """Agregar un feed en Miniflux no tiene que pedir un cambio de código."""
    assert reparto([mk("A", "Categoría Nueva")]) == {"general": ["A"]}


def test_el_match_de_categoria_ignora_mayusculas():
    assert reparto([mk("A", "vulnerability"), mk("B", "VULNERABILITY")]) == {
        "vulnerability": ["A", "B"]}


def test_fase_sin_articulos_no_aparece():
    assert "latam" not in reparto([mk("A", "Vulnerability")])


def test_sin_resumenes_no_hay_fases():
    assert group_by_phase([], CAT_MAP) == {}


def test_conserva_el_orden_dentro_de_cada_fase():
    arts = [mk(str(i), "Vulnerability") for i in range(5)]
    assert reparto(arts)["vulnerability"] == ["0", "1", "2", "3", "4"]


# ── orden de fases ──────────────────────────────────────────

def test_phase_order_arranca_por_las_canonicas():
    assert phase_order(CAT_MAP) == list(CANONICAL_PHASES)


def test_las_fases_extra_de_config_van_al_final():
    assert phase_order({**CAT_MAP, "ot": ["ICS"]}) == list(CANONICAL_PHASES) + ["ot"]


def test_una_canonica_ausente_de_config_sigue_en_el_orden():
    """El orden canónico no depende de que config la mencione."""
    assert phase_order({"vulnerability": ["Vulnerability"]}) == list(CANONICAL_PHASES)


# ── ruteo de contexto ───────────────────────────────────────

def test_solo_vulnerability_y_threat_intel_reciben_correlacion():
    assert [p for p in CANONICAL_PHASES if receives_correlation(p)] == list(CORRELATED_PHASES)
    assert not receives_correlation("latam") and not receives_correlation("general")


def test_solo_threat_intel_recibe_trending():
    assert [p for p in CANONICAL_PHASES if receives_trending(p)] == list(TRENDING_PHASES)


def test_una_fase_extra_no_recibe_ningun_contexto():
    assert not receives_correlation("ot") and not receives_trending("ot")
