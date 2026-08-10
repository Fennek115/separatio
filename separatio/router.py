"""
router.py — Ruteo de artículos y de contexto a las fases del informe.

Salió de `pipeline.py` en F-G/G-3. Responde dos preguntas que antes estaban
repartidas entre `group_by_phase()` y tres puntos sueltos de `stage3_phases()` /
`stage4_synthesis()`:

  1. **Qué artículo va a qué fase** — por la categoría de Miniflux, vía
     `PHASE_CATEGORY_MAP`. Categoría no mapeada → `general`, así que agregar un
     feed en Miniflux no pide tocar código.
  2. **Qué contexto recibe cada fase** — la correlación KEV/EPSS sólo llega a
     `vulnerability` y `threat_intel` (en LATAM y general un listado de CVEs en
     KEV es ruido); el trending, sólo a `threat_intel`. El *enrichment* no está
     acá a propósito: desde F-I va a las cuatro fases, sin ruteo.

Sin LLM, sin red y sin estado. `cat_map=None` cae a `config.PHASE_CATEGORY_MAP`
(mismo patrón que `hygiene.build_classifier`), que es lo que permite testearlo
sin montar config.
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from separatio.analyzer import ArticleSummary

# Orden canónico del informe. Las claves extra de PHASE_CATEGORY_MAP se agregan
# después de éstas (ver `phase_order`), pero el ensamblado final de Stage 4 sólo
# arma con las canónicas.
CANONICAL_PHASES = ("vulnerability", "threat_intel", "latam", "general")

# Fases que reciben CorrelationContext (KEV/EPSS y CVEs corroborados).
CORRELATED_PHASES = ("vulnerability", "threat_intel")

# Fases que reciben TrendingContext (histórico de N días).
TRENDING_PHASES = ("threat_intel",)


def _cat_map(cat_map: dict | None) -> dict:
    if cat_map is not None:
        return cat_map
    from separatio import config
    return getattr(config, "PHASE_CATEGORY_MAP", {}) or {}


def group_by_phase(
    summaries: list["ArticleSummary"],
    cat_map: dict | None = None,
) -> dict[str, list["ArticleSummary"]]:
    """Agrupa resúmenes por fase según PHASE_CATEGORY_MAP.

    Categorías no mapeadas → 'general' automáticamente.
    """
    mapping = _cat_map(cat_map)
    cat_to_phase: dict[str, str] = {
        cat.lower(): phase
        for phase, cats in mapping.items()
        for cat in cats
    }
    phases: dict[str, list["ArticleSummary"]] = defaultdict(list)
    for s in summaries:
        phase = cat_to_phase.get(s.feed_category.lower(), "general")
        phases[phase].append(s)
    return dict(phases)


def phase_order(cat_map: dict | None = None) -> list[str]:
    """Orden de generación: las canónicas primero, las extra de config al final."""
    canonical = list(CANONICAL_PHASES)
    extra = [p for p in _cat_map(cat_map) if p not in canonical]
    return canonical + extra


def receives_correlation(phase: str) -> bool:
    return phase in CORRELATED_PHASES


def receives_trending(phase: str) -> bool:
    return phase in TRENDING_PHASES
