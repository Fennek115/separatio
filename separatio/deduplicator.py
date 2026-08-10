"""
deduplicator.py — Deduplicación semántica de resúmenes (post Stage 2).

Salió de `pipeline.py` en F-G/G-3. La misma noticia entra por varios feeds y el
dedup por URL de Stage 1 no la agarra (URLs distintas, mismo hecho); lo que sí
es estable entre publicaciones es el grupo de CVEs del que hablan.

Determinista, sin LLM y sin red.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from separatio.analyzer import ArticleSummary

logger = logging.getLogger(__name__)


def dedup_by_cves(
    summaries: list["ArticleSummary"],
    min_shared: int = 2,
    min_jaccard: float = 0.4,
) -> list["ArticleSummary"]:
    """Fusiona resúmenes que cubren el mismo grupo de CVEs.

    Gana el de mayor `severity_score` (se recorre en ese orden) y absorbe los
    IOCs y actores del otro; el absorbido desaparece de la lista.
    """
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
