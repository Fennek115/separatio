"""
enrichment.py — Stage 2.7: capa de enriquecimiento externo de IOCs.

Capa de plugins desacoplada. Cada enricher cruza los IOCs extraídos por el LLM
(Stage 2) contra una fuente externa de threat intelligence y agrega hechos
verificables al EnrichmentContext. Dos familias de enrichers:

  1. Feeds planos sin API key (patrón del correlator): se descarga una lista
     (IPsum, OpenPhish, Bambenek…) una vez por run y se cruza por coincidencia
     exacta. Determinista, rápido, sin cuota.
  2. APIs por-IOC con key y rate-limit (p.ej. ipcheck/AbuseIPDB/VT/GreyNoise):
     más caras y lentas; off por defecto.

El resultado se inyecta en el prompt de Stage 3 anexándolo al CorrelationContext,
de modo que no hay que tocar las firmas de analyzer.py. Toda la etapa está
envuelta en try/except en el pipeline: un fallo de enrichment nunca rompe el run.
"""

from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from separatio import runlog

if TYPE_CHECKING:
    from separatio.analyzer import ArticleSummary

logger = logging.getLogger(__name__)

# Veredictos por fuente que entran al prompt. El tope real vive en
# config.PROMPT_CAPS["verdicts_per_source"] (F-I); éste es el piso si config no
# está disponible (import suelto, tests que no cargan config).
DEFAULT_PROMPT_CAP = 60


def _default_cap() -> int:
    try:
        from separatio import config
        return int((getattr(config, "PROMPT_CAPS", {}) or {})
                   .get("verdicts_per_source", DEFAULT_PROMPT_CAP))
    except Exception:
        return DEFAULT_PROMPT_CAP

# Detección mínima de tipo de IOC, para decidir a qué enricher mandar cada IOC.
# NO es la misma que `ioc_processor.detect_ioc_type` (la que etiqueta las filas
# de iocs.csv): ésta colapsa los tres hashes en "hash" y asume el IOC ya
# normalizado por normalize_ioc(). Las diferencias están tabuladas en el
# docstring de ioc_processor.py — se dejaron separadas a propósito (F-G/G-3).
_IP_RE     = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$")


def normalize_ioc(raw: str) -> str:
    """Defang inverso + lowercase, igual que el correlator."""
    ioc = raw.strip()
    ioc = re.sub(r"\[\.\]", ".", ioc)
    ioc = re.sub(r"\[dot\]", ".", ioc, flags=re.IGNORECASE)
    ioc = re.sub(r"^hxxps?://", lambda m: m.group().replace("hxx", "htt"), ioc, flags=re.IGNORECASE)
    return ioc.strip().lower()


def ioc_kind(ioc: str) -> str:
    """ip | domain | url | hash | other (sobre el IOC ya normalizado)."""
    v = ioc.strip()
    if _IP_RE.match(v.split(":")[0]):
        return "ip"
    if v.startswith(("http://", "https://")):
        return "url"
    if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", v):
        return "hash"
    if _DOMAIN_RE.match(v):
        return "domain"
    return "other"


def collect_iocs(summaries: list["ArticleSummary"]) -> dict[str, list[str]]:
    """Mapa ioc_normalizado -> feeds donde apareció (deduplicado por feed)."""
    out: dict[str, list[str]] = {}
    for s in summaries:
        for raw in getattr(s, "iocs", []):
            ioc = normalize_ioc(raw)
            if len(ioc) <= 4:
                continue
            out.setdefault(ioc, [])
            if s.feed_title not in out[ioc]:
                out[ioc].append(s.feed_title)
    return out


# ─────────────────────────────────────────────────────────
# CONTEXTO DE ENRICHMENT
# ─────────────────────────────────────────────────────────

@dataclass
class IocVerdict:
    """Veredicto de una fuente externa sobre un IOC concreto."""
    ioc: str
    kind: str            # ip | domain | url | hash
    source: str          # nombre del enricher (IPsum, ipcheck, OpenPhish…)
    label: str           # etiqueta corta de riesgo/clasificación
    detail: str = ""     # texto humano-legible adicional
    score: float | None = None


@dataclass
class EnrichmentContext:
    """Hechos de enrichment externo acumulados por los enrichers de Stage 2.7."""
    verdicts: list[IocVerdict] = field(default_factory=list)
    # Hechos de fuentes externas NO ligados a un IOC de los artículos (p.ej.
    # víctimas nuevas en leak sites). Van al prompt de Stage 3 pero no al
    # export de IOCs: (fuente, línea de texto).
    notes: list[tuple[str, str]] = field(default_factory=list)
    sources_ok: list[str] = field(default_factory=list)
    sources_failed: list[str] = field(default_factory=list)

    def add(self, verdict: IocVerdict) -> None:
        self.verdicts.append(verdict)

    def add_note(self, source: str, text: str) -> None:
        self.notes.append((source, text))

    def has_signals(self) -> bool:
        return bool(self.verdicts) or bool(self.notes)

    def malicious_iocs(self) -> list[IocVerdict]:
        return self.verdicts

    def format_for_prompt(self, cap: int | None = None) -> str:
        """Bloque de texto de enrichment para el prompt de Stage 3.

        `cap` es el máximo de veredictos por fuente que entran al prompt: lo que
        exceda se registra como Drop y se declara en el bloque de cobertura.
        None → el tope de `config.PROMPT_CAPS`, resuelto en cada llamada."""
        if cap is None:
            cap = _default_cap()
        if not self.verdicts and not self.notes:
            return ""
        lines: list[str] = []
        if self.verdicts:
            lines += [
                "ENRICHMENT EXTERNO DE IOCs",
                "(IOCs del día cruzados contra fuentes externas de reputación — hechos, no inferencias):",
                "",
            ]
            # Agrupar por fuente para legibilidad
            by_source: dict[str, list[IocVerdict]] = {}
            for v in self.verdicts:
                by_source.setdefault(v.source, []).append(v)
            for source, items in by_source.items():
                lines.append(f"  ▸ {source}:")
                runlog.record_drop("enrichment.format_for_prompt",
                                   shown=min(cap, len(items)), total=len(items),
                                   detail=source)
                for v in items[:cap]:
                    score = f" [{v.score:.0%}]" if isinstance(v.score, float) else ""
                    detail = f" — {v.detail}" if v.detail else ""
                    lines.append(f"      {v.ioc} ({v.kind}) → {v.label}{score}{detail}")
            lines += [
                "",
                "REGLA: trata estos veredictos como reputación verificada de los IOCs.",
            ]
        if self.notes:
            if lines:
                lines.append("")
            lines += [
                "ACTIVIDAD EXTERNA DEL DÍA",
                "(hechos observados en fuentes externas, no ligados a artículos de los feeds;",
                " si se usan en el informe, citar la fuente indicada):",
                "",
            ]
            by_src: dict[str, list[str]] = {}
            for source, text in self.notes:
                by_src.setdefault(source, []).append(text)
            for source, items in by_src.items():
                lines.append(f"  ▸ Source: {source}")
                for text in items:
                    lines.append(f"      {text}")
        return "\n".join(lines)

    def export_rows(self) -> list[dict]:
        """Filas planas para enriquecer el export de IOCs (CSV/JSON)."""
        return [
            {
                "ioc": v.ioc, "type": v.kind, "source": v.source,
                "label": v.label, "score": v.score, "detail": v.detail,
            }
            for v in self.verdicts
        ]


# ─────────────────────────────────────────────────────────
# CONTRATO DE ENRICHER (plugin)
# ─────────────────────────────────────────────────────────

class Enricher(ABC):
    """Plugin de enrichment. Implementar `name` y `enrich`.

    `enrich` recibe el mapa de IOCs (normalizado -> feeds) y el contexto que
    debe poblar con IocVerdict. Debe ser tolerante a fallos: cualquier excepción
    se captura en run_enrichment y marca la fuente como fallida sin abortar."""

    name: str = "enricher"

    @abstractmethod
    def enrich(self, iocs: dict[str, list[str]], ctx: EnrichmentContext) -> None:
        ...


def run_enrichment(
    summaries: list["ArticleSummary"],
    enrichers: list[Enricher],
) -> EnrichmentContext:
    """Ejecuta los enrichers habilitados sobre los IOCs de los resúmenes.
    Cada enricher se aísla: su fallo se registra pero no detiene a los demás."""
    ctx = EnrichmentContext()
    iocs = collect_iocs(summaries)
    if not iocs:
        logger.info("  Enrichment: no hay IOCs para enriquecer")
        return ctx

    logger.info(f"  Enrichment: {len(iocs)} IOCs únicos | {len(enrichers)} fuentes activas")
    for enricher in enrichers:
        try:
            before = len(ctx.verdicts)
            enricher.enrich(iocs, ctx)
            found = len(ctx.verdicts) - before
            ctx.sources_ok.append(enricher.name)
            runlog.record_source(enricher.name, "ok")
            logger.info(f"    [{enricher.name}] {found} veredictos")
        except Exception as e:
            ctx.sources_failed.append(enricher.name)
            runlog.record_source(enricher.name, f"failed: {type(e).__name__}: {e}")
            runlog.record_failure(f"enricher:{enricher.name}", e)
            logger.warning(f"    [{enricher.name}] falló: {e}")
    return ctx
