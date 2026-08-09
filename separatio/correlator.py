"""
correlator.py — Stage 2.5: correlación entre fuentes sin inferencia LLM.

Cruza CVEs, actores y feeds para detectar hechos verificables:
  - CVEs mencionados en ≥2 fuentes independientes (corroborados)
  - CVEs en el catálogo KEV de CISA (explotados activamente en producción)
  - CVEs con PoC/exploit público confirmado (Exploit-DB, Sploitus, ZDI)
  - Actores de amenaza con actividad reportada en ≥2 fuentes

La correlación es determinista: coincidencia exacta de IDs, sin inferencia.
"""

from __future__ import annotations

import logging
import re
import requests
from collections import defaultdict

from separatio.net import get_with_retry
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from separatio.analyzer import ArticleSummary

logger = logging.getLogger(__name__)

# Feeds que señalan existencia de exploit/PoC — no contenido narrativo
_EXPLOIT_SIGNAL_FEEDS = frozenset({
    "Exploit-DB",
    "Sploitus",
    "Zero Day Initiative (ZDI) — Published",
})

# Valores de actor que indican "desconocido" — excluir de trending
_UNKNOWN_ACTORS = frozenset({
    "unknown", "desconocido", "no identificado", "n/a", "none",
    "sin identificar", "no aplica", "no identificados",
})


@dataclass
class CorrelationContext:
    """Correlaciones calculadas por código — hechos, no inferencias del LLM."""

    # CVE -> feeds donde se mencionó (solo CVEs con ≥2 fuentes distintas)
    corroborated_cves: dict[str, list[str]] = field(default_factory=dict)
    # CVEs presentes en el catálogo KEV de CISA
    kev_active_cves: list[str] = field(default_factory=list)
    # CVEs con PoC/exploit en feeds de señal
    poc_available_cves: list[str] = field(default_factory=list)
    # Actor -> feeds donde se mencionó (solo actores en ≥2 fuentes distintas)
    trending_actors: dict[str, list[str]] = field(default_factory=dict)
    # Todos los CVEs del día y sus fuentes (para la tabla de vulnerabilidades)
    all_cve_sources: dict[str, list[str]] = field(default_factory=dict)
    # CVE -> score EPSS (0.0–1.0) y percentil — obtenidos de FIRST.org
    epss_scores: dict[str, dict] = field(default_factory=dict)
    # IOC -> feeds donde se mencionó (solo IOCs en ≥2 fuentes distintas)
    corroborated_iocs: dict[str, list[str]] = field(default_factory=dict)
    # Técnica ATT&CK -> feeds (solo en ≥2 fuentes). Mismo patrón que los CVEs:
    # "T1566 mencionada por 4 medios distintos hoy" es un hecho verificable, no
    # una inferencia. Depende de `attack_techniques`, campo nuevo de F-I: con un
    # caché viejo el dict queda vacío y no se imprime nada.
    corroborated_techniques: dict[str, list[str]] = field(default_factory=dict)

    kev_fetch_ok: bool = False
    epss_fetch_ok: bool = False
    total_articles: int = 0

    # Bloques de texto extra inyectados por etapas posteriores (p.ej. Stage 2.7
    # enrichment externo). Se anexan al final de format_for_prompt() sin que
    # el correlator deba conocer su origen — mantiene desacople.
    extra_blocks: list[str] = field(default_factory=list)

    def has_signals(self) -> bool:
        return bool(
            self.corroborated_cves or self.kev_active_cves
            or self.poc_available_cves or self.trending_actors
            or self.corroborated_iocs or self.corroborated_techniques
            or self.extra_blocks
        )

    def format_for_prompt(self) -> str:
        """Devuelve el bloque de texto para inyectar en el prompt de Stage 3."""
        if not self.has_signals():
            return ""

        lines = [
            "CORRELACIONES VERIFICADAS",
            "(calculadas por coincidencia exacta de IDs entre fuentes — no son inferencias):",
            "",
        ]

        if self.kev_active_cves:
            kev_with_epss = []
            for cve in self.kev_active_cves:
                epss = self.epss_scores.get(cve)
                suffix = f" [EPSS {epss['epss']:.0%} — percentil {float(epss['percentile']):.0%}]" if epss else ""
                kev_with_epss.append(f"{cve}{suffix}")
            lines.append("  ★ EXPLOTADOS ACTIVAMENTE — CISA KEV: " + ", ".join(kev_with_epss))

        if self.corroborated_cves:
            lines.append("  ✓ CORROBORADOS en ≥2 fuentes independientes:")
            for cve, feeds in list(self.corroborated_cves.items())[:20]:
                epss = self.epss_scores.get(cve)
                epss_str = f" [EPSS {epss['epss']:.0%}]" if epss else ""
                lines.append(f"      {cve}{epss_str} → {' | '.join(feeds[:4])}")

        if self.poc_available_cves:
            poc_with_epss = []
            for cve in self.poc_available_cves[:20]:
                epss = self.epss_scores.get(cve)
                suffix = f" [EPSS {epss['epss']:.0%}]" if epss else ""
                poc_with_epss.append(f"{cve}{suffix}")
            lines.append("  [PoC] EXPLOIT PÚBLICO CONFIRMADO: " + ", ".join(poc_with_epss))

        if self.trending_actors:
            lines.append("  ACTORES EN TENDENCIA (>=2 fuentes):")
            for actor, feeds in list(self.trending_actors.items())[:10]:
                lines.append(f"      {actor} → {' | '.join(feeds[:4])}")

        if self.corroborated_iocs:
            lines.append("  IOCs CORROBORADOS en >=2 fuentes independientes:")
            for ioc, feeds in list(self.corroborated_iocs.items())[:20]:
                lines.append(f"      {ioc} → {' | '.join(feeds[:4])}")

        if self.corroborated_techniques:
            lines.append("  TÉCNICAS ATT&CK CORROBORADAS en >=2 fuentes independientes:")
            for tech, feeds in list(self.corroborated_techniques.items())[:15]:
                lines.append(f"      {tech} ({len(set(feeds))} fuentes) → {' | '.join(feeds[:4])}")

        lines += [
            "",
            "REGLA: Usa estas correlaciones como hechos verificados en el informe.",
            "NO inferir ni especular conexiones adicionales no listadas aquí.",
        ]
        for block in self.extra_blocks:
            if block:
                lines += ["", block]
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────

def _normalize_cve(raw: str) -> str:
    return raw.upper().strip()


def _is_valid_cve(cve: str) -> bool:
    return bool(re.match(r"^CVE-\d{4}-\d{4,}$", cve))


def _normalize_ioc(raw: str) -> str:
    """Normaliza IOCs defangeados para que la correlación cruce correctamente.

    evil[.]com  → evil.com
    1.2.3[.]4   → 1.2.3.4
    evil[dot]com → evil.com
    hxxp://      → http://
    hxxps://     → https://
    """
    ioc = raw.strip()
    ioc = re.sub(r"\[\.\]", ".", ioc)
    ioc = re.sub(r"\[dot\]", ".", ioc, flags=re.IGNORECASE)
    ioc = re.sub(r"^hxxps?://", lambda m: m.group().replace("hxx", "htt"), ioc, flags=re.IGNORECASE)
    return ioc.lower()


_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _normalize_technique(raw: str) -> str:
    """`t1566.001 — Phishing` → `T1566.001`. Devuelve "" si no es un ID válido:
    el modelo a veces escribe el nombre de la técnica en vez del ID, y un nombre
    no cruza entre fuentes."""
    tech = (raw or "").strip().upper()
    tech = re.split(r"[\s:—–-]", tech, maxsplit=1)[0].strip()
    return tech if _TECHNIQUE_RE.match(tech) else ""


def _dedup(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


# ─────────────────────────────────────────────────────────
# FUNCIÓN PRINCIPAL
# ─────────────────────────────────────────────────────────

def build_correlation_context(
    summaries: list[ArticleSummary],
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    epss_url: str = "https://api.first.org/data/v1/epss",
    kev_timeout: int = 15,
) -> CorrelationContext:
    """
    Construye el contexto de correlación a partir de los ArticleSummary de Stage 2.
    No invoca ningún LLM — toda la lógica es determinista.
    """
    ctx = CorrelationContext(total_articles=len(summaries))

    cve_map: dict[str, list[str]] = defaultdict(list)
    actor_map: dict[str, list[str]] = defaultdict(list)
    exploit_cves: set[str] = set()

    for s in summaries:
        is_exploit_feed = s.feed_title in _EXPLOIT_SIGNAL_FEEDS

        for raw in s.cves:
            cve = _normalize_cve(raw)
            if not _is_valid_cve(cve):
                continue
            cve_map[cve].append(s.feed_title)
            if is_exploit_feed:
                exploit_cves.add(cve)

        for actor in s.actors:
            actor = actor.strip()
            if actor and actor.lower() not in _UNKNOWN_ACTORS:
                actor_map[actor].append(s.feed_title)

    ctx.all_cve_sources = {cve: _dedup(feeds) for cve, feeds in cve_map.items()}

    ctx.corroborated_cves = {
        cve: _dedup(feeds)
        for cve, feeds in cve_map.items()
        if len(set(feeds)) >= 2
    }

    ctx.poc_available_cves = sorted(exploit_cves)

    ctx.trending_actors = {
        actor: _dedup(feeds)
        for actor, feeds in actor_map.items()
        if len(set(feeds)) >= 2
    }

    # ── IOC correlation ──────────────────────────────────
    ioc_map: dict[str, list[str]] = defaultdict(list)
    for s in summaries:
        for raw_ioc in s.iocs:
            ioc = _normalize_ioc(raw_ioc)
            if ioc and len(ioc) > 4:   # descartar valores triviales
                ioc_map[ioc].append(s.feed_title)
    ctx.corroborated_iocs = {
        ioc: _dedup(feeds)
        for ioc, feeds in ioc_map.items()
        if len(set(feeds)) >= 2
    }

    # ── Técnicas ATT&CK (F-I) ────────────────────────────
    tech_map: dict[str, list[str]] = defaultdict(list)
    for s in summaries:
        for raw_tech in getattr(s, "attack_techniques", None) or []:
            tech = _normalize_technique(raw_tech)
            if tech:
                tech_map[tech].append(s.feed_title)
    ctx.corroborated_techniques = {
        tech: _dedup(feeds)
        for tech, feeds in tech_map.items()
        if len(set(feeds)) >= 2
    }

    # ── CISA KEV lookup ──────────────────────────────────
    logger.info("  Consultando CISA KEV...")
    try:
        resp = get_with_retry(kev_url, timeout=kev_timeout)
        resp.raise_for_status()
        kev_ids = {
            v["cveID"].upper()
            for v in resp.json().get("vulnerabilities", [])
        }
        ctx.kev_active_cves = sorted(cve for cve in cve_map if cve in kev_ids)
        ctx.kev_fetch_ok = True
        logger.info(
            f"  KEV: {len(kev_ids)} entradas — "
            f"{len(ctx.kev_active_cves)} coincidencias con los CVEs del día"
        )
    except Exception as e:
        logger.warning(f"  CISA KEV no disponible: {e}")

    # ── EPSS lookup (FIRST.org) ──────────────────────────
    all_cves = list(cve_map.keys())
    if all_cves:
        logger.info(f"  Consultando EPSS para {len(all_cves)} CVEs...")
        try:
            # API acepta hasta ~500 CVEs por request en el parámetro cve
            chunk_size = 400
            epss_data: dict[str, dict] = {}
            for i in range(0, len(all_cves), chunk_size):
                chunk = all_cves[i : i + chunk_size]
                params = {"cve": ",".join(chunk), "scope": "time-series"}
                r = get_with_retry(
                    epss_url,
                    params={"cve": ",".join(chunk)},
                    timeout=kev_timeout,
                )
                r.raise_for_status()
                for entry in r.json().get("data", []):
                    cve_id = entry["cve"].upper()
                    epss_data[cve_id] = {
                        "epss": float(entry["epss"]),
                        "percentile": float(entry["percentile"]),
                    }
            ctx.epss_scores = epss_data
            ctx.epss_fetch_ok = True
            high_epss = sum(1 for v in epss_data.values() if v["epss"] >= 0.5)
            logger.info(
                f"  EPSS: {len(epss_data)} scores obtenidos — "
                f"{high_epss} con probabilidad ≥50%"
            )
        except Exception as e:
            logger.warning(f"  EPSS no disponible: {e}")

    logger.info(
        f"  Correlaciones: {len(cve_map)} CVEs únicos | "
        f"{len(ctx.corroborated_cves)} corroborados | "
        f"{len(ctx.poc_available_cves)} con PoC | "
        f"{len(ctx.trending_actors)} actores en tendencia | "
        f"{len(ctx.corroborated_iocs)} IOCs corroborados | "
        f"{len(ctx.corroborated_techniques)} técnicas ATT&CK corroboradas"
    )
    return ctx
