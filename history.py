"""
history.py — Stage 2.6: registro histórico y trending de amenazas.

Mantiene reports/history.json con un registro compacto por día (~200 bytes).
A 365 días/año el archivo pesa ~73KB — nunca se necesita rotar.

Lo que ve el LLM en Stage 3 es siempre un bloque compacto de ventana fija
(últimos TREND_WINDOW_DAYS días), independientemente de cuántos meses lleve
corriendo el pipeline.
"""

from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from analyzer import ArticleSummary
    from correlator import CorrelationContext

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────
# TIPO DE DATOS
# ─────────────────────────────────────────────────────────

@dataclass
class TrendingContext:
    window_days: int
    days_with_data: int
    # actor -> cantidad de días en que apareció dentro de la ventana (≥2)
    returning_actors: dict[str, int] = field(default_factory=dict)
    # actores vistos hoy que NO aparecieron en la ventana previa
    new_actors: list[str] = field(default_factory=list)
    # cve -> cantidad de días en que apareció dentro de la ventana (≥2)
    recurring_cves: dict[str, int] = field(default_factory=dict)
    # tipo -> delta % respecto a la media de la ventana (solo cambios ≥20%)
    threat_type_delta: dict[str, float] = field(default_factory=dict)

    def has_data(self) -> bool:
        return self.days_with_data > 0

    def format_for_prompt(self) -> str:
        if not self.has_data():
            return ""

        lines = [
            f"CONTEXTO HISTÓRICO (últimos {self.window_days} días — "
            f"{self.days_with_data} días con datos):",
        ]

        if self.returning_actors:
            top = sorted(self.returning_actors.items(), key=lambda x: -x[1])[:8]
            actors_str = ", ".join(f"{a} ({d}d)" for a, d in top)
            lines.append(f"  Actores persistentes (activos en ≥2 días): {actors_str}")

        if self.new_actors:
            lines.append(f"  Actores nuevos hoy (no vistos en {self.window_days} días): "
                         + ", ".join(self.new_actors[:8]))

        if self.recurring_cves:
            top = sorted(self.recurring_cves.items(), key=lambda x: -x[1])[:6]
            cves_str = ", ".join(f"{c} ({d}d)" for c, d in top)
            lines.append(f"  CVEs recurrentes (mencionados en ≥2 días): {cves_str}")

        if self.threat_type_delta:
            changes = []
            for t, delta in sorted(self.threat_type_delta.items(), key=lambda x: -abs(x[1])):
                arrow = "↑" if delta > 0 else "↓"
                changes.append(f"{t} {arrow}{abs(delta):.0f}%")
            lines.append(f"  Tendencia vs. media de ventana: " + " | ".join(changes[:5]))

        lines.append("  (usa este contexto para distinguir amenazas emergentes de persistentes)")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────
# LECTURA / ESCRITURA
# ─────────────────────────────────────────────────────────

def load_history(history_path: str) -> dict:
    """Carga el historial desde disco. Retorna {} si no existe."""
    p = Path(history_path)
    if not p.exists():
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"No se pudo leer el historial: {e}")
        return {}


def save_history(history: dict, history_path: str) -> None:
    Path(history_path).parent.mkdir(parents=True, exist_ok=True)
    with open(history_path, "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, indent=2)


def append_daily_record(
    history: dict,
    date_str: str,
    summaries: list[ArticleSummary],
    correlation: CorrelationContext | None = None,
) -> dict:
    """
    Añade o reemplaza el registro del día. Almacena solo datos agregados,
    no artículos individuales.
    """
    actors: list[str] = []
    cves: list[str] = []
    threat_type_counts: dict[str, int] = {}
    ioc_count = 0

    for s in summaries:
        actors.extend(s.actors)
        cves.extend(s.cves)
        ioc_count += len(s.iocs)
        t = s.threat_type
        if t:
            threat_type_counts[t] = threat_type_counts.get(t, 0) + 1

    history[date_str] = {
        "actors":        sorted(set(actors)),
        "cves":          sorted(set(cves)),
        "threat_types":  threat_type_counts,
        "article_count": len(summaries),
        "ioc_count":     ioc_count,
        "kev_hits":      list(correlation.kev_active_cves) if correlation else [],
    }
    return history


# ─────────────────────────────────────────────────────────
# ANÁLISIS DE TENDENCIAS
# ─────────────────────────────────────────────────────────

def build_trending_context(
    history: dict,
    today_str: str,
    window_days: int = 14,
) -> TrendingContext:
    """
    Calcula el contexto de trending a partir de la ventana de los últimos
    window_days días (sin incluir hoy, para comparar contra el pasado).
    """
    ctx = TrendingContext(window_days=window_days, days_with_data=0)

    today = _parse_date(today_str)
    if today is None:
        return ctx

    # Ventana: desde (today - window_days) hasta ayer, ambos inclusive
    window_dates = {
        str(today - timedelta(days=i))
        for i in range(1, window_days + 1)
    }
    window_records = {d: history[d] for d in window_dates if d in history}
    ctx.days_with_data = len(window_records)

    if not window_records:
        return ctx

    today_record = history.get(today_str, {})
    today_actors = set(today_record.get("actors", []))
    today_cves   = set(today_record.get("cves", []))

    # ── Actores ──────────────────────────────────────────
    actor_day_count: dict[str, int] = defaultdict(int)
    for rec in window_records.values():
        for actor in rec.get("actors", []):
            actor_day_count[actor] += 1

    ctx.returning_actors = {
        a: count
        for a, count in actor_day_count.items()
        if count >= 2
    }

    # Actores nuevos: en el registro de hoy pero no en ningún día de la ventana
    seen_in_window = set(actor_day_count.keys())
    ctx.new_actors = sorted(today_actors - seen_in_window)

    # ── CVEs recurrentes ─────────────────────────────────
    cve_day_count: dict[str, int] = defaultdict(int)
    for rec in window_records.values():
        for cve in rec.get("cves", []):
            cve_day_count[cve] += 1

    ctx.recurring_cves = {
        c: count
        for c, count in cve_day_count.items()
        if count >= 2 and c in today_cves  # solo los que también están hoy
    }

    # ── Tendencia de tipos de amenaza ────────────────────
    today_types = Counter(today_record.get("threat_types", {}))
    today_total = sum(today_types.values()) or 1

    window_type_totals: dict[str, list[int]] = defaultdict(list)
    for rec in window_records.values():
        day_total = sum(rec.get("threat_types", {}).values()) or 1
        for t, count in rec.get("threat_types", {}).items():
            # Normalizar como porcentaje del día para comparar días con distinto volumen
            window_type_totals[t].append(count / day_total * 100)

    deltas: dict[str, float] = {}
    for t, daily_pcts in window_type_totals.items():
        window_avg = sum(daily_pcts) / len(daily_pcts)
        today_pct  = today_types.get(t, 0) / today_total * 100
        if window_avg > 0:
            delta = (today_pct - window_avg) / window_avg * 100
            if abs(delta) >= 20:   # solo cambios significativos
                deltas[t] = round(delta, 1)

    ctx.threat_type_delta = deltas
    return ctx


# ─────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────

def _parse_date(date_str: str) -> date | None:
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y"):
        try:
            return date.fromisoformat(date_str) if fmt == "%Y-%m-%d" \
                else date(*[int(x) for x in date_str.replace("/", "-").split("-")][::-1])
        except ValueError:
            continue
    logger.warning(f"No se pudo parsear fecha: {date_str!r}")
    return None
