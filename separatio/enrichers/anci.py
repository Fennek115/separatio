"""
enrichers/anci.py — Alertas del CSIRT Nacional de Chile (ANCI).

La única fuente **estructurada** de intel local del pipeline: los feeds LATAM de
Miniflux traen prosa, esto trae IOCs tipados y CVEs con CVSS y EPSS ya
calculados, emitidos por el CSIRT nacional. El cliente HTTP, los modelos y los
cinco hallazgos medidos contra la API viven en `separatio/anci_client.py`; acá
está sólo qué se hace con ellos.

Aporta cuatro cosas:
  1. Notas de alertas publicadas en la ventana de lookback (código, tipo, título
     y un extracto). Alimentan sobre todo la fase LATAM, que desde F-I también
     recibe el bloque de enrichment.
  2. Veredictos: IOC del día que aparece **literal** en una alerta del corpus.
  3. Notas de correlación de CVEs — lo que más rinde: una alerta de Patch Tuesday
     de ANCI trae 500 CVEs y al informe sólo van las que se cruzan con lo que
     hablan los artículos de hoy, ordenadas por EPSS. Se apoya en
     `EnrichmentContext.cves`, que puebla `run_enrichment` desde los resúmenes.
  4. Notas de noticias del CSIRT en la ventana y de documentos nuevos (boletines,
     informes) detectados por diff contra la corrida anterior.

De paso deja el volcado local de IOCs en `data/feeds/` (CSV + listas por tipo),
que es dato operativo para consumir fuera del pipeline.

**Licencia CC BY-SA 4.0: la atribución es obligatoria.** `name` es ese texto y el
bloque de notas del prompt ya pide citar la fuente indicada.

**Las IPs de ANCI son las del alojamiento, no las del atacante.** Medido sobre
el volcado real del 2026-08-19: **17 de 42 IPs (40 %) son direcciones de borde de
Cloudflare**, porque la campaña de phishing está detrás del CDN. Por eso, cuando
una IP cruza, el enricher emite además **una nota de cautela**: el veredicto dice
"esta IP figura en una alerta", que es un hecho, y no "esta IP es maliciosa", que
no se sigue. Y por eso el volcado local **no es una blocklist para meter en un
firewall** sin mirarla.

Una decisión que parece omisión: **no se indexa el host de las URLs, sólo el
valor exacto.** En el corpus real hay alertas de phishing cuyo IOC es un
redirector abusado (`https://www.google.com/share.google?q=…`, en ACF26-01147) o
un hosting compartido (`*.cpanel.site`), así que cruzar por host emitiría
"google.com aparece en una alerta del CSIRT". El cruce exacto acierta poco pero
no miente.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from separatio import runlog
from separatio.anci_client import Alert, AnciClient, Vulnerability, export_iocs
from separatio.enrichment import (Enricher, EnrichmentContext, IocVerdict,
                                  normalize_ioc)

logger = logging.getLogger(__name__)

_WS_RE = re.compile(r"\s+")


def _clean(text: str | None, limit: int) -> str:
    """Colapsa espacios y recorta a `limit` caracteres."""
    if not text:
        return ""
    flat = _WS_RE.sub(" ", str(text)).strip()
    return flat if len(flat) <= limit else flat[:limit].rstrip() + "…"


class AnciEnricher(Enricher):
    name = "CSIRT Chile (ANCI)"

    def __init__(self, client: AnciClient | None = None, *,
                 lookback_hours: int = 26, corpus_days: int = 90,
                 max_notes: int = 10, max_cve_alerts: int = 5,
                 max_cves_per_alert: int = 8, max_news: int = 5,
                 doc_categories: tuple[str, ...] = ("boletines", "documentos"),
                 export_dir: str = "data/feeds", export: bool = True,
                 state_dir: str = "data/feeds/anci"):
        self.client = client or AnciClient()
        self.lookback_hours = lookback_hours
        self.corpus_days = corpus_days
        self.max_notes = max_notes
        self.max_cve_alerts = max_cve_alerts
        self.max_cves_per_alert = max_cves_per_alert
        self.max_news = max_news
        self.doc_categories = tuple(doc_categories or ())
        self.export_dir = export_dir
        self.export = export
        self.state_dir = Path(state_dir)

    # ── ENTRADA ───────────────────────────────────────────

    def enrich(self, iocs: dict[str, list[str]], ctx: EnrichmentContext) -> None:
        now = datetime.now(timezone.utc)
        corpus_cutoff = now - timedelta(days=self.corpus_days)
        window_cutoff = now - timedelta(hours=self.lookback_hours)

        alerts = self.client.alerts(since=corpus_cutoff)
        logger.debug(f"    ANCI: {len(alerts)} alertas publicadas en los últimos "
                     f"{self.corpus_days} días")
        if alerts:
            self._alert_notes(alerts, window_cutoff, ctx)
            self._cross_iocs(alerts, iocs, ctx)
            self._cross_cves(alerts, ctx)
            if self.export:
                try:
                    export_iocs(alerts, self.export_dir)
                except OSError as e:
                    logger.warning(f"    ANCI: no se pudo volcar los IOCs: {e}")

        self._news_notes(window_cutoff, ctx)
        self._document_notes(ctx)

    # ── ALERTAS ───────────────────────────────────────────

    def _alert_notes(self, alerts: list[Alert], cutoff: datetime,
                     ctx: EnrichmentContext) -> None:
        recent = [a for a in alerts
                  if (ts := a.published_at) is not None and ts >= cutoff]
        if not recent:
            return
        ctx.add_note(self.name,
                     f"{len(recent)} alerta(s) publicadas por el CSIRT Nacional de "
                     f"Chile en las últimas {self.lookback_hours}h "
                     f"(datos CC BY-SA 4.0, atribución obligatoria).")
        runlog.record_drop("enrichers.anci.alertas",
                           shown=min(self.max_notes, len(recent)), total=len(recent))
        for a in recent[:self.max_notes]:
            counts = []
            if a.iocs:
                counts.append(f"{len(a.iocs)} IOCs")
            if a.vulnerabilities:
                counts.append(f"{len(a.vulnerabilities)} CVEs")
            meta = f" ({', '.join(counts)})" if counts else ""
            desc = _clean(a.specific_description or a.general_description, 220)
            tail = f" — {desc}" if desc else ""
            ctx.add_note(self.name,
                         f"[{a.day}] {a.code or '?'} · {a.incident_type or '?'}: "
                         f"{_clean(a.title, 90)}{meta}{tail}")

    def _cross_iocs(self, alerts: list[Alert], iocs: dict[str, list[str]],
                    ctx: EnrichmentContext) -> None:
        """IOC del día que aparece literal en una alerta del corpus.

        Se normaliza con `enrichment.normalize_ioc` de los dos lados para que el
        defang y el lowercase sean exactamente los mismos."""
        if not iocs:
            return
        index: dict[str, tuple[Alert, str]] = {}
        for a in alerts:
            for ioc in a.crossable_iocs():
                value = normalize_ioc(ioc.value)
                if len(value) > 4:
                    index.setdefault(value, (a, ioc.kind))

        ips = 0
        for ioc in iocs:
            hit = index.get(ioc)
            if hit is None:
                continue
            a, kind = hit
            ips += kind == "ip"
            ctx.add(IocVerdict(
                ioc=ioc, kind=kind, source=self.name,
                label=f"figura en alerta del CSIRT chileno ({a.incident_type or '?'})",
                detail=f"{a.code or '?'} — {_clean(a.title, 70)} ({a.day})",
            ))
        if ips:
            # Sin esto el modelo lee "IP en alerta del CSIRT" como "IP maliciosa"
            # (el bloque de veredictos le pide tratarlos como reputación
            # verificada) y termina recomendando bloquear medio Cloudflare.
            ctx.add_note(self.name,
                         "Cautela con las IPs de ANCI: son las del ALOJAMIENTO del "
                         "sitio fraudulento, no las del atacante — medido, el 40% "
                         "son direcciones de borde de Cloudflare. Que una IP figure "
                         "en una alerta no la hace maliciosa por sí sola.")

    def _cross_cves(self, alerts: list[Alert], ctx: EnrichmentContext) -> None:
        """Alertas nacionales que cubren CVEs de los artículos de hoy.

        `ctx.cves` lo puebla `run_enrichment` desde los resúmenes de Stage 2; si
        nadie lo pobló (import suelto, test viejo) esta etapa no hace nada."""
        day_cves = {str(c).strip().upper() for c in getattr(ctx, "cves", set())}
        day_cves.discard("")
        if not day_cves:
            return

        hits: list[tuple[Alert, list[Vulnerability]]] = []
        for a in alerts:
            matched = [v for code, v in a.cve_map().items() if code in day_cves]
            if matched:
                # Lo más explotable primero; las que no traen EPSS, al final.
                matched.sort(key=lambda v: (v.epss_pct is not None,
                                            v.epss_pct or 0.0), reverse=True)
                hits.append((a, matched))
        if not hits:
            return

        hits.sort(key=lambda h: (len(h[1]), h[0].date), reverse=True)
        runlog.record_drop("enrichers.anci.cves",
                           shown=min(self.max_cve_alerts, len(hits)), total=len(hits))
        for a, matched in hits[:self.max_cve_alerts]:
            shown = matched[:self.max_cves_per_alert]
            listado = ", ".join(self._fmt_cve(v) for v in shown)
            resto = (f" (+{len(matched) - len(shown)} más)"
                     if len(matched) > len(shown) else "")
            ctx.add_note(self.name,
                         f"[{a.day}] {a.code or '?'} · {_clean(a.title, 90)}: "
                         f"alerta nacional que cubre {len(matched)} CVE(s) de los "
                         f"artículos de hoy — {listado}{resto}")

    @staticmethod
    def _fmt_cve(v: Vulnerability) -> str:
        partes = []
        if v.cvss:
            partes.append(f"CVSS {v.cvss}")
        if v.epss_pct is not None:
            partes.append(f"EPSS {v.epss_pct:.1f}%")
        return f"{v.code} ({', '.join(partes)})" if partes else v.code

    # ── NOTICIAS Y DOCUMENTOS ─────────────────────────────

    def _news_notes(self, cutoff: datetime, ctx: EnrichmentContext) -> None:
        if self.max_news <= 0:
            return
        try:
            news = self.client.news(since=cutoff)
        except Exception as e:
            # Las noticias son accesorias: que fallen no puede tirar la fuente
            # entera y perder las alertas, que son el 100% del valor.
            logger.warning(f"    ANCI: /news/ falló ({e}); se continúa sin noticias")
            return
        if not news:
            return
        runlog.record_drop("enrichers.anci.noticias",
                           shown=min(self.max_news, len(news)), total=len(news))
        for n in news[:self.max_news]:
            desc = _clean(n.body, 200)
            tail = f" — {desc}" if desc else ""
            ctx.add_note(self.name,
                         f"[{n.date[:10]}] Noticia ANCI: "
                         f"{_clean(n.title, 90)}{tail}")

    def _document_notes(self, ctx: EnrichmentContext) -> None:
        """Documentos nuevos (boletines, informes) por diff contra la corrida
        anterior: el esquema no trae fecha, así que no hay otra forma.

        La primera corrida sólo **fija la línea base** y no reporta nada: si no,
        el día que se prende la fuente el informe se llenaría con los 300
        documentos históricos."""
        if not self.doc_categories:
            return
        try:
            docs = self.client.documents(categories=self.doc_categories)
        except Exception as e:
            logger.warning(f"    ANCI: /documents/ falló ({e}); se continúa sin documentos")
            return
        if not docs:
            return

        state = self.state_dir / "documents-seen.json"
        known = self._load_seen(state)
        current = {d.key for d in docs if d.key}
        self._save_seen(state, current)
        if known is None:
            logger.info(f"    ANCI: línea base de documentos fijada "
                        f"({len(current)} conocidos); el diff empieza mañana")
            return

        nuevos = [d for d in docs if d.key and d.key not in known]
        if not nuevos:
            return
        runlog.record_drop("enrichers.anci.documentos",
                           shown=min(self.max_notes, len(nuevos)), total=len(nuevos))
        for d in nuevos[:self.max_notes]:
            desc = _clean(d.description, 160)
            tail = f" — {desc}" if desc else ""
            ctx.add_note(self.name,
                         f"Documento nuevo de ANCI ({d.root_category}): "
                         f"{_clean(d.title, 90)}{tail}")

    @staticmethod
    def _load_seen(path: Path) -> set[str] | None:
        """`None` = no hay línea base todavía (distinto de "no había ninguno")."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return set(data) if isinstance(data, list) else None

    @staticmethod
    def _save_seen(path: Path, keys: set[str]) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(sorted(keys), ensure_ascii=False),
                            encoding="utf-8")
        except OSError as e:
            logger.warning(f"    ANCI: no se pudo guardar {path}: {e}")
