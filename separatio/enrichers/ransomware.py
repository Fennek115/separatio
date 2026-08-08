"""
enrichers/ransomware.py — Actividad de leak sites de ransomware vía Ransomware.live.

Ransomware.live scrapea los leak sites .onion y sirve el resultado por HTTPS
clearnet: el pipeline nunca toca Tor ni un leak site. Una sola llamada por run
a /v2/recentvictims (el free tier aplica 1 req/min por endpoint de verdad, y
los ToS prohíben evadirlo con reintentos — por eso acá NO se usa net.py).

Aporta dos cosas:
  1. Notas de contexto: víctimas publicadas en la ventana de lookback, para la
     síntesis de Stage 3 (grupo, víctima, país, sector). No entran al export
     de IOCs.
  2. Veredictos: cruce del dominio de cada víctima contra los IOCs del día.

Obligaciones (licencia de datos no comercial con atribución + GDPR):
  - El informe debe citar "Source: Ransomware.live" (el bloque de prompt lo pide).
  - NUNCA guardar ni propagar `screenshot` (capturas con datos personales de
    víctimas), `claim_url` (.onion) ni `infostealer`. Solo metadatos.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import requests

from separatio.enrichment import Enricher, EnrichmentContext, IocVerdict

logger = logging.getLogger(__name__)

# Campos que se conservan de cada víctima. Todo lo demás (screenshot,
# claim_url, infostealer, press…) se descarta en el parseo.
_KEEP = ("victim", "group", "discovered", "attackdate", "country", "activity", "domain")


class RansomwareLiveEnricher(Enricher):
    name = "Ransomware.live"

    def __init__(self, url: str, lookback_hours: int = 26,
                 max_victims: int = 15, timeout: int = 20):
        self.url = url
        self.lookback_hours = lookback_hours
        self.max_victims = max_victims
        self.timeout = timeout

    def _fetch(self) -> list[dict]:
        """Una llamada, sin reintentos: un 429 marca la fuente como fallida."""
        resp = requests.get(
            self.url,
            headers={"User-Agent": "separatio-pipeline (homelab CTI)"},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, list):
            raise ValueError(f"respuesta inesperada: {type(data).__name__}")
        return [{k: v for k, v in item.items() if k in _KEEP} for item in data]

    @staticmethod
    def _parse_ts(value) -> datetime | None:
        if not value or not isinstance(value, str):
            return None
        try:
            ts = datetime.fromisoformat(value)
        except ValueError:
            return None
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)

    def enrich(self, iocs: dict[str, list[str]], ctx: EnrichmentContext) -> None:
        victims = self._fetch()
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.lookback_hours)
        recent = [v for v in victims
                  if (ts := self._parse_ts(v.get("discovered"))) and ts >= cutoff]
        recent.sort(key=lambda v: v.get("discovered") or "", reverse=True)
        logger.debug(f"    Ransomware.live: {len(victims)} víctimas en feed, "
                     f"{len(recent)} en ventana de {self.lookback_hours}h")

        for v in recent[:self.max_victims]:
            group = v.get("group") or "?"
            name = v.get("victim") or "?"
            country = v.get("country") or "?"
            sector = v.get("activity") or "?"
            ctx.add_note(self.name,
                         f"{group} publicó víctima: {name} ({country}, {sector})")
        if len(recent) > self.max_victims:
            ctx.add_note(self.name,
                         f"(+{len(recent) - self.max_victims} víctimas más en las "
                         f"últimas {self.lookback_hours}h)")

        # Cruce: dominio de víctima presente entre los IOCs del día
        domains = {v.get("domain", "").lower().removeprefix("www."): v
                   for v in victims if v.get("domain")}
        for ioc in iocs:
            v = domains.get(ioc.removeprefix("www."))
            if v:
                ctx.add(IocVerdict(
                    ioc=ioc,
                    kind="domain",
                    source=self.name,
                    label=f"víctima publicada en leak site de {v.get('group', '?')}",
                    detail=f"descubierto {v.get('discovered', '?')[:10]}",
                ))
