"""
enrichers/onionlookup.py — Metadatos de dominios .onion vía onion-lookup (CIRCL).

Si un artículo trae un .onion como IOC, este enricher pregunta al servicio
onion-lookup del AIL Project (clearnet, "without restrictions") si lo conoce:
first_seen / last_seen / títulos. El pipeline nunca resuelve el .onion — ese
es todo el punto.

Solo actúa cuando hay .onion entre los IOCs del día (lo normal es que no haya
ninguno), así que su costo típico es cero llamadas.
"""

from __future__ import annotations

import logging

from separatio.enrichment import Enricher, EnrichmentContext, IocVerdict
from separatio.net import get_with_retry

logger = logging.getLogger(__name__)


class OnionLookupEnricher(Enricher):
    name = "onion-lookup"

    def __init__(self, base_url: str, max_lookups: int = 10, timeout: int = 15):
        self.base_url = base_url.rstrip("/")
        self.max_lookups = max_lookups
        self.timeout = timeout

    def enrich(self, iocs: dict[str, list[str]], ctx: EnrichmentContext) -> None:
        onions = [i for i in iocs if i.endswith(".onion")]
        if not onions:
            return
        for onion in onions[:self.max_lookups]:
            try:
                resp = get_with_retry(f"{self.base_url}/{onion}", timeout=self.timeout)
            except Exception as e:
                logger.debug(f"    onion-lookup: {onion} → {e}")
                continue
            if resp.status_code != 200:
                continue
            data = resp.json()
            if not isinstance(data, dict) or not data.get("id"):
                continue
            titles = ", ".join(data.get("titles", [])[:3])
            detail = (f"first_seen {data.get('first_seen', '?')}, "
                      f"last_seen {data.get('last_seen', '?')}")
            if titles:
                detail += f" — títulos: {titles}"
            ctx.add(IocVerdict(
                ioc=onion,
                kind="domain",
                source=self.name,
                label="onion conocido por AIL Project",
                detail=detail,
            ))
