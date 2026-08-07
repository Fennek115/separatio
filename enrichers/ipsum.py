"""
enrichers/ipsum.py — Cross-reference de IPs contra IPsum (sin API key).

IPsum (https://github.com/stamparm/ipsum) agrega ~30 listas públicas de IPs
maliciosas. El archivo plano `ipsum.txt` tiene formato `IP<TAB>score`, donde
score = número de listas que reportaron esa IP. Se descarga una vez por run y
se cruza por coincidencia exacta — mismo patrón determinista que CISA KEV.
"""

from __future__ import annotations

import logging

import requests

from enrichment import Enricher, EnrichmentContext, IocVerdict, ioc_kind

logger = logging.getLogger(__name__)


class IpsumEnricher(Enricher):
    name = "IPsum"

    def __init__(self, url: str, min_score: int = 3, timeout: int = 15):
        self.url = url
        self.min_score = min_score
        self.timeout = timeout

    def _load(self) -> dict[str, int]:
        resp = requests.get(self.url, timeout=self.timeout)
        resp.raise_for_status()
        scores: dict[str, int] = {}
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                scores[parts[0]] = int(parts[1])
        return scores

    def enrich(self, iocs: dict[str, list[str]], ctx: EnrichmentContext) -> None:
        ip_iocs = [ioc for ioc in iocs if ioc_kind(ioc) == "ip"]
        if not ip_iocs:
            return
        scores = self._load()
        logger.debug(f"    IPsum: {len(scores)} IPs en la lista")
        for ioc in ip_iocs:
            ip = ioc.split(":")[0]
            score = scores.get(ip)
            if score is not None and score >= self.min_score:
                ctx.add(IocVerdict(
                    ioc=ip,
                    kind="ip",
                    source=self.name,
                    label="IP maliciosa (listas públicas)",
                    detail=f"reportada en {score} listas",
                    score=None,
                ))
