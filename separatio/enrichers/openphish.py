"""
enrichers/openphish.py — Cross-reference de URLs/dominios contra OpenPhish (sin key).

OpenPhish community feed (https://openphish.com/feed.txt) lista URLs de phishing
activas de las últimas horas. Se descarga una vez por run; se cruzan tanto las
URLs exactas como los dominios extraídos de los artículos contra los hosts del feed.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

import requests

from separatio.enrichment import Enricher, EnrichmentContext, IocVerdict, ioc_kind

logger = logging.getLogger(__name__)


class OpenPhishEnricher(Enricher):
    name = "OpenPhish"

    def __init__(self, url: str, timeout: int = 15):
        self.url = url
        self.timeout = timeout

    def _load(self) -> tuple[set[str], set[str]]:
        """Devuelve (urls_exactas, hosts) del feed."""
        resp = requests.get(self.url, timeout=self.timeout)
        resp.raise_for_status()
        urls: set[str] = set()
        hosts: set[str] = set()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line:
                continue
            urls.add(line.lower())
            host = urlparse(line).netloc.lower()
            if host:
                hosts.add(host.removeprefix("www."))
        return urls, hosts

    def enrich(self, iocs: dict[str, list[str]], ctx: EnrichmentContext) -> None:
        targets = [ioc for ioc in iocs if ioc_kind(ioc) in ("url", "domain")]
        if not targets:
            return
        urls, hosts = self._load()
        logger.debug(f"    OpenPhish: {len(urls)} URLs / {len(hosts)} hosts en el feed")
        for ioc in targets:
            kind = ioc_kind(ioc)
            hit = False
            if kind == "url" and ioc in urls:
                hit = True
            elif kind == "domain" and ioc.removeprefix("www.") in hosts:
                hit = True
            elif kind == "url" and urlparse(ioc).netloc.lower().removeprefix("www.") in hosts:
                hit = True
            if hit:
                ctx.add(IocVerdict(
                    ioc=ioc,
                    kind=kind,
                    source=self.name,
                    label="phishing activo",
                    detail="presente en OpenPhish",
                ))
