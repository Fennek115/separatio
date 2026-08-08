"""
enrichers — plugins concretos de la capa de enrichment (Stage 2.7).

`build_enrichers(config)` lee los toggles de config y devuelve la lista de
enrichers habilitados. Agregar una fuente nueva = crear un módulo con una
subclase de Enricher y registrarla aquí; no se toca el pipeline.
"""

from __future__ import annotations

import logging

from separatio.enrichment import Enricher

logger = logging.getLogger(__name__)


def build_enrichers(config) -> list[Enricher]:
    """Instancia los enrichers habilitados en config.ENRICHERS."""
    toggles: dict = getattr(config, "ENRICHERS", {})
    enrichers: list[Enricher] = []

    if toggles.get("ipsum"):
        from separatio.enrichers.ipsum import IpsumEnricher
        enrichers.append(IpsumEnricher(
            url=getattr(config, "IPSUM_URL",
                        "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"),
            min_score=getattr(config, "IPSUM_MIN_SCORE", 3),
            timeout=getattr(config, "KEV_FETCH_TIMEOUT", 15),
        ))

    if toggles.get("openphish"):
        from separatio.enrichers.openphish import OpenPhishEnricher
        enrichers.append(OpenPhishEnricher(
            url=getattr(config, "OPENPHISH_URL", "https://openphish.com/feed.txt"),
            timeout=getattr(config, "KEV_FETCH_TIMEOUT", 15),
        ))

    if toggles.get("ip_reputation"):
        from separatio.enrichers.ip_reputation import IpReputationEnricher
        enrichers.append(IpReputationEnricher(
            max_ips=getattr(config, "ENRICH_MAX_IPS", 25),
            sleep_on_vt=getattr(config, "ENRICH_VT_SLEEP", 15),
        ))

    if toggles.get("ransomware_live"):
        from separatio.enrichers.ransomware import RansomwareLiveEnricher
        enrichers.append(RansomwareLiveEnricher(
            url=getattr(config, "RANSOMWARELIVE_URL",
                        "https://api.ransomware.live/v2/recentvictims"),
            lookback_hours=getattr(config, "RANSOMWARE_LOOKBACK_HOURS", 26),
            max_victims=getattr(config, "RANSOMWARE_MAX_VICTIMS", 15),
            timeout=getattr(config, "KEV_FETCH_TIMEOUT", 15),
        ))

    if toggles.get("onion_lookup"):
        from separatio.enrichers.onionlookup import OnionLookupEnricher
        enrichers.append(OnionLookupEnricher(
            base_url=getattr(config, "ONIONLOOKUP_URL",
                             "https://onion.ail-project.org/api/lookup"),
            max_lookups=getattr(config, "ONIONLOOKUP_MAX", 10),
            timeout=getattr(config, "KEV_FETCH_TIMEOUT", 15),
        ))

    if toggles.get("honeypot"):
        from separatio.enrichers.honeypot import HoneypotEnricher
        enrichers.append(HoneypotEnricher(
            data_path=getattr(config, "HONEYPOT_DATA",
                              "data/honeypot/attackers.json"),
            max_notes=getattr(config, "HONEYPOT_MAX_NOTES", 10),
        ))

    if toggles.get("malwarebazaar"):
        from separatio.enrichers.malwarebazaar import MalwareBazaarEnricher
        enrichers.append(MalwareBazaarEnricher(
            auth_keys=getattr(config, "MALWAREBAZAAR_AUTH_KEYS", []),
            corpus_path=getattr(config, "MALWAREBAZAAR_CORPUS",
                                "data/honeypot/hashes.log"),
            max_lookups=getattr(config, "MALWAREBAZAAR_MAX", 25),
            url=getattr(config, "MALWAREBAZAAR_URL",
                        "https://mb-api.abuse.ch/api/v1/"),
            timeout=getattr(config, "KEV_FETCH_TIMEOUT", 15),
        ))

    return enrichers
