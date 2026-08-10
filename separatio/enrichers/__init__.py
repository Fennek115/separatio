"""
enrichers — plugins concretos de la capa de enrichment (Stage 2.7).

`build_enrichers(settings)` lee los toggles y devuelve la lista de
enrichers habilitados. Agregar una fuente nueva = crear un módulo con una
subclase de Enricher y registrarla aquí; no se toca el pipeline.
"""

from __future__ import annotations

import logging

from separatio.enrichment import Enricher

logger = logging.getLogger(__name__)


def build_enrichers(settings) -> list[Enricher]:
    """Instancia los enrichers habilitados en `ENRICHERS`.

    `settings` es un `separatio.settings.Settings` desde F-G/G-2 (antes era el
    módulo `config`); cualquiera de los dos sirve, se lee todo por `getattr`."""
    toggles: dict = getattr(settings, "ENRICHERS", {})
    enrichers: list[Enricher] = []

    if toggles.get("ipsum"):
        from separatio.enrichers.ipsum import IpsumEnricher
        enrichers.append(IpsumEnricher(
            url=getattr(settings, "IPSUM_URL",
                        "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"),
            min_score=getattr(settings, "IPSUM_MIN_SCORE", 3),
            timeout=getattr(settings, "KEV_FETCH_TIMEOUT", 15),
        ))

    if toggles.get("openphish"):
        from separatio.enrichers.openphish import OpenPhishEnricher
        enrichers.append(OpenPhishEnricher(
            url=getattr(settings, "OPENPHISH_URL", "https://openphish.com/feed.txt"),
            timeout=getattr(settings, "KEV_FETCH_TIMEOUT", 15),
        ))

    if toggles.get("ip_reputation"):
        from separatio.enrichers.ip_reputation import IpReputationEnricher
        enrichers.append(IpReputationEnricher(
            max_ips=getattr(settings, "ENRICH_MAX_IPS", 25),
            sleep_on_vt=getattr(settings, "ENRICH_VT_SLEEP", 15),
        ))

    if toggles.get("ransomware_live"):
        from separatio.enrichers.ransomware import RansomwareLiveEnricher
        enrichers.append(RansomwareLiveEnricher(
            url=getattr(settings, "RANSOMWARELIVE_URL",
                        "https://api.ransomware.live/v2/recentvictims"),
            lookback_hours=getattr(settings, "RANSOMWARE_LOOKBACK_HOURS", 26),
            max_victims=getattr(settings, "RANSOMWARE_MAX_VICTIMS", 15),
            timeout=getattr(settings, "KEV_FETCH_TIMEOUT", 15),
        ))

    if toggles.get("onion_lookup"):
        from separatio.enrichers.onionlookup import OnionLookupEnricher
        enrichers.append(OnionLookupEnricher(
            base_url=getattr(settings, "ONIONLOOKUP_URL",
                             "https://onion.ail-project.org/api/lookup"),
            max_lookups=getattr(settings, "ONIONLOOKUP_MAX", 10),
            timeout=getattr(settings, "KEV_FETCH_TIMEOUT", 15),
        ))

    if toggles.get("honeypot"):
        from separatio.enrichers.honeypot import HoneypotEnricher
        enrichers.append(HoneypotEnricher(
            data_path=getattr(settings, "HONEYPOT_DATA",
                              "data/honeypot/attackers.json"),
            max_notes=getattr(settings, "HONEYPOT_MAX_NOTES", 10),
        ))

    if toggles.get("honeypot_recon"):
        from separatio.enrichers.honeypot_recon import HoneypotReconEnricher
        enrichers.append(HoneypotReconEnricher(
            window_hours=getattr(settings, "RECON_WINDOW_HOURS", 26),
            max_escalate=getattr(settings, "RECON_MAX_ESCALATE", 5),
            quotas=getattr(settings, "QUOTAS", {}),
            ttl_days=getattr(settings, "ENRICH_TTL_DAYS", {}),
            vt_sleep=getattr(settings, "ENRICH_VT_SLEEP", 15),
            recurrence_window_days=getattr(settings, "RECURRENCE_WINDOW_DAYS", 14),
            hassh_min_ips=getattr(settings, "HASSH_MIN_IPS", 3),
            hassh_window_days=getattr(settings, "HASSH_WINDOW_DAYS", 30),
        ))

    if toggles.get("malwarebazaar"):
        from separatio.enrichers.malwarebazaar import MalwareBazaarEnricher
        enrichers.append(MalwareBazaarEnricher(
            auth_keys=getattr(settings, "MALWAREBAZAAR_AUTH_KEYS", []),
            corpus_path=getattr(settings, "MALWAREBAZAAR_CORPUS",
                                "data/honeypot/hashes.log"),
            max_lookups=getattr(settings, "MALWAREBAZAAR_MAX", 25),
            url=getattr(settings, "MALWAREBAZAAR_URL",
                        "https://mb-api.abuse.ch/api/v1/"),
            timeout=getattr(settings, "KEV_FETCH_TIMEOUT", 15),
        ))

    return enrichers
