"""
enrichers/ip_reputation.py — Enrichment de IPs vía la librería ipcheck.

Reutiliza `ip_enricher.IpEnricher` (proyecto ipcheck refactorizado a librería)
para consultar AbuseIPDB / VirusTotal / GreyNoise / OTX / URLhaus / ThreatFox /
Shodan / ip-api sobre las IPs encontradas en los IOCs del día.

A diferencia de los enrichers de feed plano, este consume cuota de API y respeta
el rate-limit de VirusTotal (sleep entre IPs que alcanzan Nivel 3), por lo que
está OFF por defecto y limitado por `max_ips`.

Importa ipcheck como paquete del monorepo (`ipcheck.ip_enricher`).
"""

from __future__ import annotations

import logging
import time

from separatio.enrichment import Enricher, EnrichmentContext, IocVerdict, ioc_kind

logger = logging.getLogger(__name__)

_RISK_LABELS = {
    "CRITICO": "IP de alto riesgo",
    "ALTO":    "IP de riesgo alto",
    "MEDIO":   "IP de riesgo medio",
}


class IpReputationEnricher(Enricher):
    name = "ipcheck"

    def __init__(self, max_ips: int = 25, sleep_on_vt: int = 15):
        self.max_ips = max_ips
        self.sleep_on_vt = sleep_on_vt

    def _load_lib(self):
        """Import diferido para que el enricher pueda construirse sin la librería."""
        from ipcheck import ip_enricher
        return ip_enricher

    def enrich(self, iocs: dict[str, list[str]], ctx: EnrichmentContext) -> None:
        ip_iocs = [ioc.split(":")[0] for ioc in iocs if ioc_kind(ioc) == "ip"]
        if not ip_iocs:
            return

        lib = self._load_lib()
        session = lib.IpEnricher(lib.ApiKeys.from_env())

        for ip in ip_iocs[: self.max_ips]:
            result = session.enrich(ip)
            risk = result.get("risk", "BAJO")
            if risk in _RISK_LABELS:
                detail_bits = []
                ab = result.get("abuseipdb")
                if ab and ab.get("status") == "ok" and ab.get("abuse_score"):
                    detail_bits.append(f"AbuseIPDB {ab['abuse_score']}%")
                vt = result.get("virustotal")
                if vt and vt.get("status") == "ok" and vt.get("malicious"):
                    detail_bits.append(f"VT {vt['malicious']} maliciosos")
                tf = result.get("threatfox")
                if tf and tf.get("status") == "ok" and tf.get("found"):
                    detail_bits.append("ThreatFox: " + ", ".join(tf.get("malware", []) or ["C2"]))
                geo = result.get("ipapi") or {}
                if geo.get("status") == "ok":
                    detail_bits.append(geo.get("country_code", "?"))
                ctx.add(IocVerdict(
                    ioc=ip,
                    kind="ip",
                    source=self.name,
                    label=_RISK_LABELS[risk],
                    detail=" | ".join(detail_bits),
                ))
            # Pacing del rate-limit de VirusTotal: solo tras alcanzar Nivel 3.
            if result.get("level_reached") == 3 and not session.vt_quota_exhausted:
                time.sleep(self.sleep_on_vt)

        logger.info(f"    ipcheck: api_stats={ {k: v for k, v in session.stats.items() if any(v.values())} }")
