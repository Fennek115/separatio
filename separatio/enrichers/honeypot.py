"""
enrichers/honeypot.py — Dato propio (capa 4): quién ataca TU honeypot.

Lee un JSON local con los atacantes que el honeypot de Oracle (Cowrie + Nginx
catch-all + CrowdSec) capturó, que un colector *pull* deposita en disco. El
honeypot NO tiene credenciales de nada: es casa la que se conecta a buscar los
logs (`tools/pull_honeypot.sh`), no al revés.

Aporta dos señales:
  1. Nota de contexto: resumen de los atacantes del día (top IPs, tipo, URIs
     señuelo más golpeadas) para la síntesis de Stage 3.
  2. La señal fuerte del proyecto — el "círculo detección→inteligencia→detección":
     si una IP de la que hablan los feeds del día ADEMÁS pegó a tu honeypot, se
     emite un IocVerdict. Eso es lo que distingue "otro agregador de feeds" de
     inteligencia propia.

El archivo lo produce el colector con este esquema (una entrada por IP):
  {"generated": "<iso8601>", "window_hours": 24, "attackers": [
     {"ip": "1.2.3.4", "hits": 42, "kinds": ["web","cowrie"],
      "first_seen": "...", "last_seen": "...", "sample_uris": ["/.env", ...],
      "crowdsec": true, "crowdsec_sensors": ["vm2-crowdsec"]}]}

`crowdsec_sensors` dice CUÁL de los dos CrowdSec tomó la decisión (hay uno por
VM y cada uno mira sólo el sshd real de su host): desde que el 22 de VM1 es de
Cowrie, el de allá se quedó sin entrada. Ver `honeypot/EXPONER.md` §CrowdSec.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from separatio import runlog
from separatio.enrichment import Enricher, EnrichmentContext, IocVerdict

logger = logging.getLogger(__name__)


class HoneypotEnricher(Enricher):
    name = "Honeypot"

    def __init__(self, data_path: str, max_notes: int = 10, stale_hours: int = 48):
        self.data_path = Path(data_path)
        self.max_notes = max_notes
        self.stale_hours = stale_hours

    def _load(self) -> dict:
        if not self.data_path.exists():
            logger.debug(f"    Honeypot: sin datos en {self.data_path} (colector no corrió aún)")
            return {}
        return json.loads(self.data_path.read_text())

    def enrich(self, iocs: dict[str, list[str]], ctx: EnrichmentContext) -> None:
        data = self._load()
        attackers = data.get("attackers", [])
        if not attackers:
            return

        # Índice por IP para el cruce con los IOCs del día
        by_ip = {a["ip"]: a for a in attackers if a.get("ip")}

        # (1) Nota de contexto: top atacantes por nº de hits
        top = sorted(attackers, key=lambda a: a.get("hits", 0), reverse=True)
        window = data.get("window_hours", 24)
        ctx.add_note(self.name,
                     f"{len(attackers)} IPs únicas atacaron el honeypot en las últimas "
                     f"{window}h (fuente: sensor propio, Oracle).")
        runlog.record_drop("enrichers.honeypot.notes",
                           shown=min(self.max_notes, len(top)), total=len(top))
        for a in top[:self.max_notes]:
            kinds = "+".join(a.get("kinds", [])) or "?"
            all_uris = a.get("sample_uris", [])
            runlog.record_drop("enrichers.honeypot.uris",
                               shown=min(3, len(all_uris)), total=len(all_uris),
                               detail=a.get("ip", "?"))
            uris = ", ".join(all_uris[:3])
            tail = f" — señuelos: {uris}" if uris else ""
            scanner = (f" [escáner de investigación: {a.get('scanner_name') or '?'}]"
                       if a.get("class") == "scanner" else "")
            ctx.add_note(self.name,
                         f"{a['ip']} → {a.get('hits', 0)} hits ({kinds}){scanner}{tail}")

        # (2) Señal fuerte: IP de la que hablan los feeds y que ADEMÁS te atacó
        for ioc in iocs:
            a = by_ip.get(ioc)
            if not a:
                continue
            # Que Censys o Shodan te escaneen y además salgan en una noticia no es
            # correlación: es el ruido de fondo de internet (F-A del rework).
            if a.get("class") == "scanner":
                continue
            kinds = "+".join(a.get("kinds", [])) or "?"
            ctx.add(IocVerdict(
                ioc=ioc,
                kind="ip",
                source=self.name,
                label="observada atacando TU honeypot",
                detail=f"{a.get('hits', 0)} hits ({kinds}), "
                       f"últimos {a.get('last_seen', '?')[:16]}",
            ))
