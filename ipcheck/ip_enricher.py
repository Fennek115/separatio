"""
ip_enricher.py — Librería de enriquecimiento de IPs (núcleo reutilizable).

Extrae la lógica pura de consulta a fuentes de threat intelligence del CLI
(`ip_threat_checker.py`) para poder importarla desde otros proyectos sin
arrastrar estado global, lectura de stdin, colores de terminal ni escritura
de archivos.

Diseño:
  - Las funciones `check_*` son puras: reciben (ip, key/enabled, timeout),
    hacen una petición HTTP y devuelven un dict (o None si están deshabilitadas).
    No mutan estado global ni imprimen.
  - `decidir_nivel` / `debe_pasar_nivel3` / `risk_level` son funciones puras.
  - `IpEnricher` es una sesión liviana que orquesta el análisis por niveles
    (1→2→3), acumula estadísticas de uso y recuerda si la cuota de VirusTotal
    se agotó. Es el punto de entrada recomendado: `IpEnricher(keys).enrich(ip)`.

Uso mínimo como librería:

    from ip_enricher import ApiKeys, IpEnricher

    enricher = IpEnricher(ApiKeys.from_env())
    result = enricher.enrich("185.220.101.45")
    print(result["risk"], result["level_reached"])

El CLI (`ip_threat_checker.py`) conserva su comportamiento (colores, historial,
Excel) delegando las consultas HTTP a este módulo.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime

import requests

logger = logging.getLogger(__name__)

# Valor centinela del .env.example: una key igual a esto se trata como no configurada.
KEY_PLACEHOLDER = "TU_API_KEY_AQUI"

# Nombres canónicos de las 8 fuentes integradas.
API_NAMES = (
    "abuseipdb", "virustotal", "greynoise", "otx",
    "urlhaus", "threatfox", "shodan", "ipapi",
)

# Campos que pedimos a ip-api.com en cada consulta
IPAPI_FIELDS = "status,message,country,countryCode,regionName,city,isp,org,as,proxy,hosting,mobile"

# Puertos que elevan una IP al Nivel 3 aunque no haya señales en Abuse/OTX
PUERTOS_C2_SOSPECHOSOS = {
    4444, 1337, 31337, 6666, 6667, 7777, 8888, 9999,
    12345, 54321, 1234, 5555, 1080, 9001, 9030,
}

# Categorías de reporte de AbuseIPDB (id → nombre legible)
ABUSE_CATEGORIES = {
    3: "Fraud", 4: "DDoS", 5: "FTP BruteForce", 6: "Ping of Death",
    7: "Phishing", 8: "VoIP Fraud", 9: "Open Proxy", 10: "Web Spam",
    11: "Email Spam", 12: "Blog Spam", 13: "VPN", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing", 18: "BruteForce",
    19: "Bad Bot", 20: "Exploited Host", 21: "Web App Attack", 22: "SSH",
    23: "IoT",
}


# ─────────────────────────────────────────────────────────
# CONFIGURACIÓN DE CLAVES (inyectada, sin globals)
# ─────────────────────────────────────────────────────────

@dataclass
class ApiKeys:
    """Claves de API inyectables. Una clave vacía o igual al placeholder
    se considera no configurada y la fuente correspondiente se omite."""
    abuseipdb: str = ""
    virustotal: str = ""
    otx: str = ""
    abusech: str = ""   # cubre URLhaus y ThreatFox (https://auth.abuse.ch)

    @classmethod
    def from_env(cls) -> "ApiKeys":
        """Lee las claves de variables de entorno. No llama a load_dotenv:
        el caller decide si carga un .env (evita efectos en tiempo de import)."""
        return cls(
            abuseipdb=os.environ.get("ABUSEIPDB_API_KEY", ""),
            virustotal=os.environ.get("VIRUSTOTAL_API_KEY", ""),
            otx=os.environ.get("OTX_API_KEY", ""),
            abusech=os.environ.get("ABUSECH_API_KEY", ""),
        )

    @staticmethod
    def active(key: str | None) -> bool:
        return bool(key) and key != KEY_PLACEHOLDER


def _active(key: str | None) -> bool:
    return ApiKeys.active(key)


# ─────────────────────────────────────────────────────────
# FUNCIONES DE CONSULTA (puras: sin globals, sin prints)
# Cada una retorna un dict con clave "status" en {"ok","error","quota"}
# o None si la fuente está deshabilitada (sin key / enabled=False).
# ─────────────────────────────────────────────────────────

def check_abuseipdb(ip: str, key: str, *, timeout: int = 10) -> dict | None:
    if not _active(key):
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=timeout,
        )
        if r.status_code == 200:
            d = r.json()["data"]
            cat_counter: dict[str, int] = {}
            for report in d.get("reports", []):
                for cat_id in report.get("categories", []):
                    name = ABUSE_CATEGORIES.get(cat_id, str(cat_id))
                    cat_counter[name] = cat_counter.get(name, 0) + 1
            top_cats = sorted(cat_counter, key=cat_counter.get, reverse=True)[:3]
            return {
                "status":         "ok",
                "http_code":      r.status_code,
                "abuse_score":    d.get("abuseConfidenceScore", 0),
                "country":        d.get("countryCode", "?"),
                "isp":            d.get("isp", "?"),
                "domain":         d.get("domain", "?"),
                "usage_type":     d.get("usageType", "?"),
                "total_reports":  d.get("totalReports", 0),
                "distinct_users": d.get("numDistinctUsers", 0),
                "last_reported":  d.get("lastReportedAt", "Nunca"),
                "is_tor":         d.get("isTor", False),
                "is_whitelisted": d.get("isWhitelisted", False),
                "top_categories": top_cats,
            }
        return {"status": "error", "http_code": r.status_code, "detail": r.text[:200]}
    except Exception as e:
        return {"status": "error", "http_code": 0, "detail": str(e)}


def check_virustotal(ip: str, key: str, *, timeout: int = 10) -> dict | None:
    if not _active(key):
        return None
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": key},
            timeout=timeout,
        )
        if r.status_code == 200:
            attr  = r.json()["data"]["attributes"]
            stats = attr.get("last_analysis_stats", {})
            ts    = attr.get("last_analysis_date")
            last_analysis = datetime.fromtimestamp(ts).strftime("%Y-%m-%d") if ts else "?"
            return {
                "status":        "ok",
                "http_code":     r.status_code,
                "malicious":     stats.get("malicious", 0),
                "suspicious":    stats.get("suspicious", 0),
                "harmless":      stats.get("harmless", 0),
                "undetected":    stats.get("undetected", 0),
                "asn":           attr.get("asn", "?"),
                "as_owner":      attr.get("as_owner", "?"),
                "country":       attr.get("country", "?"),
                "reputation":    attr.get("reputation", 0),
                "last_analysis": last_analysis,
                "tags":          attr.get("tags", []),
            }
        elif r.status_code == 429:
            # Con el sleep de pacing el rate-limit puntual no debería ocurrir,
            # así que cualquier 429 se trata como cuota diaria agotada.
            try:
                msg = r.json().get("error", {}).get("message", r.text[:100])
            except Exception:
                msg = r.text[:100]
            return {"status": "quota", "http_code": 429, "detail": msg}
        return {"status": "error", "http_code": r.status_code, "detail": r.text[:200]}
    except Exception as e:
        return {"status": "error", "http_code": 0, "detail": str(e)}


def check_greynoise(ip: str, enabled: bool = True, *, timeout: int = 10) -> dict | None:
    if not enabled:
        return None
    try:
        r = requests.get(f"https://api.greynoise.io/v3/community/{ip}", timeout=timeout)
        if r.status_code == 200:
            d = r.json()
            return {
                "status":         "ok",
                "http_code":      r.status_code,
                "noise":          d.get("noise", False),
                "riot":           d.get("riot", False),
                "classification": d.get("classification", "unknown"),
                "name":           d.get("name", "—"),
                "last_seen":      d.get("last_seen", "?"),
            }
        elif r.status_code == 404:
            return {
                "status": "ok", "http_code": 404,
                "noise": False, "riot": False,
                "classification": "unknown", "name": "—", "last_seen": "?",
            }
        return {"status": "error", "http_code": r.status_code, "detail": r.text[:200]}
    except Exception as e:
        return {"status": "error", "http_code": 0, "detail": str(e)}


def check_otx(ip: str, key: str, *, timeout: int = 10) -> dict | None:
    if not _active(key):
        return None
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": key},
            timeout=timeout,
        )
        if r.status_code == 200:
            d          = r.json()
            pulse_info = d.get("pulse_info", {})
            pulses     = pulse_info.get("pulses", [])
            tags: list[str] = []
            for p in pulses[:5]:
                tags.extend(p.get("tags", []))
            top_tags = list(dict.fromkeys(tags))[:4]
            return {
                "status":      "ok",
                "http_code":   r.status_code,
                "pulse_count": pulse_info.get("count", 0),
                "reputation":  d.get("reputation", 0),
                "top_tags":    top_tags,
            }
        return {"status": "error", "http_code": r.status_code, "detail": r.text[:200]}
    except Exception as e:
        return {"status": "error", "http_code": 0, "detail": str(e)}


def check_urlhaus(ip: str, key: str, *, timeout: int = 10) -> dict | None:
    if not _active(key):
        return None
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            headers={"Auth-Key": key},
            data={"host": ip},
            timeout=timeout,
        )
        if r.status_code == 200:
            d      = r.json()
            found  = d.get("query_status") == "is_host"
            urls   = d.get("urls", [])
            online = sum(1 for u in urls if u.get("url_status") == "online")
            return {
                "status":      "ok",
                "http_code":   r.status_code,
                "found":       found,
                "total_urls":  len(urls),
                "online_urls": online,
                "reference":   d.get("urlhaus_reference", ""),
            }
        return {"status": "error", "http_code": r.status_code, "detail": r.text[:200]}
    except Exception as e:
        return {"status": "error", "http_code": 0, "detail": str(e)}


def check_threatfox(ip: str, key: str, *, timeout: int = 10) -> dict | None:
    if not _active(key):
        return None
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": key},
            json={"query": "search_ioc", "search_term": ip, "exact_match": True},
            timeout=timeout,
        )
        if r.status_code == 200:
            d     = r.json()
            found = d.get("query_status") == "ok"
            iocs  = d.get("data", []) if found else []
            malware_list = list(dict.fromkeys(
                i.get("malware_printable", "?") for i in iocs if i.get("malware_printable")
            ))[:3]
            threat_types = list(dict.fromkeys(
                i.get("threat_type", "?") for i in iocs if i.get("threat_type")
            ))[:2]
            confidence = max((i.get("confidence_level", 0) for i in iocs), default=0)
            first_seen = str(iocs[0].get("first_seen", "?"))[:10] if iocs else None
            return {
                "status":       "ok",
                "http_code":    r.status_code,
                "found":        found,
                "ioc_count":    len(iocs),
                "malware":      malware_list,
                "threat_types": threat_types,
                "confidence":   confidence,
                "first_seen":   first_seen,
            }
        return {"status": "error", "http_code": r.status_code, "detail": r.text[:200]}
    except Exception as e:
        return {"status": "error", "http_code": 0, "detail": str(e)}


def check_shodan(ip: str, enabled: bool = True, *, timeout: int = 10) -> dict | None:
    """Shodan InternetDB — sin key, sin cuota documentada.
    Devuelve puertos abiertos, CVEs conocidas, CPEs y hostnames.
    404 = IP no indexada (común en IPs residenciales / poco activas)."""
    if not enabled:
        return None
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=timeout)
        if r.status_code == 200:
            d = r.json()
            return {
                "status":    "ok",
                "http_code": 200,
                "ports":     d.get("ports", []),
                "vulns":     d.get("vulns", []),
                "cpes":      d.get("cpes", []),
                "hostnames": d.get("hostnames", []),
                "tags":      d.get("tags", []),
            }
        elif r.status_code == 404:
            return {"status": "ok", "http_code": 404,
                    "ports": [], "vulns": [], "cpes": [], "hostnames": [], "tags": []}
        return {"status": "error", "http_code": r.status_code, "detail": r.text[:200]}
    except Exception as e:
        return {"status": "error", "http_code": 0, "detail": str(e)}


def check_ipapi(ip: str, enabled: bool = True, *, timeout: int = 10) -> dict | None:
    """ip-api.com — sin key, 45 req/min. Geolocalización, ISP/ASN, flags proxy/hosting/mobile.
    Nota: el plan free usa HTTP (no HTTPS); no enviar datos sensibles por este canal."""
    if not enabled:
        return None
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": IPAPI_FIELDS},
            timeout=timeout,
        )
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                return {
                    "status":       "ok",
                    "http_code":    200,
                    "country":      d.get("country", "?"),
                    "country_code": d.get("countryCode", "?"),
                    "region":       d.get("regionName", "?"),
                    "city":         d.get("city", "?"),
                    "isp":          d.get("isp", "?"),
                    "org":          d.get("org", "?"),
                    "asn":          d.get("as", "?"),
                    "proxy":        d.get("proxy", False),
                    "hosting":      d.get("hosting", False),
                    "mobile":       d.get("mobile", False),
                }
            return {"status": "error", "http_code": 200, "detail": d.get("message", "unknown error")}
        elif r.status_code == 429:
            return {"status": "error", "http_code": 429, "detail": "rate limit (45 req/min)"}
        return {"status": "error", "http_code": r.status_code, "detail": r.text[:200]}
    except Exception as e:
        return {"status": "error", "http_code": 0, "detail": str(e)}


# ─────────────────────────────────────────────────────────
# LÓGICA DE DECISIÓN POR NIVELES (pura)
# ─────────────────────────────────────────────────────────

def decidir_nivel(gn_data, ipapi_data, shodan_data) -> tuple[bool, str]:
    """Evalúa el Nivel 1 (GreyNoise + ip-api + Shodan) y decide si la IP puede
    cerrarse como BAJO sin gastar AbuseIPDB/OTX/VT. Retorna (pasar_nivel2, motivo)."""
    ok = lambda d: d and d.get("status") == "ok"

    if ok(gn_data) and gn_data.get("riot"):
        nombre = gn_data.get("name", "servicio legítimo")
        return False, f"GreyNoise RIOT — {nombre}"

    gn_benign  = ok(gn_data) and gn_data.get("classification") == "benign"
    es_dc      = ok(ipapi_data) and ipapi_data.get("hosting")
    sh_ports   = set(shodan_data.get("ports", [])) if ok(shodan_data) else set()
    puerto_sospechoso = bool(sh_ports & PUERTOS_C2_SOSPECHOSOS)

    if gn_benign and es_dc and not puerto_sospechoso:
        return False, "GreyNoise benign + datacenter, sin puertos sospechosos"

    return True, ""


def debe_pasar_nivel3(abuse_data, otx_data, shodan_data, ipapi_data) -> tuple[bool, str]:
    """Evalúa el Nivel 2 (AbuseIPDB + OTX) y decide si la IP necesita el análisis
    completo de Nivel 3 (VT + URLhaus + ThreatFox). Retorna (necesita_nivel3, motivo)."""
    ok = lambda d: d and d.get("status") == "ok"

    abuse_score  = abuse_data.get("abuse_score", 0)  if ok(abuse_data)  else 0
    otx_pulses   = otx_data.get("pulse_count", 0)    if ok(otx_data)    else 0
    shodan_vulns = shodan_data.get("vulns", [])       if ok(shodan_data) else []
    sh_ports     = set(shodan_data.get("ports", []))  if ok(shodan_data) else set()
    es_proxy     = ipapi_data.get("proxy", False)     if ok(ipapi_data)  else False

    señales = []
    if abuse_score > 0:    señales.append(f"AbuseIPDB={abuse_score}%")
    if otx_pulses > 0:     señales.append(f"OTX={otx_pulses} pulses")
    if shodan_vulns:       señales.append(f"CVEs={len(shodan_vulns)}")
    if sh_ports & PUERTOS_C2_SOSPECHOSOS:
        señales.append("puerto sospechoso")
    if es_proxy:           señales.append("proxy detectado")

    if señales:
        return True, ", ".join(señales)
    return False, "sin señales en Nivel 2"


def risk_level(abuse_score, vt_malicious, gn_classification,
               otx_pulses, threatfox_found, urlhaus_found) -> str:
    """Clasificación de riesgo pura (sin colores). Devuelve la etiqueta."""
    if (abuse_score >= 80 or vt_malicious >= 5
            or gn_classification == "malicious"
            or threatfox_found):
        return "CRITICO"
    elif (abuse_score >= 50 or vt_malicious >= 2
            or otx_pulses >= 5):
        return "ALTO"
    elif (abuse_score >= 20 or vt_malicious >= 1
            or otx_pulses >= 1 or urlhaus_found):
        return "MEDIO"
    return "BAJO"


# ─────────────────────────────────────────────────────────
# SESIÓN DE ENRIQUECIMIENTO (orquesta niveles + acumula stats)
# ─────────────────────────────────────────────────────────

def _empty_stats() -> dict[str, dict[str, int]]:
    return {name: {"ok": 0, "error": 0, "skipped": 0} for name in API_NAMES}


@dataclass
class IpEnricher:
    """Sesión de enriquecimiento de IPs por niveles. Sin estado global:
    mantiene sus propias estadísticas y la bandera de cuota VT agotada.

    `disabled` permite forzar el salto de fuentes concretas (p.ej. cuando un
    chequeo de conectividad falló al inicio en el CLI)."""
    keys: ApiKeys
    timeout: int = 10
    max_level: int = 3
    disabled: set[str] = field(default_factory=set)

    stats: dict[str, dict[str, int]] = field(default_factory=_empty_stats)
    vt_quota_exhausted: bool = False

    def _record(self, api: str, result: dict | None) -> dict | None:
        if result is None:
            self.stats[api]["skipped"] += 1
        elif result.get("status") == "ok":
            self.stats[api]["ok"] += 1
        else:  # "error" o "quota"
            self.stats[api]["error"] += 1
        return result

    def _call(self, name: str, fn) -> dict | None:
        """Ejecuta el check de una fuente salvo que esté en `disabled`, en cuyo
        caso se cuenta como skipped sin llamar. Hace que `disabled` sea autoritativo
        independientemente de cómo la función downstream maneje claves vacías."""
        if name in self.disabled:
            return self._record(name, None)
        return self._record(name, fn())

    def enrich(self, ip: str) -> dict:
        """Analiza una IP en cascada (Nivel 1→2→3) parando lo antes posible.
        Retorna un dict estructurado con resultados por fuente, riesgo y metadatos.
        No duerme entre llamadas: el pacing (rate-limit de VT) es responsabilidad
        del caller, que puede leer `result["level_reached"]` para decidir."""
        k = self.keys
        t = self.timeout

        # ── Nivel 1: ip-api + GreyNoise + Shodan (gratis) ──
        ipapi_data  = self._call("ipapi",     lambda: check_ipapi(ip, True, timeout=t))
        gn_data     = self._call("greynoise", lambda: check_greynoise(ip, True, timeout=t))
        shodan_data = self._call("shodan",    lambda: check_shodan(ip, True, timeout=t))

        abuse_data = otx_data = vt_data = urlhaus_data = threatfox_data = None
        level_reached = 1
        level_complete = True

        pasar_n2, motivo_corte = decidir_nivel(gn_data, ipapi_data, shodan_data)
        motivo = motivo_corte

        if pasar_n2 and self.max_level >= 2:
            # ── Nivel 2: AbuseIPDB + OTX ──
            abuse_data = self._call("abuseipdb", lambda: check_abuseipdb(ip, k.abuseipdb, timeout=t))
            otx_data   = self._call("otx",       lambda: check_otx(ip, k.otx, timeout=t))
            level_reached = 2

            necesita_n3, motivo_n3 = debe_pasar_nivel3(abuse_data, otx_data, shodan_data, ipapi_data)
            motivo = motivo_n3

            if necesita_n3 and self.max_level >= 3:
                # ── Nivel 3: VT + URLhaus + ThreatFox ──
                if self.vt_quota_exhausted:
                    self._record("virustotal", None)
                    level_complete = False
                else:
                    vt_data = self._call("virustotal", lambda: check_virustotal(ip, k.virustotal, timeout=t))
                    if vt_data and vt_data.get("status") == "quota":
                        self.vt_quota_exhausted = True
                        level_complete = False

                urlhaus_data   = self._call("urlhaus",   lambda: check_urlhaus(ip, k.abusech, timeout=t))
                threatfox_data = self._call("threatfox", lambda: check_threatfox(ip, k.abusech, timeout=t))
                level_reached = 3

        risk = self._compute_risk(abuse_data, vt_data, gn_data, otx_data, threatfox_data, urlhaus_data)

        return {
            "ip":             ip,
            "risk":           risk,
            "level_reached":  level_reached,
            "level_complete": level_complete,
            "reason":         motivo,
            "abuseipdb":      abuse_data,
            "virustotal":     vt_data,
            "greynoise":      gn_data,
            "otx":            otx_data,
            "urlhaus":        urlhaus_data,
            "threatfox":      threatfox_data,
            "shodan":         shodan_data,
            "ipapi":          ipapi_data,
        }

    @staticmethod
    def _compute_risk(abuse_data, vt_data, gn_data, otx_data, threatfox_data, urlhaus_data) -> str:
        ok = lambda d: d and d.get("status") == "ok"
        return risk_level(
            abuse_score=abuse_data.get("abuse_score", 0) if ok(abuse_data) else 0,
            vt_malicious=vt_data.get("malicious", 0) if ok(vt_data) else 0,
            gn_classification=gn_data.get("classification", "unknown") if ok(gn_data) else "unknown",
            otx_pulses=otx_data.get("pulse_count", 0) if ok(otx_data) else 0,
            threatfox_found=bool(threatfox_data.get("found")) if ok(threatfox_data) else False,
            urlhaus_found=bool(urlhaus_data.get("found")) if ok(urlhaus_data) else False,
        )
