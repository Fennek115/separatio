#!/usr/bin/env python3
"""
SOC IP Threat Intelligence Checker
Verifica IPs contra AbuseIPDB, VirusTotal, GreyNoise, AlienVault OTX,
URLhaus y ThreatFox (abuse.ch)
Uso: python3 ip_threat_checker.py [archivo.txt]
"""

import requests
import json
import time
import sys
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# ─── CONFIGURACIÓN ────────────────────────────────────────
ABUSEIPDB_API_KEY  = os.environ.get("ABUSEIPDB_API_KEY",  "TU_API_KEY_AQUI")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "TU_API_KEY_AQUI")
OTX_API_KEY        = os.environ.get("OTX_API_KEY",        "TU_API_KEY_AQUI")
ABUSECH_API_KEY    = os.environ.get("ABUSECH_API_KEY",    "TU_API_KEY_AQUI")  # https://auth.abuse.ch — vale para URLhaus y ThreatFox
IP_FILE            = "ips.txt"
OUTPUT_FILE        = f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

# ─── COLORES TERMINAL ──────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

# ─── CONTADORES DE LLAMADAS API ───────────────────────────
api_stats = {
    "abuseipdb":  {"ok": 0, "error": 0, "skipped": 0},
    "virustotal": {"ok": 0, "error": 0, "skipped": 0},
    "greynoise":  {"ok": 0, "error": 0, "skipped": 0},
    "otx":        {"ok": 0, "error": 0, "skipped": 0},
    "urlhaus":    {"ok": 0, "error": 0, "skipped": 0},
    "threatfox":  {"ok": 0, "error": 0, "skipped": 0},
}

# ─── CATEGORÍAS ABUSEIPDB ─────────────────────────────────
ABUSE_CATEGORIES = {
    3: "Fraud", 4: "DDoS", 5: "FTP BruteForce", 6: "Ping of Death",
    7: "Phishing", 8: "VoIP Fraud", 9: "Open Proxy", 10: "Web Spam",
    11: "Email Spam", 12: "Blog Spam", 13: "VPN", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing", 18: "BruteForce",
    19: "Bad Bot", 20: "Exploited Host", 21: "Web App Attack", 22: "SSH",
    23: "IoT",
}

# ─── CARGAR IPs DESDE ARCHIVO ─────────────────────────────
def load_ips(filepath):
    ips = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "," in line:
                    parts = line.split(",", 1)
                    ips.append({"ip": parts[0].strip(), "user": parts[1].strip()})
                else:
                    ips.append({"ip": line, "user": "desconocido"})
        print(f"{GREEN}[+] {len(ips)} IPs cargadas desde '{filepath}'{RESET}\n")
    except FileNotFoundError:
        print(f"{RED}[!] Archivo '{filepath}' no encontrado.{RESET}\n")
        sys.exit(1)
    return ips

# ─── VERIFICAR API KEYS AL INICIO ─────────────────────────
def verify_api_keys():
    print(f"{BOLD}[*] Verificando conexion con APIs...{RESET}")
    results = {}

    # APIs con key — GET
    keyed_checks = [
        ("abuseipdb",  ABUSEIPDB_API_KEY,
         "https://api.abuseipdb.com/api/v2/check",
         {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
         {"ipAddress": "8.8.8.8", "maxAgeInDays": 1}),
        ("virustotal", VIRUSTOTAL_API_KEY,
         "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
         {"x-apikey": VIRUSTOTAL_API_KEY}, {}),
        ("otx",        OTX_API_KEY,
         "https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general",
         {"X-OTX-API-KEY": OTX_API_KEY}, {}),
    ]
    for name, key, url, headers, params in keyed_checks:
        if key == "TU_API_KEY_AQUI":
            print(f"    {name:12s} -> {YELLOW}[SKIP] API key no configurada{RESET}")
            results[name] = False
            continue
        try:
            r = requests.get(url, headers=headers, params=params, timeout=10)
            if r.status_code == 200:
                print(f"    {name:12s} -> {GREEN}[OK] Conectado correctamente — HTTP {r.status_code}{RESET}")
                results[name] = True
            elif r.status_code == 401:
                print(f"    {name:12s} -> {RED}[ERROR] API key invalida — HTTP 401{RESET}")
                results[name] = False
            elif r.status_code == 429:
                print(f"    {name:12s} -> {YELLOW}[WARN] Rate limit — HTTP 429{RESET}")
                results[name] = True
            else:
                print(f"    {name:12s} -> {RED}[ERROR] Respuesta inesperada — HTTP {r.status_code}{RESET}")
                results[name] = False
        except Exception as e:
            print(f"    {name:12s} -> {RED}[ERROR] Sin conexion: {e}{RESET}")
            results[name] = False

    # GreyNoise — sin key
    try:
        r = requests.get("https://api.greynoise.io/v3/community/8.8.8.8", timeout=10)
        if r.status_code in (200, 404):
            print(f"    {'greynoise':12s} -> {GREEN}[OK] Conectado correctamente — HTTP {r.status_code}{RESET}")
            results["greynoise"] = True
        elif r.status_code == 429:
            print(f"    {'greynoise':12s} -> {YELLOW}[WARN] Rate limit — HTTP 429{RESET}")
            results["greynoise"] = True
        else:
            print(f"    {'greynoise':12s} -> {RED}[ERROR] Respuesta inesperada — HTTP {r.status_code}{RESET}")
            results["greynoise"] = False
    except Exception as e:
        print(f"    {'greynoise':12s} -> {RED}[ERROR] Sin conexion: {e}{RESET}")
        results["greynoise"] = False

    # URLhaus y ThreatFox — misma key (ABUSECH_API_KEY)
    if ABUSECH_API_KEY == "TU_API_KEY_AQUI":
        for name in ("urlhaus", "threatfox"):
            print(f"    {name:12s} -> {YELLOW}[SKIP] ABUSECH_API_KEY no configurada{RESET}")
            results[name] = False
    else:
        auth_header = {"Auth-Key": ABUSECH_API_KEY}
        # URLhaus
        try:
            r = requests.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                headers=auth_header, data={"host": "8.8.8.8"}, timeout=10
            )
            if r.status_code == 200:
                print(f"    {'urlhaus':12s} -> {GREEN}[OK] Conectado correctamente — HTTP {r.status_code}{RESET}")
                results["urlhaus"] = True
            elif r.status_code == 401:
                print(f"    {'urlhaus':12s} -> {RED}[ERROR] API key invalida — HTTP 401{RESET}")
                results["urlhaus"] = False
            else:
                print(f"    {'urlhaus':12s} -> {RED}[ERROR] Respuesta inesperada — HTTP {r.status_code}{RESET}")
                results["urlhaus"] = False
        except Exception as e:
            print(f"    {'urlhaus':12s} -> {RED}[ERROR] Sin conexion: {e}{RESET}")
            results["urlhaus"] = False
        # ThreatFox
        try:
            r = requests.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                headers=auth_header,
                json={"query": "search_ioc", "search_term": "8.8.8.8", "exact_match": True},
                timeout=10
            )
            if r.status_code == 200:
                print(f"    {'threatfox':12s} -> {GREEN}[OK] Conectado correctamente — HTTP {r.status_code}{RESET}")
                results["threatfox"] = True
            elif r.status_code == 401:
                print(f"    {'threatfox':12s} -> {RED}[ERROR] API key invalida — HTTP 401{RESET}")
                results["threatfox"] = False
            else:
                print(f"    {'threatfox':12s} -> {RED}[ERROR] Respuesta inesperada — HTTP {r.status_code}{RESET}")
                results["threatfox"] = False
        except Exception as e:
            print(f"    {'threatfox':12s} -> {RED}[ERROR] Sin conexion: {e}{RESET}")
            results["threatfox"] = False

    print()
    return (results.get("abuseipdb", False), results.get("virustotal", False),
            results.get("greynoise", False), results.get("otx", False),
            results.get("urlhaus", False), results.get("threatfox", False))

# ─── ABUSEIPDB ─────────────────────────────────────────────
def check_abuseipdb(ip, enabled):
    if not enabled:
        api_stats["abuseipdb"]["skipped"] += 1
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=10
        )
        if r.status_code == 200:
            api_stats["abuseipdb"]["ok"] += 1
            d = r.json()["data"]
            cat_counter = {}
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
        else:
            api_stats["abuseipdb"]["error"] += 1
            return {"status": "error", "http_code": r.status_code, "detail": r.text[:200]}
    except Exception as e:
        api_stats["abuseipdb"]["error"] += 1
        return {"status": "error", "http_code": 0, "detail": str(e)}

# ─── VIRUSTOTAL ────────────────────────────────────────────
def check_virustotal(ip, enabled):
    if not enabled:
        api_stats["virustotal"]["skipped"] += 1
        return None
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=10
        )
        if r.status_code == 200:
            api_stats["virustotal"]["ok"] += 1
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
        else:
            api_stats["virustotal"]["error"] += 1
            return {"status": "error", "http_code": r.status_code, "detail": r.text[:200]}
    except Exception as e:
        api_stats["virustotal"]["error"] += 1
        return {"status": "error", "http_code": 0, "detail": str(e)}

# ─── GREYNOISE ─────────────────────────────────────────────
def check_greynoise(ip, enabled):
    if not enabled:
        api_stats["greynoise"]["skipped"] += 1
        return None
    try:
        r = requests.get(f"https://api.greynoise.io/v3/community/{ip}", timeout=10)
        if r.status_code == 200:
            api_stats["greynoise"]["ok"] += 1
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
            api_stats["greynoise"]["ok"] += 1
            return {
                "status": "ok", "http_code": 404,
                "noise": False, "riot": False,
                "classification": "unknown", "name": "—", "last_seen": "?",
            }
        else:
            api_stats["greynoise"]["error"] += 1
            return {"status": "error", "http_code": r.status_code, "detail": r.text[:200]}
    except Exception as e:
        api_stats["greynoise"]["error"] += 1
        return {"status": "error", "http_code": 0, "detail": str(e)}

# ─── ALIENVAULT OTX ────────────────────────────────────────
def check_otx(ip, enabled):
    if not enabled:
        api_stats["otx"]["skipped"] += 1
        return None
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            timeout=10
        )
        if r.status_code == 200:
            api_stats["otx"]["ok"] += 1
            d          = r.json()
            pulse_info = d.get("pulse_info", {})
            pulses     = pulse_info.get("pulses", [])
            tags = []
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
        else:
            api_stats["otx"]["error"] += 1
            return {"status": "error", "http_code": r.status_code, "detail": r.text[:200]}
    except Exception as e:
        api_stats["otx"]["error"] += 1
        return {"status": "error", "http_code": 0, "detail": str(e)}

# ─── URLHAUS (abuse.ch) ────────────────────────────────────
def check_urlhaus(ip, enabled):
    if not enabled:
        api_stats["urlhaus"]["skipped"] += 1
        return None
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            headers={"Auth-Key": ABUSECH_API_KEY},
            data={"host": ip},
            timeout=10
        )
        if r.status_code == 200:
            api_stats["urlhaus"]["ok"] += 1
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
        else:
            api_stats["urlhaus"]["error"] += 1
            return {"status": "error", "http_code": r.status_code, "detail": r.text[:200]}
    except Exception as e:
        api_stats["urlhaus"]["error"] += 1
        return {"status": "error", "http_code": 0, "detail": str(e)}

# ─── THREATFOX (abuse.ch) ──────────────────────────────────
def check_threatfox(ip, enabled):
    if not enabled:
        api_stats["threatfox"]["skipped"] += 1
        return None
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": ABUSECH_API_KEY},
            json={"query": "search_ioc", "search_term": ip, "exact_match": True},
            timeout=10
        )
        if r.status_code == 200:
            api_stats["threatfox"]["ok"] += 1
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
        else:
            api_stats["threatfox"]["error"] += 1
            return {"status": "error", "http_code": r.status_code, "detail": r.text[:200]}
    except Exception as e:
        api_stats["threatfox"]["error"] += 1
        return {"status": "error", "http_code": 0, "detail": str(e)}

# ─── CLASIFICACION DE RIESGO ──────────────────────────────
def get_risk_level(abuse_score, vt_malicious, gn_classification, otx_pulses, threatfox_found, urlhaus_found):
    if (abuse_score >= 80 or vt_malicious >= 5
            or gn_classification == "malicious"
            or threatfox_found):
        return "CRITICO", RED
    elif (abuse_score >= 50 or vt_malicious >= 2
            or otx_pulses >= 5):
        return "ALTO",    RED
    elif (abuse_score >= 20 or vt_malicious >= 1
            or otx_pulses >= 1 or urlhaus_found):
        return "MEDIO",   YELLOW
    else:
        return "BAJO",    GREEN

# ─── IMPRIMIR RESULTADO DE UNA IP ─────────────────────────
def print_ip_result(ip, user, abuse_data, vt_data, gn_data, otx_data, urlhaus_data, threatfox_data):
    abuse_score       = abuse_data.get("abuse_score", 0)          if abuse_data     and abuse_data.get("status")     == "ok" else 0
    vt_malicious      = vt_data.get("malicious", 0)               if vt_data        and vt_data.get("status")        == "ok" else 0
    gn_classification = gn_data.get("classification", "unknown")  if gn_data        and gn_data.get("status")        == "ok" else "unknown"
    otx_pulses        = otx_data.get("pulse_count", 0)            if otx_data       and otx_data.get("status")       == "ok" else 0
    threatfox_found   = threatfox_data.get("found", False)        if threatfox_data and threatfox_data.get("status") == "ok" else False
    urlhaus_found     = urlhaus_data.get("found", False)          if urlhaus_data   and urlhaus_data.get("status")   == "ok" else False

    risk, color = get_risk_level(abuse_score, vt_malicious, gn_classification, otx_pulses, threatfox_found, urlhaus_found)

    print(f"{BOLD}[*] {ip:20s}  usuario: {user}{RESET}")

    # AbuseIPDB
    if abuse_data is None:
        print(f"    AbuseIPDB  -> {GRAY}[SKIP]{RESET}")
    elif abuse_data.get("status") == "ok":
        tor      = f"{RED} TOR{RESET}"  if abuse_data.get("is_tor")        else ""
        wl       = f"{CYAN} WL{RESET}"  if abuse_data.get("is_whitelisted") else ""
        cats     = ", ".join(abuse_data["top_categories"]) or "—"
        last_rep = str(abuse_data["last_reported"])[:10]
        print(f"    AbuseIPDB  -> {GREEN}[HTTP {abuse_data['http_code']}]{RESET} "
              f"Score: {color}{abuse_score}%{RESET} | "
              f"Reportes: {abuse_data['total_reports']} ({abuse_data['distinct_users']} usuarios) | "
              f"País: {abuse_data['country']}{tor}{wl}")
        print(f"                  ISP: {str(abuse_data['isp'])[:40]} | "
              f"Uso: {abuse_data['usage_type']} | "
              f"Último: {last_rep} | "
              f"Categorías: {cats}")
    else:
        print(f"    AbuseIPDB  -> {RED}[HTTP {abuse_data['http_code']}] ERROR: {abuse_data.get('detail','')[:60]}{RESET}")

    # VirusTotal
    if vt_data is None:
        print(f"    VirusTotal -> {GRAY}[SKIP]{RESET}")
    elif vt_data.get("status") == "ok":
        rep       = vt_data["reputation"]
        rep_color = RED if rep < 0 else GREEN
        tags_str  = ", ".join(vt_data["tags"]) if vt_data["tags"] else "—"
        print(f"    VirusTotal -> {GREEN}[HTTP {vt_data['http_code']}]{RESET} "
              f"Malicious: {color}{vt_malicious}{RESET} | "
              f"Suspicious: {vt_data['suspicious']} | "
              f"País: {vt_data['country']} | "
              f"AS: {str(vt_data.get('as_owner','?'))[:30]}")
        print(f"                  Reputación: {rep_color}{rep}{RESET} | "
              f"Último análisis: {vt_data['last_analysis']} | "
              f"Tags: {tags_str}")
    else:
        print(f"    VirusTotal -> {RED}[HTTP {vt_data['http_code']}] ERROR: {vt_data.get('detail','')[:60]}{RESET}")

    # GreyNoise
    if gn_data is None:
        print(f"    GreyNoise  -> {GRAY}[SKIP]{RESET}")
    elif gn_data.get("status") == "ok":
        cl = gn_data["classification"]
        if cl == "malicious":
            cl_str = f"{RED}MALICIOSO{RESET}"
        elif cl == "benign":
            cl_str = f"{GREEN}BENIGNO (ruido internet){RESET}"
        else:
            cl_str = f"{GRAY}DESCONOCIDO{RESET}"
        riot_str = f" | {CYAN}RIOT (servicio legítimo){RESET}" if gn_data.get("riot") else ""
        name_str = f" | Nombre: {gn_data['name']}" if gn_data["name"] != "—" else ""
        seen_str = f" | Último: {gn_data['last_seen'][:10]}" if gn_data["last_seen"] != "?" else ""
        code_str = f"{GREEN}[HTTP 200]{RESET}" if gn_data["http_code"] == 200 else f"{GRAY}[HTTP 404]{RESET}"
        print(f"    GreyNoise  -> {code_str} {cl_str}{riot_str}{name_str}{seen_str}")
    else:
        print(f"    GreyNoise  -> {RED}[HTTP {gn_data['http_code']}] ERROR: {gn_data.get('detail','')[:60]}{RESET}")

    # AlienVault OTX
    if otx_data is None:
        print(f"    OTX        -> {GRAY}[SKIP]{RESET}")
    elif otx_data.get("status") == "ok":
        pulse_color = color if otx_pulses > 0 else GREEN
        tags_str    = ", ".join(otx_data["top_tags"]) if otx_data["top_tags"] else "—"
        print(f"    OTX        -> {GREEN}[HTTP {otx_data['http_code']}]{RESET} "
              f"Pulses: {pulse_color}{otx_pulses}{RESET} | "
              f"Reputación: {otx_data['reputation']} | "
              f"Tags: {tags_str}")
    else:
        print(f"    OTX        -> {RED}[HTTP {otx_data['http_code']}] ERROR: {otx_data.get('detail','')[:60]}{RESET}")

    # URLhaus
    if urlhaus_data is None:
        print(f"    URLhaus    -> {GRAY}[SKIP]{RESET}")
    elif urlhaus_data.get("status") == "ok":
        if urlhaus_found:
            online     = urlhaus_data["online_urls"]
            total      = urlhaus_data["total_urls"]
            online_str = f"{RED}{online} activas{RESET}" if online > 0 else f"{GRAY}{online} activas{RESET}"
            print(f"    URLhaus    -> {RED}[ENCONTRADO]{RESET} "
                  f"URLs de malware: {total} total | {online_str}")
        else:
            print(f"    URLhaus    -> {GREEN}[HTTP {urlhaus_data['http_code']}]{RESET} Sin resultados")
    else:
        print(f"    URLhaus    -> {RED}[HTTP {urlhaus_data['http_code']}] ERROR: {urlhaus_data.get('detail','')[:60]}{RESET}")

    # ThreatFox
    if threatfox_data is None:
        print(f"    ThreatFox  -> {GRAY}[SKIP]{RESET}")
    elif threatfox_data.get("status") == "ok":
        if threatfox_found:
            malware_str = ", ".join(threatfox_data["malware"]) or "?"
            threat_str  = ", ".join(threatfox_data["threat_types"]) or "?"
            conf        = threatfox_data["confidence"]
            conf_color  = RED if conf >= 75 else YELLOW
            print(f"    ThreatFox  -> {RED}[IOC DETECTADO]{RESET} "
                  f"Malware: {RED}{malware_str}{RESET} | "
                  f"Tipo: {threat_str} | "
                  f"Confianza: {conf_color}{conf}%{RESET} | "
                  f"IOCs: {threatfox_data['ioc_count']} | "
                  f"Visto: {threatfox_data['first_seen']}")
        else:
            print(f"    ThreatFox  -> {GREEN}[HTTP {threatfox_data['http_code']}]{RESET} Sin resultados")
    else:
        print(f"    ThreatFox  -> {RED}[HTTP {threatfox_data['http_code']}] ERROR: {threatfox_data.get('detail','')[:60]}{RESET}")

    print(f"    Riesgo     -> {color}{BOLD}{risk}{RESET}\n")
    return risk

# ─── MAIN ──────────────────────────────────────────────────
def main():
    ip_file = sys.argv[1] if len(sys.argv) > 1 else IP_FILE

    print(f"\n{BOLD}{CYAN}{'='*65}{RESET}")
    print(f"{BOLD}{CYAN}  SOC THREAT INTELLIGENCE CHECKER{RESET}")
    print(f"{BOLD}{CYAN}  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{BOLD}{CYAN}{'='*65}{RESET}\n")

    abuseipdb_ok, virustotal_ok, greynoise_ok, otx_ok, urlhaus_ok, threatfox_ok = verify_api_keys()
    IPS = load_ips(ip_file)

    results      = []
    critical_ips = []

    for entry in IPS:
        ip   = entry["ip"]
        user = entry["user"]

        abuse_data     = check_abuseipdb(ip, abuseipdb_ok)
        vt_data        = check_virustotal(ip, virustotal_ok)
        gn_data        = check_greynoise(ip, greynoise_ok)
        otx_data       = check_otx(ip, otx_ok)
        urlhaus_data   = check_urlhaus(ip, urlhaus_ok)
        threatfox_data = check_threatfox(ip, threatfox_ok)

        risk = print_ip_result(ip, user, abuse_data, vt_data, gn_data, otx_data, urlhaus_data, threatfox_data)

        result = {"ip": ip, "user": user, "risk": risk,
                  "abuseipdb": abuse_data, "virustotal": vt_data,
                  "greynoise": gn_data,    "otx": otx_data,
                  "urlhaus": urlhaus_data, "threatfox": threatfox_data}
        results.append(result)
        if risk in ("CRITICO", "ALTO"):
            critical_ips.append(result)

        time.sleep(0.5)

    # Resumen de llamadas
    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD}  RESUMEN DE LLAMADAS API{RESET}")
    print(f"{'='*65}")
    for api, s in api_stats.items():
        print(f"  {api:12s} -> "
              f"{GREEN}OK: {s['ok']}{RESET}  "
              f"{RED}Errores: {s['error']}{RESET}  "
              f"{GRAY}Saltadas: {s['skipped']}{RESET}  "
              f"(Total intentos: {s['ok'] + s['error']})")

    # Resumen de riesgos
    print(f"\n{BOLD}  RESUMEN DE RIESGOS{RESET}")
    print(f"{'='*65}")
    for nivel, col in [("CRITICO", RED), ("ALTO", RED), ("MEDIO", YELLOW), ("BAJO", GREEN)]:
        n = len([r for r in results if r["risk"] == nivel])
        print(f"  {nivel:8s}: {col}{n}{RESET}")

    if critical_ips:
        print(f"\n{BOLD}{RED}  ACCION REQUERIDA:{RESET}")
        for r in critical_ips:
            abuse    = r["abuseipdb"]  or {}
            vt       = r["virustotal"] or {}
            threatfox = r["threatfox"] or {}
            tf_str   = f"  {RED}[IOC: {', '.join(threatfox.get('malware', []))}]{RESET}" if threatfox.get("found") else ""
            print(f"    {RED}-> {r['ip']:20s}  usuario: {r['user']:<20s}  "
                  f"AbuseScore: {abuse.get('abuse_score','N/A')}%  "
                  f"VT malicious: {vt.get('malicious','N/A')}{RESET}{tf_str}")

    with open(OUTPUT_FILE, "w") as f:
        json.dump({"generated_at": datetime.now().isoformat(),
                   "ip_file": ip_file, "total_ips": len(IPS),
                   "api_stats": api_stats, "results": results},
                  f, indent=2, default=str)

    print(f"\n{GREEN}[+] Reporte guardado: {OUTPUT_FILE}{RESET}\n")

if __name__ == "__main__":
    main()
