#!/usr/bin/env python3
"""
SOC IP Threat Intelligence Checker
Verifica IPs contra AbuseIPDB, VirusTotal, GreyNoise, AlienVault OTX,
URLhaus y ThreatFox (abuse.ch)
Uso: python3 ip_threat_checker.py [archivo.txt]
"""

import argparse
import requests
import json
import time
import sys
import os
from datetime import datetime
from dotenv import load_dotenv

from ipcheck import ip_enricher

load_dotenv()

# ─── CONFIGURACIÓN ────────────────────────────────────────
ABUSEIPDB_API_KEY  = os.environ.get("ABUSEIPDB_API_KEY",  "TU_API_KEY_AQUI")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "TU_API_KEY_AQUI")
OTX_API_KEY        = os.environ.get("OTX_API_KEY",        "TU_API_KEY_AQUI")
ABUSECH_API_KEY    = os.environ.get("ABUSECH_API_KEY",    "TU_API_KEY_AQUI")  # https://auth.abuse.ch — vale para URLhaus y ThreatFox
IP_FILE            = "ip_threat_checker.txt"
HISTORIAL_FILE     = "ip_procesadas.txt"
EXCEL_FILE         = "threat_results.xlsx"
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
    "shodan":     {"ok": 0, "error": 0, "skipped": 0},
    "ipapi":      {"ok": 0, "error": 0, "skipped": 0},
}

# Campos que pedimos a ip-api.com en cada consulta
IPAPI_FIELDS = "status,message,country,countryCode,regionName,city,isp,org,as,proxy,hosting,mobile"

# Puertos que elevan una IP al Nivel 3 aunque no haya señales en Abuse/OTX
PUERTOS_C2_SOSPECHOSOS = {
    4444, 1337, 31337, 6666, 6667, 7777, 8888, 9999,
    12345, 54321, 1234, 5555, 1080, 9001, 9030,
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

    # Shodan InternetDB — sin key, sin cuota documentada
    try:
        r = requests.get("https://internetdb.shodan.io/8.8.8.8", timeout=10)
        if r.status_code in (200, 404):
            print(f"    {'shodan':12s} -> {GREEN}[OK] Conectado correctamente — HTTP {r.status_code}{RESET}")
            results["shodan"] = True
        else:
            print(f"    {'shodan':12s} -> {RED}[ERROR] Respuesta inesperada — HTTP {r.status_code}{RESET}")
            results["shodan"] = False
    except Exception as e:
        print(f"    {'shodan':12s} -> {RED}[ERROR] Sin conexion: {e}{RESET}")
        results["shodan"] = False

    # ip-api.com — sin key, 45 req/min (plan free usa HTTP)
    try:
        r = requests.get(f"http://ip-api.com/json/8.8.8.8?fields={IPAPI_FIELDS}", timeout=10)
        if r.status_code == 200 and r.json().get("status") == "success":
            print(f"    {'ipapi':12s} -> {GREEN}[OK] Conectado correctamente — HTTP {r.status_code}{RESET}")
            results["ipapi"] = True
        elif r.status_code == 429:
            print(f"    {'ipapi':12s} -> {YELLOW}[WARN] Rate limit — HTTP 429{RESET}")
            results["ipapi"] = True
        else:
            print(f"    {'ipapi':12s} -> {RED}[ERROR] Respuesta inesperada — HTTP {r.status_code}{RESET}")
            results["ipapi"] = False
    except Exception as e:
        print(f"    {'ipapi':12s} -> {RED}[ERROR] Sin conexion: {e}{RESET}")
        results["ipapi"] = False

    print()
    return (results.get("abuseipdb", False), results.get("virustotal", False),
            results.get("greynoise", False), results.get("otx", False),
            results.get("urlhaus", False), results.get("threatfox", False),
            results.get("shodan", False),   results.get("ipapi", False))

# ─────────────────────────────────────────────────────────
# CONSULTAS A APIS — delegadas a ip_enricher (librería pura).
# Estos wrappers conservan la firma (ip, enabled) usada en main(),
# la mutación de api_stats y, para el riesgo, el color de terminal.
# ─────────────────────────────────────────────────────────

def _record(api, result):
    """Actualiza api_stats según el status del resultado de ip_enricher."""
    if result is None:
        api_stats[api]["skipped"] += 1
    elif result.get("status") == "ok":
        api_stats[api]["ok"] += 1
    else:  # "error" o "quota"
        api_stats[api]["error"] += 1
    return result


def check_abuseipdb(ip, enabled):
    if not enabled:
        return _record("abuseipdb", None)
    return _record("abuseipdb", ip_enricher.check_abuseipdb(ip, ABUSEIPDB_API_KEY))


def check_virustotal(ip, enabled):
    if not enabled:
        return _record("virustotal", None)
    return _record("virustotal", ip_enricher.check_virustotal(ip, VIRUSTOTAL_API_KEY))


def check_greynoise(ip, enabled):
    return _record("greynoise", ip_enricher.check_greynoise(ip, enabled))


def check_otx(ip, enabled):
    if not enabled:
        return _record("otx", None)
    return _record("otx", ip_enricher.check_otx(ip, OTX_API_KEY))


def check_urlhaus(ip, enabled):
    if not enabled:
        return _record("urlhaus", None)
    return _record("urlhaus", ip_enricher.check_urlhaus(ip, ABUSECH_API_KEY))


def check_threatfox(ip, enabled):
    if not enabled:
        return _record("threatfox", None)
    return _record("threatfox", ip_enricher.check_threatfox(ip, ABUSECH_API_KEY))


def check_shodan(ip, enabled):
    return _record("shodan", ip_enricher.check_shodan(ip, enabled))


def check_ipapi(ip, enabled):
    return _record("ipapi", ip_enricher.check_ipapi(ip, enabled))


# Lógica de decisión por niveles — reexportada desde ip_enricher (sin cambios).
decidir_nivel     = ip_enricher.decidir_nivel
debe_pasar_nivel3 = ip_enricher.debe_pasar_nivel3

# Mapa de color por nivel de riesgo (solo presentación del CLI).
_RISK_COLORS = {"CRITICO": RED, "ALTO": RED, "MEDIO": YELLOW, "BAJO": GREEN}


def get_risk_level(abuse_score, vt_malicious, gn_classification, otx_pulses, threatfox_found, urlhaus_found):
    label = ip_enricher.risk_level(abuse_score, vt_malicious, gn_classification,
                                   otx_pulses, threatfox_found, urlhaus_found)
    return label, _RISK_COLORS[label]

# ─── IMPRIMIR RESULTADO DE UNA IP ─────────────────────────
def print_ip_result(ip, user, abuse_data, vt_data, gn_data, otx_data, urlhaus_data, threatfox_data, shodan_data=None, ipapi_data=None):
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
    elif vt_data.get("status") == "quota":
        print(f"    VirusTotal -> {YELLOW}[CUOTA AGOTADA] Se omite para IPs restantes{RESET}")
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

    # Shodan InternetDB
    if shodan_data is None:
        print(f"    Shodan     -> {GRAY}[SKIP]{RESET}")
    elif shodan_data.get("status") == "ok":
        if shodan_data["http_code"] == 404:
            print(f"    Shodan     -> {GRAY}[HTTP 404]{RESET} IP no indexada")
        else:
            ports_str = ", ".join(str(p) for p in shodan_data["ports"][:10]) or "—"
            hosts_str = ", ".join(shodan_data["hostnames"][:3]) or "—"
            tags_str  = ", ".join(shodan_data["tags"]) or "—"
            vulns     = shodan_data["vulns"]
            cpes      = shodan_data["cpes"]
            vuln_color = RED if vulns else GREEN
            print(f"    Shodan     -> {GREEN}[HTTP 200]{RESET} "
                  f"Puertos: {ports_str} | "
                  f"Hostnames: {hosts_str} | "
                  f"Tags: {tags_str}")
            if vulns:
                vuln_str = ", ".join(vulns[:5])
                mas = f" (+{len(vulns)-5} más)" if len(vulns) > 5 else ""
                print(f"                  {RED}CVEs: {vuln_str}{mas}{RESET}")
            if cpes:
                cpe_str = ", ".join(c.split(":")[-1] for c in cpes[:4])
                print(f"                  Software: {cpe_str}")
    else:
        print(f"    Shodan     -> {RED}[HTTP {shodan_data['http_code']}] ERROR: {shodan_data.get('detail','')[:60]}{RESET}")

    # ip-api.com
    if ipapi_data is None:
        print(f"    ip-api     -> {GRAY}[SKIP]{RESET}")
    elif ipapi_data.get("status") == "ok":
        proxy_str   = f"  {YELLOW}[PROXY]{RESET}"   if ipapi_data.get("proxy")   else ""
        hosting_str = f"  {CYAN}[DATACENTER]{RESET}" if ipapi_data.get("hosting") else ""
        mobile_str  = f"  [MOBILE]"                  if ipapi_data.get("mobile")  else ""
        print(f"    ip-api     -> {GREEN}[HTTP 200]{RESET} "
              f"{ipapi_data['city']}, {ipapi_data['region']}, {ipapi_data['country']}"
              f"{proxy_str}{hosting_str}{mobile_str}")
        print(f"                  ISP: {str(ipapi_data['isp'])[:45]} | "
              f"ASN: {ipapi_data['asn']}")
    else:
        print(f"    ip-api     -> {RED}[HTTP {ipapi_data['http_code']}] ERROR: {ipapi_data.get('detail','')[:60]}{RESET}")

    print(f"    Riesgo     -> {color}{BOLD}{risk}{RESET}\n")
    return risk

# ─── HISTORIAL ────────────────────────────────────────────
def inicializar_sesion_historial(path):
    """Escribe el encabezado de timestamp para esta sesión antes de entrar al loop."""
    try:
        with open(path, 'a') as f:
            f.write(f"\n# Verificadas el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    except Exception as e:
        print(f"{YELLOW}[!] No se pudo inicializar historial: {e}{RESET}")


def registrar_ip_en_historial(ip, path):
    """Agrega la IP al historial inmediatamente después de verificarla."""
    try:
        with open(path, 'a') as f:
            f.write(f"{ip}\n")
    except Exception as e:
        print(f"{YELLOW}[!] No se pudo registrar {ip} en historial: {e}{RESET}")


# ─── EXCEL ACUMULATIVO ────────────────────────────────────
def actualizar_excel(results, excel_path):
    """
    Agrega los resultados de esta sesión al Excel acumulativo.
    Si el archivo ya existe lo extiende; nunca borra filas anteriores.
    """
    try:
        import pandas as pd
    except ImportError:
        print(f"{YELLOW}[!] pandas no instalado — Excel omitido. pip install pandas openpyxl{RESET}")
        return

    filas = []
    ahora = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    for r in results:
        abuse  = r.get("abuseipdb")  or {}
        vt     = r.get("virustotal") or {}
        gn     = r.get("greynoise")  or {}
        otx    = r.get("otx")        or {}
        url    = r.get("urlhaus")    or {}
        tf     = r.get("threatfox")  or {}
        sh     = r.get("shodan")     or {}
        ip_api = r.get("ipapi")      or {}

        ok = lambda d: d.get("status") == "ok"

        # Geolocalización: preferir ip-api (ciudad) sobre AbuseIPDB/VT (solo país)
        pais   = ip_api.get("country", abuse.get("country", vt.get("country", "?"))) if ok(ip_api) or ok(abuse) or ok(vt) else "?"
        ciudad = f"{ip_api.get('city','?')}, {ip_api.get('region','?')}" if ok(ip_api) else ""

        filas.append({
            "IP":                 r["ip"],
            "Fecha":              ahora,
            "Riesgo":             r["risk"],
            "Nivel_Analisis":     r.get("nivel", 3),
            "Contexto":           r.get("user", ""),
            "Ciudad":             ciudad,
            "Pais":               pais,
            "ISP":                ip_api.get("isp", abuse.get("isp", "?")) if ok(ip_api) or ok(abuse) else "",
            "ASN":                ip_api.get("asn", "")              if ok(ip_api) else "",
            "Proxy":              ip_api.get("proxy", "")            if ok(ip_api) else "",
            "Datacenter":         ip_api.get("hosting", "")          if ok(ip_api) else "",
            "AbuseScore":         abuse.get("abuse_score", "")       if ok(abuse)  else "",
            "Abuse_Reportes":     abuse.get("total_reports", "")     if ok(abuse)  else "",
            "Abuse_Categorias":   ", ".join(abuse.get("top_categories", [])) if ok(abuse) else "",
            "VT_Malicious":       vt.get("malicious", "")            if ok(vt)     else "",
            "VT_Suspicious":      vt.get("suspicious", "")           if ok(vt)     else "",
            "VT_Reputacion":      vt.get("reputation", "")           if ok(vt)     else "",
            "GN_Clasificacion":   gn.get("classification", "")       if ok(gn)     else "",
            "GN_RIOT":            gn.get("riot", "")                 if ok(gn)     else "",
            "OTX_Pulses":         otx.get("pulse_count", "")         if ok(otx)    else "",
            "OTX_Tags":           ", ".join(otx.get("top_tags", [])) if ok(otx)    else "",
            "URLhaus":            url.get("found", "")               if ok(url)    else "",
            "URLhaus_URLs":       url.get("total_urls", "")          if ok(url)    else "",
            "ThreatFox":          tf.get("found", "")                if ok(tf)     else "",
            "ThreatFox_Malware":  ", ".join(tf.get("malware", []))   if ok(tf)     else "",
            "ThreatFox_Confianza": tf.get("confidence", "")          if ok(tf)     else "",
            "Shodan_Puertos":     ", ".join(str(p) for p in sh.get("ports", [])) if ok(sh) else "",
            "Shodan_CVEs":        ", ".join(sh.get("vulns", []))     if ok(sh)     else "",
            "Shodan_Hostnames":   ", ".join(sh.get("hostnames", [])) if ok(sh)     else "",
            "Shodan_Software":    ", ".join(c.split(":")[-1] for c in sh.get("cpes", [])) if ok(sh) else "",
        })

    df_nuevo = pd.DataFrame(filas)

    if os.path.exists(excel_path):
        try:
            df_previo = pd.read_excel(excel_path)
            df_final = pd.concat([df_previo, df_nuevo], ignore_index=True)
        except Exception:
            df_final = df_nuevo
    else:
        df_final = df_nuevo

    try:
        df_final.to_excel(excel_path, index=False)
        print(f"{GREEN}[+] Excel actualizado: {excel_path} ({len(df_final)} filas totales){RESET}")
    except Exception as e:
        print(f"{RED}[!] Error escribiendo Excel: {e}{RESET}")


# ─── MAIN ──────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="SOC Threat Intelligence Checker — consulta IPs contra múltiples APIs"
    )
    parser.add_argument("ip_file", nargs="?", default=IP_FILE,
                        help=f"Archivo de IPs a verificar (default: {IP_FILE})")
    parser.add_argument("--historial", default=HISTORIAL_FILE,
                        metavar="PATH",
                        help=f"Archivo de historial donde registrar IPs verificadas (default: {HISTORIAL_FILE})")
    parser.add_argument("--excel", default=EXCEL_FILE,
                        metavar="PATH",
                        help=f"Excel acumulativo de resultados (default: {EXCEL_FILE})")
    parser.add_argument("--no-excel", action="store_true",
                        help="No generar ni actualizar el Excel de resultados")
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}{'='*65}{RESET}")
    print(f"{BOLD}{CYAN}  SOC THREAT INTELLIGENCE CHECKER{RESET}")
    print(f"{BOLD}{CYAN}  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{BOLD}{CYAN}{'='*65}{RESET}\n")

    abuseipdb_ok, virustotal_ok, greynoise_ok, otx_ok, urlhaus_ok, threatfox_ok, shodan_ok, ipapi_ok = verify_api_keys()
    IPS = load_ips(args.ip_file)

    results      = []
    critical_ips = []
    vt_pendientes = []        # IPs que necesitaban VT pero la cuota se agotó
    vt_tenia_key  = virustotal_ok   # snapshot antes del loop para distinguir
                                    # "sin key desde el inicio" de "cuota agotada en sesión"
    vt_quota_agotada = False  # se activa cuando VT devuelve 429 en tiempo de ejecución

    inicializar_sesion_historial(args.historial)

    for entry in IPS:
        ip   = entry["ip"]
        user = entry["user"]

        # ── NIVEL 1: ip-api + GreyNoise + Shodan ──────────────
        # Siempre gratuito, sin cuota relevante.
        ipapi_data  = check_ipapi(ip, ipapi_ok)
        gn_data     = check_greynoise(ip, greynoise_ok)
        shodan_data = check_shodan(ip, shodan_ok)

        pasar_n2, motivo_corte = decidir_nivel(gn_data, ipapi_data, shodan_data)

        # Inicializar el resto como None para que print_ip_result muestre [SKIP]
        abuse_data = otx_data = vt_data = urlhaus_data = threatfox_data = None

        nivel_alcanzado = 1
        nivel_completo  = True   # True = IP procesada correctamente en su nivel

        if not pasar_n2:
            # Corte en Nivel 1 — no gastar cuota de AbuseIPDB/OTX/VT
            print(f"    {GRAY}[Nivel 1] Corte: {motivo_corte} — se omite análisis profundo{RESET}")
        else:
            # ── NIVEL 2: AbuseIPDB + OTX ──────────────────────
            abuse_data = check_abuseipdb(ip, abuseipdb_ok)
            otx_data   = check_otx(ip, otx_ok)
            nivel_alcanzado = 2

            necesita_n3, motivo_n3 = debe_pasar_nivel3(abuse_data, otx_data, shodan_data, ipapi_data)

            if not necesita_n3:
                print(f"    {GRAY}[Nivel 2] Sin señales ({motivo_n3}) — VT/URLhaus/ThreatFox omitidos{RESET}")
            else:
                # ── NIVEL 3: VT + URLhaus + ThreatFox ─────────
                print(f"    {CYAN}[Nivel 3] Señales detectadas ({motivo_n3}) — análisis completo{RESET}")
                vt_data        = check_virustotal(ip, virustotal_ok)
                urlhaus_data   = check_urlhaus(ip, urlhaus_ok)
                threatfox_data = check_threatfox(ip, threatfox_ok)
                nivel_alcanzado = 3

                # Detectar cuota VT agotada (429 en tiempo de ejecución)
                if vt_data and vt_data.get("status") == "quota":
                    virustotal_ok    = False
                    vt_quota_agotada = True
                    nivel_completo   = False
                    print(f"\n    {YELLOW}{BOLD}[!] Cuota diaria de VirusTotal agotada.{RESET}")
                    print(f"        Esta IP y las restantes que necesiten Nivel 3 se re-analizarán mañana.")
                    print(f"        IPs de Nivel 1/2 se registran normalmente.\n")
                elif vt_quota_agotada:
                    # VT fue deshabilitado por cuota en una IP anterior de esta sesión
                    nivel_completo = False
                # Si vt_tenia_key es False desde el inicio, VT nunca estuvo disponible:
                # se trata como skip intencional y la IP SÍ se registra en historial.

        risk = print_ip_result(ip, user, abuse_data, vt_data, gn_data, otx_data,
                               urlhaus_data, threatfox_data, shodan_data, ipapi_data)

        result = {
            "ip": ip, "user": user, "risk": risk, "nivel": nivel_alcanzado,
            "abuseipdb": abuse_data, "virustotal": vt_data,
            "greynoise": gn_data,    "otx":        otx_data,
            "urlhaus":   urlhaus_data, "threatfox": threatfox_data,
            "shodan":    shodan_data,  "ipapi":     ipapi_data,
        }
        results.append(result)
        if risk in ("CRITICO", "ALTO"):
            critical_ips.append(result)

        # Registrar en historial solo si el análisis está completo para este nivel.
        # Si VT era necesario pero la cuota lo bloqueó, no registrar → mañana se reintenta.
        if nivel_completo:
            registrar_ip_en_historial(ip, args.historial)
        else:
            vt_pendientes.append(ip)
            print(f"    {YELLOW}[!] {ip} no registrada en historial → pendiente de VT mañana{RESET}")

        # Sleep de rate-limit: 15s si VT activo, 1s si corte en Nivel 1 o 2, o cuota agotada.
        if virustotal_ok and nivel_alcanzado == 3:
            print(f"    {GRAY}[rate limit VT: esperando 15s...]{RESET}")
            time.sleep(15)
        else:
            time.sleep(1)

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

    # Resumen de niveles
    niveles = {1: 0, 2: 0, 3: 0}
    for r in results:
        niveles[r.get("nivel", 3)] += 1
    print(f"\n{BOLD}  DISTRIBUCIÓN POR NIVEL{RESET}")
    print(f"{'='*65}")
    print(f"  Nivel 1 (corte temprano, sin cuota):    {niveles[1]:>4}  IPs  {GRAY}← VT/Abuse/OTX ahorradas{RESET}")
    print(f"  Nivel 2 (Abuse+OTX, sin VT):            {niveles[2]:>4}  IPs  {GRAY}← VT ahorrada{RESET}")
    print(f"  Nivel 3 (análisis completo):             {niveles[3]:>4}  IPs")
    vt_calls = api_stats["virustotal"]["ok"] + api_stats["virustotal"]["error"]
    vt_saved = len(IPS) - vt_calls
    if vt_saved > 0:
        print(f"  {GREEN}VT requests ahorradas esta sesión: {vt_saved} de {len(IPS)}{RESET}")
    if vt_pendientes:
        print(f"\n  {YELLOW}IPs pendientes de VT mañana ({len(vt_pendientes)}): {', '.join(vt_pendientes[:5])}"
              f"{'...' if len(vt_pendientes) > 5 else ''}{RESET}")

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
                   "ip_file": args.ip_file, "total_ips": len(IPS),
                   "api_stats": api_stats, "results": results},
                  f, indent=2, default=str)

    print(f"\n{GREEN}[+] Reporte JSON: {OUTPUT_FILE}{RESET}")

    if not args.no_excel and results:
        actualizar_excel(results, args.excel)
    print()

if __name__ == "__main__":
    main()
