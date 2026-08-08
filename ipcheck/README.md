# SOC IP Threat Intelligence Checker

Herramienta de línea de comandos para analizar IPs de alertas Wazuh contra múltiples fuentes de threat intelligence. Diseñada para trabajo en SOC: triage rápido, detección de C2, identificación de IPs de ataque activas y generación de reportes JSON.

## Arquitectura del pipeline

```
alertas_wazuh.csv / .xlsx
        │
        ▼
 procesar_excel      ──► ip_procesadas.txt   (historial acumulativo)
        │
        │  IPs públicas nuevas
        ▼
 ips_publicas_output.txt
        │
        ▼
 cli.py  (comando: ipcheck)
        │
        ├── AbuseIPDB
        ├── VirusTotal
        ├── GreyNoise
        ├── AlienVault OTX
        ├── URLhaus (abuse.ch)
        └── ThreatFox (abuse.ch)
        │
        ▼
 threat_report_YYYYMMDD_HHMMSS.json
```

## Instalación

`ipcheck` es un paquete del monorepo [Fennek115/separatio](https://github.com/Fennek115/separatio);
se instala una sola vez desde la raíz del repo:

```bash
git clone https://github.com/Fennek115/separatio intel
cd intel
python3 -m venv venv
venv/bin/pip install -e '.[dev]'
cp .env.example .env   # edita el .env de la RAÍZ con tus API keys
```

Quedan disponibles los comandos `ipcheck` (checker) e `ipcheck-run` (orquestador).

## Uso rápido — pipeline completo

```bash
ipcheck-run alertas_wazuh.csv
```

El orquestador ejecuta los dos pasos en secuencia:
1. Extrae IPs públicas nuevas del Excel (filtradas contra el historial)
2. Las analiza con el sistema de 3 niveles y genera el reporte

### Opciones del orquestador

```bash
# Solo extraer IPs, sin consultar APIs (para revisar antes de gastar cuota)
ipcheck-run alertas_wazuh.csv --solo-procesar

# Historial, output y Excel personalizados
ipcheck-run alertas_wazuh.csv --historial mis_ips.txt --output nuevas.txt --excel resultados.xlsx

# IPs que expiren en 90 días en lugar de 365
ipcheck-run alertas_wazuh.csv --expiry-dias 90

# Sin generar Excel
ipcheck-run alertas_wazuh.csv --no-excel
```

## Uso manual — paso a paso

### Paso 1: procesar el Excel de Wazuh

```bash
python -m ipcheck.procesar_excel alertas_wazuh.csv
```

El script:
- Muestra las columnas disponibles con ejemplos de valor
- Pregunta qué columnas contienen IPs (srcip, dstip, o ambas)
- Descarta IPs privadas, loopback, link-local, multicast y reservadas
- Consulta `ip_procesadas.txt` y salta las IPs ya analizadas antes
- Muestra el análisis de puertos entre las IPs nuevas
- Advierte sobre puertos sospechosos (4444, 1337, 31337, etc.)
- Estima cuántas requests de API consumirá
- Escribe `ips_publicas_output.txt` y actualiza `ip_procesadas.txt`

```bash
# Con historial y output personalizados
python -m ipcheck.procesar_excel alertas_wazuh.csv --historial mis_ips.txt --output nuevas.txt
```

### Paso 2: consultar APIs

```bash
ipcheck ips_publicas_output.txt
```

Genera `threat_report_YYYYMMDD_HHMMSS.json` con todos los resultados.

## Configuración de API keys

Edita el `.env` de la raíz del monorepo:

```env
ABUSEIPDB_API_KEY=tu_key_aqui
VIRUSTOTAL_API_KEY=tu_key_aqui
OTX_API_KEY=tu_key_aqui
ABUSECH_API_KEY=tu_key_aqui
```

| Dónde obtener cada key | |
|---|---|
| AbuseIPDB | [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) |
| VirusTotal | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) |
| AlienVault OTX | [otx.alienvault.com](https://otx.alienvault.com) → tu perfil → API Key |
| abuse.ch (URLhaus + ThreatFox) | [auth.abuse.ch](https://auth.abuse.ch) — cubre ambas APIs con una sola key |

Las APIs sin key (GreyNoise) funcionan automáticamente.

## APIs integradas y límites

| API | Key | Límite free | Qué aporta |
|-----|:---:|---|---|
| AbuseIPDB | Sí | 1.000 req/día | Abuse score 0-100, categorías de ataque, historial de reportes |
| VirusTotal | Sí | **500 req/día, 4 req/min** | Consenso de ~90 motores AV, reputación, tags |
| GreyNoise | No* | Sin límite con key gratuita | Clasifica si la IP es ruido de internet o amenaza activa |
| AlienVault OTX | Sí | Sin límite oficial | Threat pulses, familias de malware, infraestructura |
| URLhaus | Sí | Sin límite | IPs sirviendo URLs de malware activas |
| ThreatFox | Sí | Sin límite | IOCs de C2 activos (Cobalt Strike, QakBot, etc.) |
| **Shodan InternetDB** | **No** | **Sin límite documentado** | Puertos abiertos, CVEs conocidas, hostnames, software |
| **ip-api.com** | **No** | **45 req/min, sin límite diario** | Ciudad/región, ISP, ASN, detección proxy/datacenter |

> *GreyNoise sin key tiene un límite real de ~10 consultas/día. Crear cuenta gratuita en greynoise.io y configurar la key elimina ese límite.

> **VirusTotal es el cuello de botella:** 4 req/min en el plan free. El script espera 15 segundos entre IPs cuando VT está habilitado. Si la cuota diaria se agota (429), VT se deshabilita automáticamente para la sesión y las demás APIs continúan sin interrupción.

> **Shodan InternetDB e ip-api.com son gratuitos y sin key** — siempre activos.

## Análisis por niveles — protección de cuota

El checker analiza cada IP en cascada, parando en el nivel mínimo necesario:

| Nivel | APIs | Cuándo para | Resultado |
|-------|------|------------|-----------|
| **1** | ip-api + GreyNoise + Shodan | GreyNoise RIOT, o benign+datacenter sin puertos sospechosos | BAJO — no gasta AbuseIPDB ni VT |
| **2** | + AbuseIPDB + OTX | Score=0, Pulses=0, sin CVEs, sin proxy | BAJO — no gasta VT |
| **3** | + VirusTotal + URLhaus + ThreatFox | Siempre completa | Análisis completo |

En un export típico de Wazuh, el 40-60% de IPs (DNS públicos, CDNs, NTP conocidos) se resuelven en Nivel 1 sin tocar la cuota de VT.

## Mecanismo de historial y continuación de análisis

`ip_procesadas.txt` protege la cuota y permite continuar sesiones interrumpidas:

- El historial lo escribe **el checker** (no el procesador de Excel), IP a IP, justo después de verificar cada una
- Si el checker se interrumpe en la IP 15 de 100, solo las 15 verificadas están en historial — mañana el procesador encuentra las 85 restantes como nuevas
- Si la cuota de VT se agota a mitad de sesión, las IPs que necesitaban VT **no se registran** en historial → mañana se re-analizan con VT disponible
- IPs cortadas en Nivel 1 o 2 (sin señales) sí se registran → no se re-analizan

```
# Verificadas el 2026-05-12 14:30:00   ← escrito por el checker al iniciar sesión
1.1.1.1                                 ← registrada después de verificar (Nivel 1, RIOT)
190.102.231.147                         ← registrada después de verificar (Nivel 2, sin señales)
# Verificadas el 2026-05-13 09:00:00
203.0.113.45                            ← registrada (Nivel 3, análisis completo)
```

Las IPs expiran del historial después de `--expiry-dias` días (default: 365). Al expirar se re-analizan, útil porque las reputaciones de IPs cambian con el tiempo.

## Formato del archivo de IPs (manual)

Si querés alimentar el checker directamente sin pasar por el procesador:

```
# comentarios con #
185.220.101.45,john.doe      # IP con usuario asociado
10.0.0.5                     # solo IP — aparece como "desconocido"
```

El procesador escribe automáticamente el puerto como contexto:

```
190.102.231.147,p:123/NTP c:74
181.190.22.69,p:123/NTP c:24
```

Ese campo aparece como "usuario" en el output del checker, dando contexto inmediato del servicio contactado.

## Niveles de riesgo

| Nivel | Condiciones |
|-------|------------|
| **CRITICO** | AbuseIPDB ≥ 80%, VT malicious ≥ 5, GreyNoise = malicioso, o ThreatFox encontrado |
| **ALTO** | AbuseIPDB ≥ 50%, VT malicious ≥ 2, o OTX pulses ≥ 5 |
| **MEDIO** | AbuseIPDB ≥ 20%, VT malicious ≥ 1, OTX pulses ≥ 1, o URLhaus encontrado |
| **BAJO** | Sin indicadores de amenaza |

## Output de ejemplo

```
================================================================
  SOC THREAT INTELLIGENCE CHECKER
  2026-05-12 14:30:01
================================================================

[*] 185.220.101.45      usuario: p:22/SSH c:4821
    AbuseIPDB  -> [HTTP 200] Score: 100% | Reportes: 847 (312 usuarios) | País: DE
                  ISP: Frantech Solutions | Uso: Data Center | Último: 2026-05-11 | Categorías: SSH, Port Scan, BruteForce
    VirusTotal -> [HTTP 200] Malicious: 12 | Suspicious: 2 | País: DE | AS: Frantech Solutions
                  Reputación: -85 | Último análisis: 2026-05-10 | Tags: tor
    GreyNoise  -> [HTTP 200] MALICIOSO | Último: 2026-05-11
    OTX        -> [HTTP 200] Pulses: 14 | Reputación: -3 | Tags: tor, scanner, brute-force
    URLhaus    -> [HTTP 200] Sin resultados
    ThreatFox  -> [IOC DETECTADO] Malware: Cobalt Strike | Tipo: botnet_cc | Confianza: 90% | IOCs: 3
    Riesgo     -> CRITICO
```

## Estructura del reporte JSON

```json
{
  "generated_at": "2026-05-12T14:30:55",
  "ip_file": "ips_publicas_output.txt",
  "total_ips": 5,
  "api_stats": {
    "abuseipdb":  {"ok": 5, "error": 0, "skipped": 0},
    "virustotal": {"ok": 5, "error": 0, "skipped": 0},
    "greynoise":  {"ok": 5, "error": 0, "skipped": 0},
    "otx":        {"ok": 5, "error": 0, "skipped": 0},
    "urlhaus":    {"ok": 5, "error": 0, "skipped": 0},
    "threatfox":  {"ok": 5, "error": 0, "skipped": 0}
  },
  "results": [
    {
      "ip": "185.220.101.45",
      "user": "p:22/SSH c:4821",
      "risk": "CRITICO",
      "abuseipdb":  {"abuse_score": 100, "country": "DE", "isp": "Frantech Solutions", ...},
      "virustotal": {"malicious": 12, "suspicious": 2, ...},
      "greynoise":  {"classification": "malicious", "noise": true, ...},
      "otx":        {"pulse_count": 14, "reputation": -3, ...},
      "urlhaus":    {"found": false, ...},
      "threatfox":  {"found": true, "malware": ["Cobalt Strike"], "confidence": 90, ...}
    }
  ]
}
```

## Archivos del proyecto

```
ipcheck/                      # paquete dentro del monorepo (deps en el pyproject.toml raíz)
├── run.py                    # Orquestador (comando ipcheck-run): pipeline completo
├── procesar_excel.py         # Paso 1: extrae IPs del Excel de Wazuh
├── cli.py                    # Paso 2 (comando ipcheck): consulta de APIs
├── ip_enricher.py            # Librería reutilizable (la consume el pipeline Separatio)
├── ip_procesadas.txt         # Historial acumulativo (se crea automáticamente, gitignoreado)
├── ips_publicas_output.txt   # IPs nuevas del último procesamiento (gitignoreado)
└── threat_report_*.json      # Reportes generados por el checker (gitignoreados)
```

Las API keys viven en el `.env` de la **raíz del monorepo** (gitignoreado; ver `.env.example`).
