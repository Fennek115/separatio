# SOC IP Threat Intelligence Checker

Herramienta de línea de comandos para analizar IPs contra múltiples fuentes de threat intelligence de forma simultánea. Diseñada para trabajo en SOC: triage rápido, detección de C2, identificación de IPs de ataque activas y generación de reportes JSON.

## APIs integradas

| API | Key requerida | Límite gratuito | Qué aporta |
|-----|:---:|---|---|
| [AbuseIPDB](https://www.abuseipdb.com) | Sí | 1.000 req/día | Abuse score, categorías de ataque, reportes históricos |
| [VirusTotal](https://www.virustotal.com) | Sí | 500 req/día | Detecciones por motores AV, reputación, tags |
| [GreyNoise](https://www.greynoise.io) | No | 1.000 req/día | Clasificación ruido/malicioso — clave para triage |
| [AlienVault OTX](https://otx.alienvault.com) | Sí | Sin límite oficial | Pulses de threat intel, familias de malware |
| [URLhaus](https://urlhaus.abuse.ch) | No | Sin límite | IPs sirviendo URLs de malware activas |
| [Feodo Tracker](https://feodotracker.abuse.ch) | No | Sin límite | Detección de C2 activos (Emotet, QakBot, etc.) |

## Output de ejemplo

```
=================================================================
  SOC THREAT INTELLIGENCE CHECKER
  2025-04-27 10:32:11
=================================================================

[*] 185.220.101.45      usuario: desconocido
    AbuseIPDB  -> [HTTP 200] Score: 100% | Reportes: 847 (312 usuarios) | País: DE
                  ISP: Frantech Solutions | Uso: Data Center | Último: 2025-04-26 | Categorías: SSH, Port Scan, BruteForce
    VirusTotal -> [HTTP 200] Malicious: 12 | Suspicious: 2 | País: DE | AS: Frantech Solutions
                  Reputación: -85 | Último análisis: 2025-04-25 | Tags: tor
    GreyNoise  -> [HTTP 200] MALICIOSO | Último: 2025-04-26
    OTX        -> [HTTP 200] Pulses: 14 | Reputación: -3 | Tags: tor, scanner, brute-force
    URLhaus    -> [HTTP 200] Sin resultados
    Feodo      -> [C2 DETECTADO] Malware: Emotet | Estado: online | Visto: 2024-12-01 → 2025-04-26
    Riesgo     -> CRITICO
```

## Niveles de riesgo

| Nivel | Condiciones |
|-------|------------|
| **CRITICO** | AbuseIPDB ≥ 80%, VT malicious ≥ 5, GreyNoise = malicioso, o Feodo encontrado |
| **ALTO** | AbuseIPDB ≥ 50%, VT malicious ≥ 2, o OTX pulses ≥ 5 |
| **MEDIO** | AbuseIPDB ≥ 20%, VT malicious ≥ 1, OTX pulses ≥ 1, o URLhaus encontrado |
| **BAJO** | Sin indicadores de amenaza |

## Instalación

```bash
git clone https://github.com/tu-usuario/ipcheck.git
cd ipcheck
pip install -r requirements.txt
```

## Configuración de API keys

```bash
cp .env.example .env
```

Edita `.env` y rellena tus keys:

```env
ABUSEIPDB_API_KEY=tu_key_aqui
VIRUSTOTAL_API_KEY=tu_key_aqui
OTX_API_KEY=tu_key_aqui
```

Dónde obtener cada key:
- **AbuseIPDB**: [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api)
- **VirusTotal**: [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)
- **OTX**: [otx.alienvault.com](https://otx.alienvault.com) → tu perfil → API Key

GreyNoise, URLhaus y Feodo Tracker no requieren key — funcionan automáticamente.

## Uso

Crea un archivo de IPs (una por línea). El usuario es opcional:

```
# formato: IP,usuario  (el usuario es opcional)
192.168.1.1,john.doe
10.0.0.5
185.220.101.45,sospechoso
```

Ejecuta el script:

```bash
# usando el archivo por defecto (ips.txt)
python3 ip_threat_checker.py

# con un archivo personalizado
python3 ip_threat_checker.py mi_lista.txt
```

Al terminar se genera un reporte JSON con todos los datos en `threat_report_YYYYMMDD_HHMMSS.json`.

## Estructura del reporte JSON

```json
{
  "generated_at": "2025-04-27T10:32:55",
  "ip_file": "ips.txt",
  "total_ips": 5,
  "api_stats": { "abuseipdb": {"ok": 5, "error": 0, "skipped": 0}, ... },
  "results": [
    {
      "ip": "185.220.101.45",
      "user": "desconocido",
      "risk": "CRITICO",
      "abuseipdb": { "abuse_score": 100, "country": "DE", ... },
      "virustotal": { "malicious": 12, ... },
      "greynoise":  { "classification": "malicious", ... },
      "otx":        { "pulse_count": 14, ... },
      "urlhaus":    { "found": false, ... },
      "feodo":      { "found": true, "malware": "Emotet", "c2_status": "online", ... }
    }
  ]
}
```
