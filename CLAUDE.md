# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the tool

```bash
pip install -r requirements.txt

# Default — reads IPs from ips.txt
python3 ip_threat_checker.py

# Custom IP file
python3 ip_threat_checker.py my_ips.txt
```

Output: colored terminal summary + a timestamped JSON file (`threat_report_YYYYMMDD_HHMMSS.json`).

## API key configuration

Keys are loaded from a `.env` file (gitignored) via `python-dotenv`:

```bash
cp .env.example .env   # then edit .env with real keys
```

The script reads them with `os.environ.get("KEY_NAME", "TU_API_KEY_AQUI")`. If a key is missing or equals `"TU_API_KEY_AQUI"`, that provider is skipped with `[SKIP]`.

GreyNoise, URLhaus, and Feodo Tracker require no key — always enabled.

## IP file format

```
# comment lines are ignored
192.168.1.1,username    # IP with associated user
10.0.0.1                # IP only — shown as "desconocido"
```

## Architecture

Single-file script (`ip_threat_checker.py`) with a linear flow:

1. `verify_api_keys()` — connectivity check against all APIs using `8.8.8.8`; returns a tuple of booleans `(abuseipdb_ok, virustotal_ok, greynoise_ok, otx_ok, urlhaus_ok, feodo_ok)`
2. `load_ips()` — parses the input file into `[{"ip": ..., "user": ...}]`
3. Main loop — for each IP calls all 6 check functions, then `print_ip_result()`, with a 0.5 s sleep between IPs
4. Summary — per-API call stats and per-risk-level counts; flags CRITICO/ALTO IPs under "ACCION REQUERIDA" with C2 info if Feodo detected
5. JSON dump of the full results dict

**APIs and their check functions:**
| Function | Provider | Key required |
|---|---|---|
| `check_abuseipdb()` | AbuseIPDB | Yes |
| `check_virustotal()` | VirusTotal | Yes |
| `check_greynoise()` | GreyNoise community | No |
| `check_otx()` | AlienVault OTX | Yes |
| `check_urlhaus()` | abuse.ch URLhaus | No |
| `check_feodo()` | abuse.ch Feodo Tracker | No |

**Risk thresholds** (`get_risk_level`):
| Level   | Conditions |
|---------|-----------|
| CRITICO | AbuseIPDB ≥ 80, VT malicious ≥ 5, GreyNoise = malicious, OR Feodo found |
| ALTO    | AbuseIPDB ≥ 50, VT malicious ≥ 2, OR OTX pulses ≥ 5 |
| MEDIO   | AbuseIPDB ≥ 20, VT malicious ≥ 1, OTX pulses ≥ 1, OR URLhaus found |
| BAJO    | Everything else |

The global `api_stats` dict tracks ok/error/skipped counts per provider and is written into the JSON report.
