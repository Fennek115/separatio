# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the tool

Desde 2026-08-08 esto es el paquete `ipcheck` del monorepo `~/Projects/Intel/`
(instalado con `pip install -e '.[dev]'` en la raíz; deps en el `pyproject.toml` raíz):

```bash
# Default — reads IPs from ips.txt
venv/bin/ipcheck

# Custom IP file
venv/bin/ipcheck my_ips.txt

# Orquestador Wazuh completo
venv/bin/ipcheck-run alertas_wazuh.csv
```

Output: colored terminal summary + a timestamped JSON file (`threat_report_YYYYMMDD_HHMMSS.json`).

## API key configuration

Keys are loaded from the **root monorepo `.env`** (gitignored) via `python-dotenv` —
`cli.py` lo carga explícitamente; ya no existe `ipcheck/.env`:

```bash
cp .env.example .env   # en la raíz del monorepo; luego editar con las keys reales
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

### Pipeline files
| File | Role |
|---|---|
| `run.py` | Orchestrator (`ipcheck-run`) — runs `ipcheck.procesar_excel` then `ipcheck.cli` as modules |
| `procesar_excel.py` | Step 1 — extracts public IPs from Wazuh CSV/Excel export |
| `cli.py` | Step 2 (CLI, entry point `ipcheck`; ex `ip_threat_checker.py`) — colored output, history, Excel; delegates HTTP to `ip_enricher` |
| `ip_enricher.py` | **Reusable library** — pure check_* functions + `IpEnricher.enrich(ip)`; no globals, no I/O, no color |

### Reusable library (`ip_enricher.py`)

The query logic was extracted into `ip_enricher.py` so other projects can import
it without the CLI's global state, stdin prompts, colors or file writes. Design:

- `check_*` functions are pure: `(ip, key/enabled, timeout) -> dict | None`. No
  global mutation, no prints. `None` = source disabled (no key / `enabled=False`).
- `decidir_nivel`, `debe_pasar_nivel3`, `risk_level` are pure functions.
- `ApiKeys` (dataclass, `from_env()`) injects keys explicitly — no module globals,
  no `load_dotenv()` at import time.
- `IpEnricher(keys).enrich(ip) -> dict` is the entry point: orchestrates the
  Level 1→2→3 cascade, accumulates per-source `stats`, and remembers
  `vt_quota_exhausted`. `disabled={"virustotal", …}` forces-skips sources
  (authoritative — the call is not made). It does **not** sleep; the caller paces
  VT using `result["level_reached"]`.

```python
from ip_enricher import ApiKeys, IpEnricher
r = IpEnricher(ApiKeys.from_env()).enrich("185.220.101.45")
# r = {ip, risk, level_reached, level_complete, reason, abuseipdb, virustotal, ...}
```

The CLI keeps identical behavior: its `check_*` are thin wrappers that call the
library and update the global `api_stats`; `get_risk_level` adds terminal color.

Consumed by the `separatio` pipeline via its `enrichers/ip_reputation.py`
(Stage 2.7), which does `from ipcheck import ip_enricher` (package import;
the old `IPCHECK_DIR` path hack died with the monorepo, 2026-08-08).

Tests: `venv/bin/pytest tests/ -q` desde la raíz del monorepo (no network — HTTP monkeypatched).

### cli.py flow (ex ip_threat_checker.py)

1. `verify_api_keys()` — connectivity check against all 8 APIs using `8.8.8.8`; returns 8-tuple of booleans
2. `load_ips()` — parses the input file into `[{"ip": ..., "user": ...}]`
3. Main loop — **3-level tiered analysis** per IP (see below), then `print_ip_result()`
4. Summary — per-API call stats, risk counts, level distribution, VT requests saved, pending IPs
5. JSON dump + Excel update

### Tiered analysis logic (3 levels)

```
ALL IPs → Level 1: ip-api + GreyNoise + Shodan (free, no quota)
              │
              ├─ GreyNoise RIOT → STOP → BAJO → add to history ✓
              ├─ benign + datacenter + no suspicious ports → STOP → BAJO → history ✓
              │
              ▼
          Level 2: AbuseIPDB + OTX (1000/day, generous limits)
              │
              ├─ score=0 + pulses=0 + no CVEs + no proxy → STOP → BAJO → history ✓
              │
              ▼
          Level 3: VirusTotal + URLhaus + ThreatFox (limited quota)
              │
              ├─ VT OK → full analysis → history ✓
              ├─ VT quota exhausted (429 at runtime) → nivel_completo=False → NOT in history
              │   → IP will be retried tomorrow with fresh VT quota
              └─ VT key not configured → treated as intentional skip → history ✓
```

Key distinction: `vt_quota_agotada` flag (set on runtime 429) vs `vt_tenia_key` snapshot (False if key never configured). Only runtime quota exhaustion prevents history registration.

**Decision functions:** `decidir_nivel()` (Level 1 cutoff) and `debe_pasar_nivel3()` (Level 2 cutoff)

### Sleep strategy
- Level 3 with VT active: 15s (VirusTotal free = 4 req/min)
- Level 1 or 2 cutoff: 1s (VT not called)
- VT quota exhausted: 1s (no point waiting for VT)

**APIs and their check functions:**
| Function | Provider | Key required | What it adds |
|---|---|---|---|
| `check_abuseipdb()` | AbuseIPDB | Yes | Abuse score, attack categories, report history |
| `check_virustotal()` | VirusTotal | Yes | Multi-engine AV consensus, reputation tags |
| `check_greynoise()` | GreyNoise community | No | Scanner classification (benign noise vs active threat) |
| `check_otx()` | AlienVault OTX | Yes | Threat pulses, malware family tags |
| `check_urlhaus()` | abuse.ch URLhaus | Yes (ABUSECH_API_KEY) | Malware-serving URLs on the IP |
| `check_threatfox()` | abuse.ch ThreatFox | Yes (ABUSECH_API_KEY) | C2 IOC correlation (Cobalt Strike, QakBot, etc.) |
| `check_shodan()` | Shodan InternetDB | **No** | Open ports, CVEs, hostnames, software fingerprint |
| `check_ipapi()` | ip-api.com | **No** | City-level geolocation, ISP/ASN, proxy/datacenter flags |

**Rate limits (free tier):**
- VirusTotal: 4 req/min, 500 req/day → script sleeps 15s between IPs when VT enabled
- AbuseIPDB: 1,000 req/day
- GreyNoise: no documented limit with key; ~10/day without key
- ip-api.com: 45 req/min, no daily limit
- Shodan InternetDB: no documented limit
- OTX, URLhaus, ThreatFox: generous/no documented limits

**Risk thresholds** (`get_risk_level`):
| Level   | Conditions |
|---------|-----------|
| CRITICO | AbuseIPDB ≥ 80, VT malicious ≥ 5, GreyNoise = malicious, OR ThreatFox found |
| ALTO    | AbuseIPDB ≥ 50, VT malicious ≥ 2, OR OTX pulses ≥ 5 |
| MEDIO   | AbuseIPDB ≥ 20, VT malicious ≥ 1, OTX pulses ≥ 1, OR URLhaus found |
| BAJO    | Everything else |

Note: VT fields are 0 when Level 1/2 cutoff applies. Risk is still calculated from available data.

The global `api_stats` dict tracks ok/error/skipped counts per provider and is written into the JSON report.

### procesar_excel.py flow

1. `leer_archivo()` — reads CSV or Excel, strips Wazuh sort suffixes from column names (`: Descending`)
2. `seleccionar_columnas()` — interactive: user picks IP columns and optional port column
3. `extraer_ips()` — returns `(dict{canonical_ip: {tipo, puertos, count_total}}, n_invalidas, n_vacias)`. Uses canonical `str(ipaddress.ip_address())` as key to prevent duplicates from format variations
4. `leer_historial()` — reads `ip_procesadas.txt`, applies expiry by block timestamp, reports expired/sin_fecha counts
5. `mostrar_resumen()` — console output including port table and tiered-aware API quota estimate
6. `guardar_output()` — writes `ips_publicas_output.txt` with format `ip,p:PORT/NAME c:COUNT`, sorted IPv4 then IPv6
7. History is written by `ip_threat_checker.py`, NOT by this script

### History file format

```
# Verificadas el 2026-05-12 14:30:00   ← timestamp written by checker at session start
1.1.1.1                                 ← written immediately after each IP is verified
8.8.8.8
# Verificadas el 2026-05-13 09:00:00
190.102.231.147
```

IPs without a preceding timestamp block are kept regardless of expiry (conservative).
