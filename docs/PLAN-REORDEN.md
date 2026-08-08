# PLAN-REORDEN — Reestructuración de ~/Projects/Intel/

Escrito el 2026-08-07 tras relevar el estado real (regla: **gana la máquina**).
Este documento es el plan de la reestructuración pendiente (frente 1). El OCR de imágenes
(frente 2, AIOCRIOC reimplementado) queda para después, sobre la estructura nueva.

---

## 1. Estado verificado contra la máquina (2026-08-07)

| Qué | Estado real |
|---|---|
| `threat intel/` (git `Fennek115/separatio`) | **Limpio**, HEAD `32412b8`, empujado |
| `ipcheck/` (git `Fennek115/ip_threatcheck`, **público** — "sin remoto" era falso) | **Sucio**: 5 modificados + ~15 sin trackear (xlsx, csv, `threat_report_*.json`, logs, `Zone.Identifier`) — datos de corridas mezclados con código. → **Limpiado 2026-08-08** (§5 paso 1) |
| `./.env` (raíz) | 9 vars. **Sin `ANTHROPIC_API_KEY`** (bloqueante del pipeline) |
| `ipcheck/.env` | 5 vars, **3 duplicadas** con la raíz (ABUSEIPDB, OTX, ABUSECH) y 2 que la raíz no tiene: **`VIRUSTOTAL_API_KEY`** (¡existe! el pipeline no la ve porque carga solo el `.env` raíz) y `URLSCAN_API_KEY` |
| Miniflux (CT 112) | API responde, token válido (admin). **0 feeds cargados.** Las 5 categorías existen (`Cibersecurity` 6, `Hacking & Research` 7, `Threat Intel` 8, `Vulnerability` 9, `LATAM` 63, todas vacías) |
| `feeds.opml` | 56 feeds en 4 categorías. **Es la fuente a reimportar** — hay que curarlo ANTES de importar (§2) |
| Basura en `threat intel/` | `threat-analysis-feeds.opml` (duplicado viejo del OPML) + su `Zone.Identifier`, `__pycache__/`, `venv/` y `output-threatintel/` dentro del repo |

**Dos trampas detectadas:**

1. **Mismatch de categoría:** el OPML dice `text="Hacking"`, pero Miniflux/`PHASE_CATEGORY_MAP`
   usan `Hacking & Research`. Importar el OPML tal cual crearía una categoría nueva "Hacking"
   cuyos artículos **no rutearían a la fase threat_intel**. Corregir el OPML antes de importar.
2. **`VIRUSTOTAL_API_KEY` no está perdida** — está en `ipcheck/.env`, que el pipeline no carga.
   Al unificar los `.env`, VirusTotal entra al enricher `ip_reputation` gratis.

---

## 2. Auditoría de feeds (verificada por HTTP el 2026-08-07)

> **RESUELTO el 2026-08-08:** el usuario recuró el OPML (40 feeds, categorías correctas,
> LATAM con 5 fuentes) y lo importó. Los dos feeds que quedaron con error (Mandiant con URL
> muerta y Google TAG cuyo RSS ya no existe) se unificaron en **Google Threat Intelligence
> (Mandiant/TAG)** — GTIG los fusionó en 2025 — apuntando a
> `https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/` (la URL análoga en
> `cloud.google.com` devuelve HTML, no XML). Estado final verificado por API: **39 feeds,
> 0 errores**. `feeds.opml` ya refleja esto. Lo de abajo queda como registro de la auditoría.

### Bajas / reemplazos (los 4 rotos, confirmados)

| Feed | Verificación | Acción |
|---|---|---|
| NVD `nvd-rss.xml` | **404** — NVD retiró sus RSS | **Quitar.** El pipeline ya cubre CVEs por KEV + EPSS (correlator) + CISA + MSRC + CERT/CC + Full Disclosure. Como reemplazo del flujo de advisories: **ZDI published advisories** `https://www.zerodayinitiative.com/rss/published/` (**200 ✓**, además alimenta la detección de PoC del correlator). Marcar `hideGlobally` como estaba NVD |
| Mandiant `mandiant.com/resources/blog/rss.xml` | Redirige a `cloud.google.com/security/mandiant` sin feed | **Reemplazar** por Google Cloud Threat Intelligence (el blog de Mandiant post-adquisición): `https://cloud.google.com/blog/topics/threat-intelligence/rss/` (**200 ✓**), categoría Threat Intel |
| Black Hills InfoSec `/feed/` | **404**; también 404 `/blog/feed/`, `/feed/atom/`, `/rss/`, `/feed/podcast/`; la home no expone `<link rel=alternate>` | **Quitar** (el sitio eliminó los feeds WordPress al reestructurarse). Su contenido de pentest queda cubierto por Outflank/PortSwigger/WatchTowr. Re-evaluar en unos meses por si restauran el feed |
| HackRead `/feed/` | **403** incluso con User-Agent de navegador (Cloudflare bloquea clientes no-browser; Miniflux nunca va a pasar) | **Quitar.** Cobertura redundante con BleepingComputer / The Hacker News / SecurityWeek |

### Altas — LATAM (categoría 63 vacía → sección del informe en blanco)

Verificados con **200 ✓** el 2026-08-07:

| Feed | URL | Por qué |
|---|---|---|
| WeLiveSecurity en español (ESET LATAM) | `https://www.welivesecurity.com/la-es/feed/` | Investigación con foco LATAM real (ESET tiene lab en Buenos Aires) |
| Segu-Info (Argentina) | `https://blog.segu-info.com.ar/feeds/posts/default?alt=rss` | La referencia de noticias infosec de Argentina, volumen diario |
| Una al día (Hispasec) | `https://unaaldia.hispasec.com/feed` | Noticia diaria en español, foco vulnerabilidades, 25+ años |
| INCIBE-CERT avisos | `https://www.incibe.es/incibe-cert/alerta-temprana/avisos/feed` | Avisos de vulnerabilidades en español (España, no LATAM estricto — opcional; volumen alto: considerar `hideGlobally`) |

Descartados por muertos: `blog.cronup.com/feed` (timeout), `csirt.gob.cl/feed/` (404),
`welivesecurity.com/es/feed/` (404 — la variante viva es `la-es`).

### Además, al importar

- Cambiar `text="Hacking"` → `text="Hacking & Research"` en el OPML (trampa §1.1).
- Conservar los `miniflux:hideGlobally` existentes (Huntress, Exploit-DB, MSRC, Sploitus…).
- El resto de los 52 feeds queda igual: la curación de agosto ya está bien balanceada
  (sin solapamiento grave, mezcla noticias/research/vendor/oficial).

---

## 3. Arquitectura objetivo: monorepo `Intel` con paquetes

> **EJECUTADO 2026-08-08** (fases 2–3 de §5). Decisión del usuario sobre el nombre: el remoto
> "probablemente se llame algo como separatio" — el monorepo **continúa** `Fennek115/separatio`
> (historia preservada; ipcheck entró por subtree). Sin renombres en GitHub por ahora.

**Decisión propuesta: un solo repo** (renombrar el remoto `Fennek115/separatio` → `Fennek115/intel`
o crear `intel` y archivar el viejo). Razones: un solo operador, las piezas ya están acopladas por
filesystem (`IPCHECK_DIR` + `sys.path.insert`), un `.env`, y **una sola unidad de deploy** al LXC.
Repos separados solo pagarían si ipcheck tuviera otros consumidores — no los tiene.

```
Intel/                          # repo git único
├── pyproject.toml              # paquetes: separatio + ipcheck; deps; extras [dev]
├── .env.example                # todas las vars documentadas (commiteado)
├── .env                        # secretos reales (gitignored) — EL ÚNICO
├── .gitignore                  # venv/, __pycache__/, .env, data/, output/
├── feeds/
│   └── feeds.opml              # curado según §2
├── docs/
│   ├── CAPAS-Y-FUENTES.md
│   ├── IMPROVEMENTS.md
│   └── PLAN-REORDEN.md         # este archivo
├── separatio/                  # ← "threat intel/" renombrado (muere el espacio)
│   ├── pipeline.py  config.py  analyzer.py  correlator.py  history.py
│   ├── extractor.py reporter.py miniflux_client.py net.py  setup_check.py
│   └── enrichers/
├── ipcheck/                    # paquete instalable
│   ├── ip_enricher.py          # librería (ya refactorizada, ver IMPROVEMENTS §7)
│   ├── cli.py                  # ← ip_threat_checker.py; entry point `ipcheck`
│   └── data/                   # xlsx/csv/json de corridas (gitignored) — o borrar
├── output/                     # reports del pipeline (gitignored)
└── tests/                      # los de ambos paquetes, un solo `pytest tests/`
```

Claves del diseño:

- **`pyproject.toml` con entry points**: `separatio = separatio.pipeline:main` y
  `ipcheck = ipcheck.cli:main`. Instalación editable en dev (`pip install -e .`),
  instalación normal en el LXC. **El uso de consola de ipcheck se preserva** (restricción
  del usuario): `ipcheck <ip>` en vez de `python ip_threat_checker.py`.
- **Muere `IPCHECK_DIR` + `sys.path.insert`**: `enrichers/ip_reputation.py` pasa a
  `from ipcheck.ip_enricher import ApiKeys, IpEnricher`. Import normal de paquete.
- **`config.py` deja de asumir cwd/rutas absolutas de la laptop**: `OUTPUT_DIR` y `HISTORY_FILE`
  salen de env vars con default relativo al repo (`INTEL_OUTPUT_DIR`), para que el mismo código
  corra en la laptop y en el LXC.
- Los refactors grandes de `IMPROVEMENTS.md` §6 (providers/, Jinja2, split de pipeline.py)
  **no van en esta fase** — la reestructura mueve archivos sin reescribirlos, para poder
  verificar con los mismos 14 tests + un dry-run. Refactors después, de a uno.

### Historia git

- `separatio`: se preserva entera (es el repo que se renombra/continúa).
- `ipcheck`: `git subtree add` (o merge con `--allow-unrelated-histories`) para conservar
  sus 3 commits; antes hay que **limpiar y commitear** su working tree (§5, paso 1).

---

## 4. Secretos: un solo `.env`, y qué pasa con rbw

**Consolidar en `./.env` raíz** (11 vars únicas hoy + `ANTHROPIC_API_KEY` cuando el usuario la
ponga): mover `VIRUSTOTAL_API_KEY` y `URLSCAN_API_KEY` desde `ipcheck/.env`, borrar
`ipcheck/.env`, dejar `.env.example` completo commiteado. Solo el entry point (`pipeline.py` /
`cli.py`) hace `load_dotenv()`; la librería lee `os.environ` (ya es así, mantenerlo).

**rbw: no para el runtime del server.** Un cron/timer headless no puede desbloquear el vault de
Bitwarden sin dejar la master password en disco — se pierde exactamente lo que rbw protege, y suma
un binario + estado de agente al LXC. Esquema propuesto:

- **Laptop (dev):** `.env` en la raíz del repo, gitignored (como hoy).
- **LXC (prod):** systemd `EnvironmentFile=/etc/intel/intel.env`, `root:root 0600`. Sin dotenv.
- **rbw/Bitwarden:** como *bóveda de respaldo manual* de las keys (nota "Intel API keys"),
  no como dependencia de ejecución. Copiar de ahí al `.env` cuando se aprovisiona una máquina.

---

## 5. Orden de ejecución

Fases chicas, cada una verificable y commiteable. Las 1–4 no necesitan la API key.

1. ~~**Limpiar ipcheck**~~ **Hecho 2026-08-08** (commit `d153156`, sin pushear): el usuario
   decidió **borrar** todos los datos de corridas (xlsx/csv/json/logs); se trackearon
   `ip_enricher.py`, `tests/`, `run.py`, `procesar_excel.py`, `requirements-dev.txt`; se
   commitearon los 5 modificados; se destrackeó `ip_threat_checker.txt` (IPs reales de una
   investigación — el repo es **público**) y se extendió el `.gitignore` (que ya existía
   trackeado y ocultaba los `threat_report_*.json`). Tests: 10/10 pasan. → `git status` limpio.
2. ~~**Armar el monorepo**~~ **Hecho 2026-08-08**: `~/Projects/Intel/` es el repo (continúa
   `Fennek115/separatio`; ipcheck por subtree, historia de ambos preservada), `threat intel/`
   → `separatio/`, OPML duplicado y `Zone.Identifier` borrados, `venv/`/`output-threatintel/`
   fuera del árbol, `feeds/feeds.opml` y `docs/` en la raíz.
3. ~~**Packaging**~~ **Hecho 2026-08-08**: `pyproject.toml` con entry points (`separatio`,
   `separatio-check`, `ipcheck`, `ipcheck-run`), imports de paquete (murió `IPCHECK_DIR` +
   `sys.path.insert`), `ip_threat_checker.py` → `ipcheck/cli.py`, venv raíz editable.
   24 tests ✓, `ipcheck --help` ✓, `separatio-check` todo verde ✓, `separatio --dry-run` ✓.
   (Rutas por env var `INTEL_OUTPUT_DIR`: NO se hizo — queda para el deploy al LXC.)
4. ~~**`.env` único**~~ **Hecho 2026-08-08**: VT y URLSCAN rescatadas al `.env` raíz
   (la `ABUSECH_API_KEY` de `ipcheck/.env` estaba vencida — 403 — y se descartó; la de la
   raíz da 200), `ipcheck/.env` borrado, `.env.example` completo commiteado, `cli.py` carga
   el `.env` raíz. **VirusTotal quedó activo** en el enricher `ip_reputation` (key verificada,
   HTTP 200). La parte de feeds ya estaba resuelta el 2026-08-08 por la mañana (§2).
5. **Usuario:** `ANTHROPIC_API_KEY` en `.env`. Luego Paso 6 de F0:
   `setup_check` → `--dry-run` → `--limit 5` → corrida completa.
6. **Recién entonces** (decisiones diferidas de Motherbase): dónde corre — CT nuevo en
   `motherbase` junto a Miniflux es lo natural, con systemd timer diario — y arranque de las
   dos semanas de cierre de F0.
7. **Frente 2 (OCR)**: sobre la estructura nueva, etapa en Stage 1–2: `<img>` del HTML →
   `pytesseract` → concatenar al prompt de extracción existente. Sin segundo proveedor,
   sin vendorizar AIOCRIOC. Deps nuevas: `pytesseract`, `Pillow`, binario `tesseract`
   (agregarlo a la receta del LXC).

## 6. Qué NO se toca (decidido en Motherbase)

- Proveedor: Claude cloud. Nada de Ollama/CT 111.
- MCP fuera del cron; corpus por MCP recién en F4.
- Nada de MISP/OpenCTI/plataformas pesadas.
- No crear CTs ni crons antes de terminar las fases 1–5.
