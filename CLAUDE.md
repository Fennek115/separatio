# CLAUDE.md — ~/Projects/Intel/

Contexto para trabajar acá. Reescrito el 2026-08-08 al cierre de la sesión del reorden
(fases 1–4 de `docs/PLAN-REORDEN.md` ejecutadas).

**Regla heredada del proyecto madre: verificar contra la máquina, no contra el documento.**
Si algo de acá no coincide con el estado real, gana el estado real y se corrige este archivo.

## Qué es esto

**Monorepo de la central de threat intel** (fase F0 del proyecto Motherbase). Es la
continuación del repo git `Fennek115/separatio` (**público**) — la historia de Separatio se
preservó entera y la de ipcheck entró por `git subtree`. Decisión del usuario 2026-08-08: el
remoto "probablemente se llame algo como separatio" — no se renombró nada en GitHub todavía.

Estado git: **pusheado a `Fennek115/separatio`** el 2026-08-08. El repo viejo
`Fennek115/ip_threatcheck` (también público) quedó congelado en GitHub — pendiente decidir
si se archiva.

## ⚠️ Trabajo en curso: el REWORK

Desde el 2026-08-09 el proyecto está en un **rework por fases, una por sesión**. Si vas a tocar
código, el punto de entrada es **`docs/REWORK-ESTADO.md`** (tabla de estado, protocolo de sesión y
prompt de arranque), no este archivo. El diseño está en `docs/PLAN-REWORK.md` y el detalle de cada
fase en `docs/fases/`.

**Fase activa: F-I (afinado de prompts).** F-A (higiene de la entrada) y **F-H (observabilidad de
la corrida)** quedaron **hechas el 2026-08-09**. Las fases están **planificadas al detalle** (DDL,
firmas, tests, comandos): una sesión ejecuta y documenta, no rediseña. Orden: **F-I** → F-B1 → F-B2
→ F-E → F-C → F-D, con F-F bloqueada por corpus y F-G en paralelo.

F-I sigue a F-H porque ahora el manifiesto **ya sabe qué se recortó** — falta que el modelo lo sepa
también. F-H dejó medidos diez puntos de descarte silencioso, entre ellos que el enrichment nunca
llega a las fases `latam` y `general` (`pipeline.py`, `ENRICHED_PHASES`): eso hoy se declara en el
manifiesto y **todavía no en el informe**.

## Layout

| Qué | Detalle |
|---|---|
| `pyproject.toml` | Paquetes `separatio` (+`separatio.enrichers`) e `ipcheck`. Entry points: `separatio`, `separatio-check`, `ipcheck`, `ipcheck-run`. Venv en `./venv/` (raíz) con `pip install -e '.[dev]'` |
| `separatio/` | El pipeline (4 etapas + enriquecimiento). Detalle técnico y estado fino en su `CLAUDE.md`. Enrichers (F2, 2026-08-08): IPsum, OpenPhish, ipcheck, **Ransomware.live** (1 llamada/run, sin reintentos ante 429 — ToS; nunca guardar `screenshot`/`claim_url`) y **onion-lookup** (CIRCL, solo si hay `.onion` entre los IOCs). **Honeypot (F3, capa 4)**: `enrichers/honeypot.py` lee `data/honeypot/attackers.json` (del colector `tools/pull_honeypot.sh`) — toggle `honeypot` en OFF hasta que el pull traiga dato real. **Desde F-A (2026-08-09):** `hygiene.py` (clasifica IPs en propia / escáner / desconocida) y `honeypot_collector.py` (el consolidador del honeypot, que salió del heredoc de `tools/pull_honeypot.sh` para poder testearse). **Desde F-H (2026-08-09):** `runlog.py` — el manifiesto de la corrida (singleton de módulo con no-op, como el `logger`): registra recortes con `shown`/`total`, tokens por llamada, fuentes caídas u **omitidas**, y calcula `status` (ok/degraded/failed) y exit code |
| `ipcheck/` | Librería (`ip_enricher.py`) + CLI de reputación de IPs. Su `CLAUDE.md` tiene el detalle. El enricher `ip_reputation` la importa como paquete (`from ipcheck import ip_enricher`) — `IPCHECK_DIR` y el `sys.path.insert` murieron |
| `tests/` | Los **94** tests de ambos paquetes: `venv/bin/pytest tests/ -q` (sin red). 42 previos + 31 de F-A + 21 de F-H |
| `.env` | **EL ÚNICO** — 13 variables, gitignored (el repo es público). Espejo documentado en `.env.example` (commiteado). Lo cargan solo los entry points; las librerías leen `os.environ`. ⚠️ `ANTHROPIC_API_KEY` es **temporal** (puesta 2026-08-08, caduca en días) — reemplazar por la definitiva |
| `feeds/feeds.opml` | Espejo curado de Miniflux (CT 112, `192.168.1.7:8080`): 40 feeds, 0 errores, bajo el usuario `threat_intel` (id 12, **no** `admin`), LATAM con 6. Verificado por API 2026-08-08 |
| `.mcp.json` | MCP de investigación manual (F2): HIBP hosted + AbuseIPDB por `uvx` (la key sale del `.env` al lanzar; nada secreto commiteado). Solo para sesiones en esta carpeta — **nunca** en el cron |
| `docs/` | **`REWORK-ESTADO.md` ← el punto de entrada de cada sesión del rework** (tabla de estado, protocolo, prompt de arranque) y `fases/F-A.md`…`F-G.md` (una por sesión, con bloque *"¿Ya está hecho?"* y as-built). `PLAN-REWORK.md` es el **diseño** detrás: del pipeline de informes al *archivo* de inteligencia. · `PLAN-REORDEN.md` (reorden, fases 1–4 hechas) · `CAPAS-Y-FUENTES.md` (capas y fuentes, **verificadas por HTTP el 2026-08-09**) · `IMPROVEMENTS.md` (backlog de refactors) · `DEPLOY.md` (as-built del CT 113) |
| `separatio/reports/` | Salidas (gitignored): `YYYY-MM-DD/{reports,iocs}`, **`run-manifest.json`** (F-H), `history.json`, `pipeline.log` (**rota**: 5 MB × 5). Los `--dry-run` van aislados a `reports/dryrun/` |

## Comandos

```bash
venv/bin/separatio                # corrida completa (~8-15 min con VT activo)
venv/bin/separatio --dry-run      # fetch sin LLM — aislado en reports/dryrun/, no marca leídos
venv/bin/separatio --report-only  # regenerar informe desde el caché del día
venv/bin/separatio --last-run     # ¿cómo salió la última corrida? (F-H; --json = manifiesto crudo)
venv/bin/separatio-check          # diagnóstico de entorno (carga el .env)
venv/bin/ipcheck archivo.txt      # checker de IPs de consola (uso suelto preservado)
venv/bin/pytest tests/ -q         # 94 tests, sin red
```

## Incidente 2026-08-08 (aprendizaje)

Un `--dry-run` de verificación pisó el informe real del día, el caché de 116 resúmenes y el
registro de `history.json`: hasta ese día el dry-run escribía los artefactos reales y marcaba
leídos en Miniflux. Se arregló (commit `7b675cf`: dry-run aislado, sin history, sin mark-read)
y el informe se regeneró re-marcando unread el batch en Miniflux y corriendo el pipeline de
nuevo. Moraleja vigente: **el dry-run viejo era destructivo; el nuevo no. No correr versiones
anteriores a `7b675cf` con `--dry-run` un día que ya tuvo corrida real.**

## Automatización (activa desde 2026-08-08)

**El pipeline corre en el LXC 113 (`intel`, `192.168.1.55`) de `motherbase`**: timers systemd
diario 07:00 y semanal lunes 08:00, ambos `Persistent=true`. Código en `/opt/intel/app`
(clone del repo público), secretos en `/etc/intel/intel.env` root:600, corre como usuario de
sistema `intel`. As-built completo, operación y pendientes del deploy en `docs/DEPLOY.md`.
En el laptop **no queda nada** corriendo (hubo timers de usuario unas horas ese día; se
desmontaron — las pruebas van en contenedores).

## Pendiente (en orden)

0. ⚠️ **Desplegar F-A + F-H al CT 113** (2026-08-09): el mismo `git pull` lleva las dos. El
   colector del CT corre cada 6 h con la versión **vieja** y sigue metiendo la IP de casa como
   atacante; y sin F-H el informe diario sigue sin manifiesto. Falta commit+push, `git pull` en
   `/opt/intel/app` y agregar `OWN_IPS=` a `/etc/intel/intel.env`. Comandos exactos en
   `docs/fases/F-A.md` §Pendientes.
1. ⚠️ **`ANTHROPIC_API_KEY` definitiva** (la del CT es la temporal de prueba; el usuario decidió
   esperar a que termine la etapa de pruebas). Cambiarla = editar una línea de
   `/etc/intel/intel.env` en el CT 113.
2. **Dos semanas de informes solos** (criterio de cierre de F0) — verificar cada tanto con
   `docs/DEPLOY.md` §4. Desde F-H eso se chequea con **`separatio --last-run`** (o
   `journalctl -u separatio.service`), no mirando si apareció el fichero. Decidir si el CT 113
   entra en los jobs de backup (hoy no está).
3. Decidir si se archiva `Fennek115/ip_threatcheck` en GitHub.
4. Frente 2: OCR de imágenes en Stage 1–2 (idea AIOCRIOC, ~15 líneas con pytesseract;
   ver `docs/CAPAS-Y-FUENTES.md`). Recién después del deploy.
5. Bugs menores conocidos: enricher OpenPhish falla **a veces** con "Invalid IPv6 URL" (no rompe
   el run; en las dos corridas del 2026-08-09 salió ok, así que depende del feed del día);
   warnings cosméticos de trafilatura en Stage 1. ~~Cuelgue indefinido de Stage 1~~ **Arreglado
   2026-08-08** (mismo día que se descubrió: 37 min dormido en un sleep de urllib3 honrando un
   `Retry-After` grande): ahora todo fetch de artículo corre bajo `FETCH_HARD_TIMEOUT` (45s de
   reloj total, `config.py`) en un thread daemon que se abandona al vencer — el artículo cae al
   fallback de feed/título y el run sigue. Tests en `tests/test_extractor.py`.
   Backlog grande en `docs/IMPROVEMENTS.md`.

## Lo que NO hay que rediscutir (decidido en Motherbase)

- Proveedor cloud (Claude), no Ollama local: el CT 111 ya no existe.
- MCP no va en el cron del pipeline; el corpus propio se servirá por MCP después (fase F4).
- Nada de MISP/OpenCTI/plataformas pesadas.

## Referencias

- Plan completo y fases: `~/Projects/Motherbase/ESTADO.md` y `~/Projects/Motherbase/fases/F0-separatio.md`
- Análisis de fondo de la central de intel: `~/Projects/Motherbase/INTEL-ARQUITECTURA.md`
