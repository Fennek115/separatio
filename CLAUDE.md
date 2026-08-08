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

Estado git: varios commits locales **sin pushear** (el push a `Fennek115/separatio` sería
fast-forward). El repo viejo `Fennek115/ip_threatcheck` (también público) quedó congelado en
GitHub — pendiente decidir si se archiva.

## Layout

| Qué | Detalle |
|---|---|
| `pyproject.toml` | Paquetes `separatio` (+`separatio.enrichers`) e `ipcheck`. Entry points: `separatio`, `separatio-check`, `ipcheck`, `ipcheck-run`. Venv en `./venv/` (raíz) con `pip install -e '.[dev]'` |
| `separatio/` | El pipeline (4 etapas + enriquecimiento). Detalle técnico y estado fino en su `CLAUDE.md` |
| `ipcheck/` | Librería (`ip_enricher.py`) + CLI de reputación de IPs. Su `CLAUDE.md` tiene el detalle. El enricher `ip_reputation` la importa como paquete (`from ipcheck import ip_enricher`) — `IPCHECK_DIR` y el `sys.path.insert` murieron |
| `tests/` | Los 24 tests de ambos paquetes: `venv/bin/pytest tests/ -q` (sin red) |
| `.env` | **EL ÚNICO** — 12 variables, gitignored (el repo es público). Espejo documentado en `.env.example` (commiteado). Lo cargan solo los entry points; las librerías leen `os.environ`. ⚠️ `ANTHROPIC_API_KEY` es **temporal** (puesta 2026-08-08, caduca en días) — reemplazar por la definitiva |
| `feeds/feeds.opml` | Espejo curado de Miniflux (CT 112, `192.168.1.7:8080`): 40 feeds, 0 errores, bajo el usuario `threat_intel` (id 12, **no** `admin`), LATAM con 6. Verificado por API 2026-08-08 |
| `docs/` | `PLAN-REORDEN.md` (el plan del reorden, fases 1–4 hechas), `CAPAS-Y-FUENTES.md` (diseño de capas y fuentes nuevas, incl. idea OCR/AIOCRIOC), `IMPROVEMENTS.md` (backlog de refactors de Separatio) |
| `separatio/reports/` | Salidas (gitignored): `YYYY-MM-DD/{reports,iocs}`, `history.json`, `pipeline.log`. Los `--dry-run` van aislados a `reports/dryrun/` |

## Comandos

```bash
venv/bin/separatio                # corrida completa (~8-15 min con VT activo)
venv/bin/separatio --dry-run      # fetch sin LLM — aislado en reports/dryrun/, no marca leídos
venv/bin/separatio --report-only  # regenerar informe desde el caché del día
venv/bin/separatio-check          # diagnóstico de entorno (carga el .env)
venv/bin/ipcheck archivo.txt      # checker de IPs de consola (uso suelto preservado)
venv/bin/pytest tests/ -q         # 24 tests, sin red
```

## Incidente 2026-08-08 (aprendizaje)

Un `--dry-run` de verificación pisó el informe real del día, el caché de 116 resúmenes y el
registro de `history.json`: hasta ese día el dry-run escribía los artefactos reales y marcaba
leídos en Miniflux. Se arregló (commit `7b675cf`: dry-run aislado, sin history, sin mark-read)
y el informe se regeneró re-marcando unread el batch en Miniflux y corriendo el pipeline de
nuevo. Moraleja vigente: **el dry-run viejo era destructivo; el nuevo no. No correr versiones
anteriores a `7b675cf` con `--dry-run` un día que ya tuvo corrida real.**

## Pendiente (en orden)

1. ⚠️ **`ANTHROPIC_API_KEY` definitiva** (la actual es temporal de prueba).
2. **Dónde corre + timer diario** (decisión diferida de Motherbase): lo natural es un LXC
   nuevo en `motherbase` junto a Miniflux, systemd timer + `EnvironmentFile=/etc/intel/intel.env`
   (esquema en `docs/PLAN-REORDEN.md` §4). Con eso arranca el criterio de cierre de F0:
   **dos semanas de informes diarios sin intervención**.
3. Push del monorepo a GitHub y decidir si se archiva `Fennek115/ip_threatcheck`.
4. Frente 2: OCR de imágenes en Stage 1–2 (idea AIOCRIOC, ~15 líneas con pytesseract;
   ver `docs/CAPAS-Y-FUENTES.md`). Recién después del deploy.
5. Bugs menores conocidos: enricher OpenPhish falla con "Invalid IPv6 URL" (no rompe el run);
   warnings cosméticos de trafilatura en Stage 1. **Nuevo 2026-08-08:** Stage 1 puede colgarse
   indefinidamente en la extracción de un artículo (visto: 37 min dormido en un sleep, 0% CPU,
   sockets en CLOSE-WAIT; `trafilatura.fetch_url` se llama sin timeout en `extractor.py:53`).
   Para un cron desatendido hace falta un timeout duro por artículo — anotado para antes/durante
   el deploy. Mitigación manual: `NO_SCRAPE_DOMAINS` para el dominio culpable, o matar y relanzar
   (es seguro: no marca leídos ni escribe nada hasta el final). Backlog grande en `docs/IMPROVEMENTS.md`.

## Lo que NO hay que rediscutir (decidido en Motherbase)

- Proveedor cloud (Claude), no Ollama local: el CT 111 ya no existe.
- MCP no va en el cron del pipeline; el corpus propio se servirá por MCP después (fase F4).
- Nada de MISP/OpenCTI/plataformas pesadas.

## Referencias

- Plan completo y fases: `~/Projects/Motherbase/ESTADO.md` y `~/Projects/Motherbase/fases/F0-separatio.md`
- Análisis de fondo de la central de intel: `~/Projects/Motherbase/INTEL-ARQUITECTURA.md`
