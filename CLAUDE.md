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

**Fase activa: F-G (deuda técnica), por descarte.** F-A (higiene de la entrada), **F-H
(observabilidad de la corrida)**, **F-I (afinado de prompts)**, **F-B1 (el store)**, **F-B2 (ingesta
idempotente y backfill)**, **F-E (listas locales)**, **F-C (enricher inverso y triage)** y **F-D
(reincidencia)** quedaron **hechas el 2026-08-09** — F-D con una salvedad: código y tests cerrados,
pero el **cierre real está bloqueado por falta de tráfico SSH** (el store de producción tiene 0 IPs
con `days_seen >= 2` y 0 HASSH). Las fases están **planificadas al detalle** (DDL, firmas, tests,
comandos): una sesión ejecuta y documenta, no rediseña. F-F sigue bloqueada por corpus (0 payloads en
disco), así que con F-D también esperando dato real, **F-G (track paralelo, deuda técnica) es la
única fase sin dependencia de tráfico real hoy**.

Primer ítem de F-G, **G-1 (partir `consolidate()`), cerrado 2026-08-09**: la función de 306 líneas
que F-A había movido verbatim del heredoc se partió en cinco funciones de módulo —
`parse_cowrie`/`parse_web`/`parse_beelzebub`/`parse_cowrie_downloads`/`write_artifacts` en
`separatio/honeypot_collector.py`—, `consolidate()` quedó en 131 líneas. Verificado con los 180
tests (sin tocar ninguno) más una comparación byte a byte antes/después sobre un `raw/` sintético
que ejercita las cinco rutas (HASSH, descarga con tar, web, Beelzebub HTTP+TCP, CrowdSec): salida
idéntica salvo el timestamp `generated`. As-built en `docs/fases/F-G.md`.

Segundo ítem de F-G, **G-4 (enriquecer el export de IOCs), cerrado 2026-08-09**: `export_iocs()`
corría antes de Stage 2.7, así que el CSV/JSON de IOCs salía sin reputación externa aunque
`EnrichmentContext.export_rows()` ya existiera sin consumidor. Ahora `export_iocs()` toma un
`enrichment=None` opcional y las dos llamadas de `_run()` (`--report-only` y corrida completa) se
movieron a después de `stage27_enrich()`, pasándole el contexto — cada fila del export suma una
columna `reputation` (`"fuente:etiqueta"`, vacía si no hay veredicto o si no se pasa `enrichment`,
como en `run_weekly()`). 180 tests sin tocar (no había ninguno sobre `pipeline.export_iocs`) más
prueba manual con `EnrichmentContext` sintético y un `--dry-run --limit 5` real de punta a punta.
Con `honeypot_recon` (F-C) todavía en OFF esto no cambia el export de producción hoy — deja el
mecanismo listo para cuando se prenda. As-built en `docs/fases/F-G.md`.

Cuarto ítem de F-G, **G-3 (modularizar `pipeline.py`), cerrado 2026-08-09**: el orquestador tenía
**985 líneas** (el plan decía 855; cada fase del rework le fue sumando etapa) y **cero tests** —ningún
test del repo lo importaba. Quedó en **839** y salieron tres módulos hoja (no importan `pipeline`, así
que se testean sin `load_dotenv` ni `OUTPUT_DIR`): `separatio/deduplicator.py` (`dedup_by_cves`),
`separatio/ioc_processor.py` (`detect_ioc_type` + `export_iocs`) y `separatio/router.py` (el ruteo:
`group_by_phase`, `phase_order()`, `CANONICAL_PHASES`/`CORRELATED_PHASES`/`TRENDING_PHASES` y
`receives_correlation()`/`receives_trending()`). Los nombres viejos siguen resolviendo desde
`pipeline` porque los tres se importan a su namespace. **Lo que el plan pedía y no se hizo:** reusar
`enrichment.ioc_kind` en el export — parecen la misma función pero `ioc_kind` colapsa md5/sha1/sha256
en `hash` y asume el IOC ya normalizado, así que sustituirla habría cambiado la columna `type` de
`iocs.csv`; quedaron separadas con la diferencia tabulada en el docstring de `ioc_processor.py`.
Hallazgo de la sesión: el orden canónico de fases estaba escrito **dos veces** y las dos listas
**divergen** — una clave extra de `PHASE_CATEGORY_MAP` se genera en Stage 3 (se paga al LLM) y
`stage4_synthesis` no la ensambla, así que el texto se tira. Hoy no pasa (la config tiene las cuatro
canónicas) y arreglarlo cambiaría la salida, así que se preservó y quedó anotado como deuda en
`docs/fases/F-G.md`. Verificado con equivalencia función a función contra el `pipeline.py` previo
(44 comprobaciones, `export_iocs` byte a byte con y sin enrichment: 0 diferencias), 228 tests
(45 nuevos) y un `--dry-run --limit 5` antes/después con informe idéntico. As-built en
`docs/fases/F-G.md`.

Tercer ítem de F-G, **G-7 (bugs menores conocidos), cerrado 2026-08-09**: los dos bugs eran el
mismo patrón — una excepción de una dependencia externa que el try/except de Stage 2.7 ya toleraba,
pero que perdía la fuente **entera** esa corrida en vez de sólo la línea puntual que la disparaba.
`urlparse()` levanta `ValueError: Invalid IPv6 URL` ante un `[` suelto en el netloc (no hace falta
IPv6 real: `urlparse("http://[malformed")` ya lo reproduce) — una sola línea del feed o un solo IOC
malformado tiraba `enrichers/openphish.py:_load()`/`enrich()` entero, y `run_enrichment()` marcaba
todo OpenPhish `failed` para el día. Se agregó `_safe_netloc()` (mismo `urlparse(...).netloc`
envuelto en `try/except ValueError`, devuelve `""`) en los dos sitios. El segundo, `discarding
data: None` de trafilatura, no era un fallo — es `trafilatura/core.py:477` avisando que descartó un
documento por texto insuficiente/idioma/duplicado, control de flujo normal suyo que ya cae al
fallback de requests+BeautifulSoup; se bajó su logger propio a `ERROR` en `extractor.py`. 183 tests
(3 nuevos en `tests/test_openphish.py`) más `--dry-run --limit 5` de punta a punta sin ninguna de
las dos líneas de ruido. As-built en `docs/fases/F-G.md`.

Quinto ítem de F-G, **G-5 (abstracción de proveedores LLM), cerrado 2026-08-09**: `analyzer._llm_chat`
mezclaba Ollama/Claude/OpenAI/Gemini con `if provider ==`, y el loop de streaming de Ollama estaba
copiado dos veces —`generate_report` y `generate_phase_report`—, cada copia con su propio logging.
Paquete nuevo `separatio/providers/`: `LLMProvider` (ABC, `chat()`/`chat_stream()` — la base cae a
`chat()`, así que sólo `OllamaProvider` sobreescribe `chat_stream()`, el único que streamea de
verdad) + `OllamaProvider`/`AnthropicProvider`/`OpenAIProvider`/`GeminiProvider` + fábrica
`get_provider(name, ollama_host="")`. `analyzer.py` 1241 → 1154 líneas; `_llm_chat` quedó en 6
líneas de cuerpo y una nueva `_llm_chat_stream` es lo que ahora comparten las dos ramas Ollama.
Hallazgo de la sesión, no arreglado a propósito (misma disciplina que dejó G-3 con
`PHASE_CATEGORY_MAP`): las dos ramas Ollama nunca logueaban el consumo igual —
`generate_phase_report` sí llamaba `_log_usage`, `generate_report` (el modo legacy de una sola
llamada) nunca lo hizo— y arreglarlo habría sumado una entrada al manifiesto que antes no estaba,
así que el quirk se preservó literal y quedó anotado como deuda. Verificado con 264 tests (36
nuevos: cada SDK reemplazado por un doble en `sys.modules` — `openai`/`google-generativeai` ni
siquiera están instalados, no son dependencias del proyecto — más un `FakeProvider` fijando el
comportamiento exacto de `analyzer.py`, incluido el quirk) y, porque Ollama es legacy sin servidor
vivo (**el CT 111 ya no existe**) y `--dry-run` nunca llama al LLM, una **llamada real contra
Claude** ejercitando `_llm_chat`/`generate_phase_report`/`generate_synthesis_report` de punta a
punta. `pyproject.toml` sumó `separatio.providers` a `packages` — pidió reinstalar
(`pip install -e '.[dev]'`), mismo caso que F-B1 dejó anotado para `separatio.store`. As-built en
`docs/fases/F-G.md`.

Quedan G-2, G-6 sin tocar — F-G es un track de ítem-por-sesión, no se cierra de una vez.

Lo que dejó F-D y conviene saber antes de tocar la reincidencia: `separatio/store/queries.py`
(`ip_recurrence`, `payload_history`, `hassh_fanout`, `top_recurrent`) convierte filas del store en
las frases que el criterio de cierre del rework pide — "esta IP volvió N de los últimos 14 días, no
está en ninguna blocklist, y GreyNoise no la ve escanear internet". Fue casi gratis: F-B2 ya mantenía
`days_seen`/`times_seen` y el HASSH ya entraba como IOC propio, así que la fase fue sobre todo
consultas y redacción sobre `HoneypotReconEnricher` (F-C), no diseño nuevo. Único ajuste al diseño de
F-C: la prioridad del residuo pasó del `days_seen` denormalizado (la vida entera del indicador) a
`ip_recurrence()` (acotado a `RECURRENCE_WINDOW_DAYS=14`), porque el enunciado "de los últimos 14
días" necesita contar dentro de la ventana, no desde siempre. Hallazgo de la sesión: no hay
hallazgo de diseño — el plan estaba bien especificado y se ejecutó tal cual. Lo que sí quedó
pendiente explícito es la verificación en vivo: **con datos sintéticos el código se probó y anda**
(180 tests, smoke test manual con los tres tipos de nota juntos), pero la regla del rework prohíbe
declarar la fase hecha con eso — falta que el honeypot vea reincidencia real.

Lo que dejó F-B1 y conviene saber antes de tocar el store: el DDL vive en
`separatio/store/schema.sql` y se puede leer sin abrir Python, y `open_store()` **nunca levanta**:
si no puede abrir, loguea y devuelve `None`. Hallazgo de la sesión: las ventanas del store comparan
**cadenas** de tiempo y el colector emite `…Z` mientras Python emite `…+00:00` — en ASCII `'+' <
'Z'`, así que un formato mezclado rompía `quota_used` y la poda en silencio; todo timestamp que
entra se normaliza en `models._iso()`.

Lo que dejó F-B2 y conviene saber antes de tocar la ingesta: el store **ya tiene memoria** — cada
pull del colector (`honeypot_collector.consolidate()`) escribe en `data/archivo.db` vía
`separatio/store/ingest.py:ingest_run()`, envuelto en try/except (si el store falla, el pull sigue
igual) — y `separatio/store/backfill.py` reconstruye desde `data/honeypot/by-date/*/` lo que hubiera
antes. Hallazgo de la sesión: `observation.payload_sha256` es clave foránea igual que
`observation.ioc`, así que un evento con `sha256` necesita su fila en `payload` **antes** de
insertarse — la misma trampa de orden que F-B1 ya había anotado para `ioc`. La trampa de
`times_seen` (contar una fila "asegurada" como si fuera un avistamiento real) se resolvió agregando
`count: bool = True` a `upsert_ioc`: `count=False` crea/toca la fila sin sumar, y sólo se cuenta
cuando `add_observation()` devuelve `True`.

Lo que dejó F-E y conviene saber antes de tocar el filtro: `separatio/lists.py` (`LocalLists`, no es
un `Enricher`) responde gratis si una IP ya está en jamesbrine/IPsum/FireHOL — `array('I')` + bisect
para IPs sueltas, rangos `(inicio,fin)` + bisect para CIDR, 4 bytes por IP. Queda **listo pero sin
cablear**: nadie lo llama todavía, eso lo hace F-C sobre las IPs del honeypot. Dos hallazgos de la
sesión: `levels/3.txt` de IPsum **no trae score por línea** (el plan lo daba por hecho; el score sólo
está en el agregado `ipsum.txt`, y `config.IPSUM_URL` se corrigió para no cambiarlo) y la carga
inicial rompía el techo de RAM del CT por pico transitorio, no por el tamaño final: `text.splitlines()`
sobre 1 M de líneas más `sorted(set(...))` llegaban a 128,8 MB contra un techo de 120 MB. Se arregló
iterando el archivo línea a línea y sacando el `set()` intermedio — quedó en 79,8 MB de pico real en
el CT.

Lo que dejó F-I y conviene saber antes de tocar prompts: el informe **declara sus propios
faltantes** (`runlog.coverage_block()` arma el bloque COBERTURA desde el manifiesto de F-H y cada
fase cierra con una línea "Limitaciones de esta corrida"), los topes de prompt viven todos en
`config.PROMPT_CAPS`, y el **enrichment llega a las cuatro fases** — `ENRICHED_PHASES` ya no existe;
lo que se sigue reservando a vulnerability/threat_intel es la correlación KEV/EPSS
(`pipeline.CORRELATED_PHASES`). Hallazgo de la sesión: darle el dato al modelo no alcanza, hay que
**pedirle explícitamente que lo escriba** — con el bloque pero sin la regla, lo sabía y se lo callaba.

Lo que dejó F-C y conviene saber antes de tocar el triage: `separatio/enrichers/honeypot_recon.py`
(`HoneypotReconEnricher`) es el enricher inverso — pregunta "esta IP me pegó, ¿es actor conocido o
ruido de internet?" sobre las IPs del store, no sobre los IOCs de los artículos (`enrich(iocs, ctx)`
ignora `iocs` a propósito). Triage en 4 etapas a coste creciente: higiene (descarta `klass=scanner`)
→ cache (`enrichment` fresca) → `LocalLists` de F-E → sólo el residuo gasta una consulta de
GreyNoise, y **sólo el resultado NEGATIVO** (`noise=False`, no la ve escanear internet) escala a la
cascada completa de `ipcheck` — es la única señal parecida a "dirigido a mí", porque ninguna
blocklist contiene negativos. Presupuesto declarativo en `config.QUOTAS`, contado contra el store
(`quota_used`), no en memoria. Toggle `honeypot_recon` en OFF: prenderlo gasta cuota real de
GreyNoise (20/semana reservadas de las 25 medidas), así que quedó para que el usuario lo active a
propósito. Hallazgo de la sesión: `models.recent_ips` (F-B1) no traía las columnas que el orden de
prioridad del residuo necesitaba (payload enviado, multi-sensor) — se le agregaron `sensors` y
`has_payload`, aditivo, sin tocar los tests de F-B1.

## Layout

| Qué | Detalle |
|---|---|
| `pyproject.toml` | Paquetes `separatio` (+`separatio.enrichers`, +`separatio.store`) e `ipcheck`. Entry points: `separatio`, `separatio-check`, `ipcheck`, `ipcheck-run`. Venv en `./venv/` (raíz) con `pip install -e '.[dev]'` |
| `separatio/` | El pipeline (4 etapas + enriquecimiento). Detalle técnico y estado fino en su `CLAUDE.md`. Enrichers (F2, 2026-08-08): IPsum, OpenPhish, ipcheck, **Ransomware.live** (1 llamada/run, sin reintentos ante 429 — ToS; nunca guardar `screenshot`/`claim_url`) y **onion-lookup** (CIRCL, solo si hay `.onion` entre los IOCs). **Honeypot (F3, capa 4)**: `enrichers/honeypot.py` lee `data/honeypot/attackers.json` (del colector `tools/pull_honeypot.sh`) — toggle `honeypot` en OFF hasta que el pull traiga dato real. **Desde F-A (2026-08-09):** `hygiene.py` (clasifica IPs en propia / escáner / desconocida) y `honeypot_collector.py` (el consolidador del honeypot, que salió del heredoc de `tools/pull_honeypot.sh` para poder testearse). **Desde F-H (2026-08-09):** `runlog.py` — el manifiesto de la corrida (singleton de módulo con no-op, como el `logger`): registra recortes con `shown`/`total`, tokens por llamada, fuentes caídas u **omitidas**, y calcula `status` (ok/degraded/failed) y exit code. **Desde F-I (2026-08-09):** `runlog.coverage_block(phase)` (el bloque COBERTURA que se inyecta en los cinco prompts), `config.PROMPT_CAPS`/`PHASE_EFFORT`, salida estructurada en Stage 2 (`ARTICLE_SUMMARY_SCHEMA`) y tres campos nuevos en `ArticleSummary` (`attack_techniques`, `exploitation_status`, `confidence`). **Desde F-C (2026-08-09):** `enrichers/honeypot_recon.py` (`HoneypotReconEnricher`) — el enricher inverso, triage de las IPs del honeypot contra GreyNoise + la cascada de `ipcheck` con presupuesto declarativo (`config.QUOTAS`). Toggle `honeypot_recon` en OFF (gasta cuota real de GreyNoise). **Desde F-D (2026-08-09):** el mismo enricher suma la reincidencia (`store/queries.py`) al `detail` de la señal fuerte y a tres notas nuevas (IP reincidente, payload ya conocido, HASSH fanout) — sin cambiar el toggle ni el presupuesto. **Desde F-G/G-3 (2026-08-09):** `pipeline.py` bajó de 985 a 839 líneas y son tres módulos hoja los que tienen la lógica que se le fue extrayendo — `deduplicator.py` (dedup semántico por CVEs), `ioc_processor.py` (`detect_ioc_type` + `export_iocs`, sin depender de `config`) y `router.py` (qué artículo va a qué fase y qué contexto recibe cada una). `pipeline.py` los reexporta, así que `pipeline.export_iocs` y compañía siguen resolviendo. **Desde F-G/G-5 (2026-08-09):** `providers/` — `LLMProvider` (ABC) + `OllamaProvider`/`AnthropicProvider`/`OpenAIProvider`/`GeminiProvider` + `get_provider()` (fábrica), reemplaza el `if provider ==` de `analyzer._llm_chat` y el streaming de Ollama duplicado; `analyzer.py` bajó de 1241 a 1154 líneas |
| `ipcheck/` | Librería (`ip_enricher.py`) + CLI de reputación de IPs. Su `CLAUDE.md` tiene el detalle. El enricher `ip_reputation` la importa como paquete (`from ipcheck import ip_enricher`) — `IPCHECK_DIR` y el `sys.path.insert` murieron. **Desde F-C:** también la importa `honeypot_recon.py` (`check_greynoise`, `IpEnricher` con `disabled={"greynoise"}` para no pagar dos veces la misma IP) |
| `separatio/store/` | **El archivo de inteligencia** (F-B1, 2026-08-09): `schema.sql` (5 tablas —`ioc`, `observation`, `enrichment`, `payload`, `meta`— + 5 índices), `db.py` (`open_store`/`migrate`/`store`, WAL + `foreign_keys` + `busy_timeout`, tolerante a fallos) y `models.py` (acceso sin ORM: `upsert_ioc`, `add_observation`, `get_cached`/`put_cached`, `quota_used`, `prune_observations`, `recent_ips`…). **Desde F-B2 (2026-08-09): `ingest.py`** (`ingest_run()`, el punto único de escritura que comparten colector y backfill) y **`backfill.py`** (`python3 -m separatio.store.backfill [--since AAAA-MM-DD] [--dry-run]`, reconstruye desde `data/honeypot/by-date/*/` y reclasifica snapshots anteriores a F-A). **Desde F-C:** `recent_ips` trae además `sensors`/`has_payload` (criterio de prioridad del residuo). **Desde F-D (2026-08-09): `queries.py`** (`ip_recurrence`/`payload_history`/`hassh_fanout`/`top_recurrent` — la reincidencia acotada a ventana, no el contador de toda la vida del indicador). El fichero es `data/archivo.db` (gitignored). Sólo stdlib: lo importa el colector, que corre sin venv |
| `separatio/lists.py` | **El filtro gratis** (F-E, 2026-08-09): `LocalLists` — pertenencia de IPs en jamesbrine + IPsum + FireHOL (tor_exits, level1) sin gastar cuota. No es un `Enricher`; lo consulta `honeypot_recon.py` (F-C) sobre las IPs del honeypot, no sobre los IOCs de los artículos. `array('I')` + bisect (4 bytes/IP), cache en `data/feeds/*.txt` con TTL de 12h y fail-open a copia vencida. 79,8 MB de pico medidos en el CT (techo 120 MB). Toggle `LOCAL_LISTS_ENABLED` |
| `tests/` | Los **264** tests de ambos paquetes: `venv/bin/pytest tests/ -q` (sin red). 42 previos + 31 de F-A + 21 de F-H + 21 de F-I + 19 de F-B1 + 12 de F-B2 + 11 de F-E + 14 de F-C + 9 de F-D + 3 de F-G/G-7 + 45 de F-G/G-3 + 36 de F-G/G-5 |
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
venv/bin/pytest tests/ -q         # 228 tests, sin red
sqlite3 data/archivo.db ".tables" # el store (F-B1); lo escribe cada pull desde F-B2
python3 -m separatio.store.backfill --dry-run  # reconstruir el store desde by-date/ (F-B2)
venv/bin/python -c "from separatio.lists import LocalLists; l=LocalLists.from_config(); l.load(); print(l.stats())"  # el filtro gratis (F-E)
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

0. ⚠️ **Commitear y desplegar F-A + F-H + F-I + F-B1 + F-B2 + F-E + F-C + F-D al CT 113** (2026-08-09):
   ninguna de las ocho está commiteada todavía (protocolo del rework: commit no es automático, se
   hace cuando el usuario lo pide — ver `docs/REWORK-ESTADO.md`). Una vez commiteadas y pusheadas, el
   mismo `git pull` las lleva todas (F-B1/F-B2 piden además rehacer `pip install -e '.[dev]'` para
   registrar `separatio.store`). El colector del CT corre cada 6 h con la versión **vieja** y sigue
   metiendo la IP de casa como atacante; sin F-H el informe diario sigue sin manifiesto; sin F-I sigue
   sin declarar lo que le falta; sin F-B2 el store se queda vacío para siempre (nadie escribe); F-E,
   F-C y F-D no cambian conducta todavía (`honeypot_recon` sigue en OFF) pero conviene llevarlas igual
   para no ir dejando deploys pendientes acumulados. Falta commit+push, `git pull` en `/opt/intel/app`,
   agregar `OWN_IPS=` a `/etc/intel/intel.env` (ninguna de estas ocho trae variables nuevas
   obligatorias) y correr `python3 -m separatio.store.backfill` una vez ahí para no perder lo que ya
   haya en `by-date/`. Comandos exactos en `docs/fases/F-A.md` §Pendientes. Después de F-I el informe
   del CT crece ~9 % y cuesta ~$0,09 más por corrida.
1. ⚠️ **`ANTHROPIC_API_KEY` definitiva** (la del CT es la temporal de prueba; el usuario decidió
   esperar a que termine la etapa de pruebas). Cambiarla = editar una línea de
   `/etc/intel/intel.env` en el CT 113.
2. **Dos semanas de informes solos** (criterio de cierre de F0) — verificar cada tanto con
   `docs/DEPLOY.md` §4. Desde F-H eso se chequea con **`separatio --last-run`** (o
   `journalctl -u separatio.service`), no mirando si apareció el fichero. Decidir si el CT 113
   entra en los jobs de backup (hoy no está).
3. Decidir si se archiva `Fennek115/ip_threatcheck` en GitHub.
4. **Prender `honeypot_recon` con GreyNoise real** (F-C, cuando el usuario lo pida): hoy queda
   construido, testeado y verificado con `LocalLists` real + GreyNoise mockeado a propósito — activar
   el toggle gasta cuota real (20/semana reservadas de las 25 medidas sin key).
5. ⚠️ **Verificar F-D contra dato real, cuando el honeypot vea tráfico SSH repetido**: hoy el store
   de producción tiene 0 IPs con `days_seen >= 2` y 0 HASSH (el sensor Cowrie no está expuesto). El
   código y los 9 tests de `tests/test_store_queries.py` están hechos y pasan con datos sintéticos,
   pero la fase no se declaró cerrada sin verlo andar con dato real — ver `docs/fases/F-D.md`
   §Pendientes que deja.
6. Frente 2: OCR de imágenes en Stage 1–2 (idea AIOCRIOC, ~15 líneas con pytesseract;
   ver `docs/CAPAS-Y-FUENTES.md`). Recién después del deploy.
7. Bugs menores conocidos: ~~enricher OpenPhish falla **a veces** con "Invalid IPv6 URL"~~ y
   ~~warnings cosméticos de trafilatura en Stage 1~~ **arreglados 2026-08-09** (F-G/G-7, ver arriba).
   ~~Cuelgue indefinido de Stage 1~~ **Arreglado
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
