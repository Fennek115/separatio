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

**Estado al 2026-08-09: no queda fase ejecutable sin dato real.** F-A (higiene de la entrada),
**F-H (observabilidad de la corrida)**, **F-I (afinado de prompts)**, **F-B1 (el store)**, **F-B2
(ingesta idempotente y backfill)**, **F-E (listas locales)**, **F-C (enricher inverso y triage)**,
**F-D (reincidencia)** y **F-G (deuda técnica, sus siete ítems)** están hechas. Las fases estaban
**planificadas al detalle** (DDL, firmas, tests, comandos): una sesión ejecuta y documenta, no
rediseña.

**Actualización del 2026-08-10 — el bloqueo por falta de tráfico se levantó.** Los honeypots se
expusieron ese día (as-built en `~/Projects/Motherbase/honeypot/EXPONER.md`) y el store pasó de
vacío a **28 IOCs / 75 observaciones / 2 payloads en el primer pull**:

- **F-D** ya tiene dato. Lo único que falta es que **pase un segundo día**: `days_seen >= 2` está
  en 0 por definición, no por falta de tráfico. Revisable desde el 2026-08-11.
- **F-F** (YARA) ya no está en 0 payloads, pero 2 tampoco es corpus. Reevaluar en días.

**El despliegue al CT 113 se hizo el 2026-08-10**: el CT pasó de `88dc851` a `dc5e850` (y de ahí
siguió), se reinstaló (`pip install -e '.[dev]'`, obligatorio por G-6), se agregó `OWN_IPS` a
`/etc/intel/intel.env` y se corrió el backfill. Las nueve fases corren en producción. **El
despliegue destapó cuatro bugs, los cuatro ya arreglados y desplegados** —`pytest` escribiendo en
el store real, el `--dry-run` del backfill contando de más, `OUTPUT_FORMAT` que no se leía del
entorno (por eso producción nunca generó un PDF), y un test con fecha fija que se rompía solo cada
día—. As-built de todo en `docs/REWORK-ESTADO.md` §Despliegue y §Bugs.

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

Sexto ítem de F-G, **G-6 (reporter con plantillas + Markdown real), cerrado 2026-08-09**: `reporter.py`
tenía 434 líneas de HTML/CSS como strings de Python y un parser de Markdown por regex, y **cero
tests**. El usuario eligió la **variante completa** de `IMPROVEMENTS.md` §6.2 —Jinja2 + la librería
`markdown`—, así que este es **el único ítem de F-G que cambia la salida a propósito** y suma dos
dependencias: la regla de la fase quedó suspendida sólo acá, y la verificación pasó de "salida
idéntica" a "ninguna diferencia pierde contenido". `reporter.py` 830 → **400 líneas**; las plantillas
viven en `separatio/templates/{pdf,web}.html.j2` como *package-data* (mismo criterio que
`store/schema.sql`: se editan sin abrir Python). El parser es `markdown.Markdown` con
`tables`/`fenced_code`/`toc` más una extensión propia con las dos concesiones al Markdown que
realmente escribe el modelo: un **preprocessor que despega la tabla del párrafo anterior** (el LLM
escribe `**IPs maliciosas:**` y la tabla pegada; Python-Markdown a secas se la traga entera dentro
del `<p>` y **se perdía una de las tres tablas** del informe real — el regex viejo era más tolerante
ahí) y el treeprocessor que marca `table-wide`. **El invariante que no se podía romper** es el índice
del PDF: la plantilla numera sus páginas con `target-counter(attr(href), page)`, así que si los `href`
del TOC y los `id` de los encabezados se desincronizan el índice sale sin números **sin fallar** —
por eso el TOC ahora se construye desde `md.toc_tokens`, mismo parseo y mismo `_slugify` inyectado.
Verificado en tres pasos: la extracción de plantillas **aislada** dio HTML byte a byte idéntico (así
el diff posterior es atribuible sólo al parser); el diff estructural sobre el informe real deja
tablas, encabezados, enlaces y código **exactamente iguales** (3 tablas, 180 celdas, 1 `table-wide`)
y los únicos 113 tokens que cambian son marcadores de lista (`-`, `1.`) que el parser viejo dejaba
**visibles como texto** —el fuente tiene 62 sublistas indentadas que `^[*-]` nunca matcheó—, con 0
palabras nuevas; y el PDF real con weasyprint mantiene sus 25 entradas de índice con los números
resueltos (20 → 19 páginas). 307 tests (43 nuevos; `reporter.py` no tenía ninguno). Hallazgo de la
sesión, preservado a propósito: el lookahead de `split_report_sections` está escrito
`(?===THREAT…`, que Python lee con **dos** `=`, no tres, así que cada sección se queda un `=` de
más; hoy no se dispara porque los marcadores sólo los emite la rama legacy `PHASE_REPORTS=False`.

Séptimo y último ítem de F-G, **G-2 (configuración inyectable), cerrado 2026-08-09 — con esto F-G
queda completa**. Era el ítem que el propio rework había ido empeorando (F-A tuvo que *rodear* el
módulo global con `build_classifier(config=None)`, y F-B/F-C repitieron el patrón). Punto de partida
medido: 97 claves, **187 accesos** a `config` en 12 ficheros, **~99 de ellos en `pipeline.py`**.
Ahora la fuente de verdad es `separatio/settings.py` — un dataclass **congelado** `Settings` con los
97 campos, sus defaults y los comentarios que documentaban cada valor (se movieron enteros desde
`config.py`), más `from_env(env=None)` (el entorno es inyectable: los tests no dependen de la
máquina) y `derive(**overrides)`. **`config.py` sobrevive como fachada de 40 líneas**
(`SETTINGS = Settings.from_env()` + `globals().update(...)`), así que los 187 accesos y el
`monkeypatch.setattr(config, ...)` de los tests siguen funcionando sin tocarse. **Los campos van en
MAYÚSCULAS a propósito**: `hygiene.build_classifier` y `setup_check` leen la config **por nombre
dinámico**, y pasarlos a snake_case los habría roto **en silencio** cayendo al default (son las
mismas claves que un análisis estático marca como "nunca usadas" — 14 falsos negativos). **Lo que de
verdad arregla el ítem**: `pipeline.py` *mutaba el módulo `config` en caliente*
(`config.OUTPUT_DIR = .../dryrun`), o sea que **el aislamiento del `--dry-run` —el fix del incidente
del 2026-08-08— dependía de reescribir un global a mitad de la corrida**; ahora es
`pipeline.settings_for(args)`, una función pura que se testea sin arrancar el pipeline, y quedan
**cero asignaciones a `config.X`** en el paquete. Verificado con los 97 valores idénticos (valor y
tipo) contra el `config.py` previo —ojo al comparar: hay que cargarlo desde su ubicación real o
`Path(__file__).parent` resuelve distinto y da 9 diferencias falsas—, con el aislamiento comprobado
**en la máquina** (mtime y md5 de los tres artefactos reales intactos tras `--dry-run` y
`--dry-run --report-only`; todo lo escrito cayó bajo `reports/dryrun/`), `--categories` en vivo,
`separatio-check` OK y 339 tests (32 nuevos). Acoplamiento a `config`: **187 → 45** referencias,
`pipeline.py` de ~99 a **9** (irreducibles: 5 son el `logging.basicConfig` que corre al importar,
antes de que `main()` parsee los flags — por eso `pipeline.log` sigue yendo al `OUTPUT_DIR` base
incluso en dry-run, conducta preexistente preservada).

**F-G está cerrada**: G-1 … G-7, los siete ítems, hechos el 2026-08-09.

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
| `pyproject.toml` | Paquetes `separatio` (+`separatio.enrichers`, +`separatio.store`, +`separatio.providers`) e `ipcheck`. Entry points: `separatio`, `separatio-check`, `ipcheck`, `ipcheck-run`. Venv en `./venv/` (raíz) con `pip install -e '.[dev]'`. *Package-data*: `store/schema.sql` y `templates/*.html.j2` |
| `separatio/settings.py` | **La configuración, como objeto** (F-G/G-2, 2026-08-09): el dataclass congelado `Settings` con los 97 campos, sus defaults y el porqué de cada valor; `from_env(env=None)` (entorno inyectable) y `derive(**overrides)`. **Editar un valor fijo se hace acá, no en `config.py`.** Los campos van en MAYÚSCULAS porque `hygiene` y `setup_check` leen por nombre dinámico |
| `separatio/config.py` | **Fachada** de 40 líneas sobre `Settings.from_env()` (F-G/G-2): expone cada campo como constante de módulo, así `config.MAX_ARTICLES` y el `monkeypatch` de los tests siguen andando. Para código nuevo: recibir un `Settings` por parámetro y usar `config.SETTINGS` sólo de default |
| `separatio/templates/` | **Las plantillas del informe** (F-G/G-6, 2026-08-09): `pdf.html.j2` (portada, índice y el CSS de paginado A4 con `@page`/`target-counter`) y `web.html.j2` (la vista oscura de pantalla). Son datos del paquete, no código: se editan sin abrir Python. Ojo con el índice del PDF — los `href` del TOC y los `id` de los encabezados tienen que salir del mismo motor o se rompe **en silencio** (sale sin números de página, no falla) |
| `separatio/` | El pipeline (4 etapas + enriquecimiento). Detalle técnico y estado fino en su `CLAUDE.md`. Enrichers (F2, 2026-08-08): IPsum, OpenPhish, ipcheck, **Ransomware.live** (1 llamada/run, sin reintentos ante 429 — ToS; nunca guardar `screenshot`/`claim_url`) y **onion-lookup** (CIRCL, solo si hay `.onion` entre los IOCs). **Honeypot (F3, capa 4)**: `enrichers/honeypot.py` lee `data/honeypot/attackers.json` (del colector `tools/pull_honeypot.sh`) — toggle `honeypot` en OFF hasta que el pull traiga dato real. **Desde F-A (2026-08-09):** `hygiene.py` (clasifica IPs en propia / escáner / desconocida) y `honeypot_collector.py` (el consolidador del honeypot, que salió del heredoc de `tools/pull_honeypot.sh` para poder testearse). **Desde F-H (2026-08-09):** `runlog.py` — el manifiesto de la corrida (singleton de módulo con no-op, como el `logger`): registra recortes con `shown`/`total`, tokens por llamada, fuentes caídas u **omitidas**, y calcula `status` (ok/degraded/failed) y exit code. **Desde F-I (2026-08-09):** `runlog.coverage_block(phase)` (el bloque COBERTURA que se inyecta en los cinco prompts), `config.PROMPT_CAPS`/`PHASE_EFFORT`, salida estructurada en Stage 2 (`ARTICLE_SUMMARY_SCHEMA`) y tres campos nuevos en `ArticleSummary` (`attack_techniques`, `exploitation_status`, `confidence`). **Desde F-C (2026-08-09):** `enrichers/honeypot_recon.py` (`HoneypotReconEnricher`) — el enricher inverso, triage de las IPs del honeypot contra GreyNoise + la cascada de `ipcheck` con presupuesto declarativo (`config.QUOTAS`). Toggle `honeypot_recon` en OFF (gasta cuota real de GreyNoise). **Desde F-D (2026-08-09):** el mismo enricher suma la reincidencia (`store/queries.py`) al `detail` de la señal fuerte y a tres notas nuevas (IP reincidente, payload ya conocido, HASSH fanout) — sin cambiar el toggle ni el presupuesto. **Desde F-G/G-3 (2026-08-09):** `pipeline.py` bajó de 985 a 839 líneas y son tres módulos hoja los que tienen la lógica que se le fue extrayendo — `deduplicator.py` (dedup semántico por CVEs), `ioc_processor.py` (`detect_ioc_type` + `export_iocs`, sin depender de `config`) y `router.py` (qué artículo va a qué fase y qué contexto recibe cada una). `pipeline.py` los reexporta, así que `pipeline.export_iocs` y compañía siguen resolviendo. **Desde F-G/G-5 (2026-08-09):** `providers/` — `LLMProvider` (ABC) + `OllamaProvider`/`AnthropicProvider`/`OpenAIProvider`/`GeminiProvider` + `get_provider()` (fábrica), reemplaza el `if provider ==` de `analyzer._llm_chat` y el streaming de Ollama duplicado; `analyzer.py` bajó de 1241 a 1154 líneas. **Desde F-G/G-6 (2026-08-09):** `reporter.py` bajó de 830 a 400 líneas — las plantillas salieron a `separatio/templates/*.html.j2` (Jinja2) y el parser de Markdown por regex lo hace ahora la librería `markdown` |
| `ipcheck/` | Librería (`ip_enricher.py`) + CLI de reputación de IPs. Su `CLAUDE.md` tiene el detalle. El enricher `ip_reputation` la importa como paquete (`from ipcheck import ip_enricher`) — `IPCHECK_DIR` y el `sys.path.insert` murieron. **Desde F-C:** también la importa `honeypot_recon.py` (`check_greynoise`, `IpEnricher` con `disabled={"greynoise"}` para no pagar dos veces la misma IP) |
| `separatio/store/` | **El archivo de inteligencia** (F-B1, 2026-08-09): `schema.sql` (5 tablas —`ioc`, `observation`, `enrichment`, `payload`, `meta`— + 5 índices), `db.py` (`open_store`/`migrate`/`store`, WAL + `foreign_keys` + `busy_timeout`, tolerante a fallos) y `models.py` (acceso sin ORM: `upsert_ioc`, `add_observation`, `get_cached`/`put_cached`, `quota_used`, `prune_observations`, `recent_ips`…). **Desde F-B2 (2026-08-09): `ingest.py`** (`ingest_run()`, el punto único de escritura que comparten colector y backfill) y **`backfill.py`** (`python3 -m separatio.store.backfill [--since AAAA-MM-DD] [--dry-run]`, reconstruye desde `data/honeypot/by-date/*/` y reclasifica snapshots anteriores a F-A). **Desde F-C:** `recent_ips` trae además `sensors`/`has_payload` (criterio de prioridad del residuo). **Desde F-D (2026-08-09): `queries.py`** (`ip_recurrence`/`payload_history`/`hassh_fanout`/`top_recurrent` — la reincidencia acotada a ventana, no el contador de toda la vida del indicador). El fichero es `data/archivo.db` (gitignored). Sólo stdlib: lo importa el colector, que corre sin venv |
| `separatio/lists.py` | **El filtro gratis** (F-E, 2026-08-09): `LocalLists` — pertenencia de IPs en jamesbrine + IPsum + FireHOL (tor_exits, level1) sin gastar cuota. No es un `Enricher`; lo consulta `honeypot_recon.py` (F-C) sobre las IPs del honeypot, no sobre los IOCs de los artículos. `array('I')` + bisect (4 bytes/IP), cache en `data/feeds/*.txt` con TTL de 12h y fail-open a copia vencida. 79,8 MB de pico medidos en el CT (techo 120 MB). Toggle `LOCAL_LISTS_ENABLED` |
| `tests/` | Los **339** tests de ambos paquetes: `venv/bin/pytest tests/ -q` (sin red). 42 previos + 31 de F-A + 21 de F-H + 21 de F-I + 19 de F-B1 + 12 de F-B2 + 11 de F-E + 14 de F-C + 9 de F-D + 3 de F-G/G-7 + 45 de F-G/G-3 + 36 de F-G/G-5 + 43 de F-G/G-6 + 32 de F-G/G-2 |
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
venv/bin/pytest tests/ -q         # 339 tests, sin red
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

**Los informes se publican al share (2026-08-10).** El CT 113 tiene `mp0` bind-mounteado a
`/mnt/pve/nvme-data/cloud/Intel` del host en `/mnt/informes`, y un `ExecStartPost=-` en
`separatio.service` / `separatio-weekly.service` corre `/usr/local/bin/publicar-informes.sh`, que
copia ahí **sólo el PDF y el HTML** de cada carpeta de fecha. Copyparty (CT 104) ya sirve
`/media/storage` entero, así que aparecen solos en `/Intel/<fecha>/`. El directorio de trabajo
sigue local: los dry-run, el caché y los manifiestos no llegan al share. Y ojo, dato que costó
encontrar: **hasta el 2026-08-10 el CT no generaba ningún PDF** — `weasyprint` estaba instalado
pero sin `libpango`, y `_write_pdf` se comía el `OSError` con un `except Exception`. Ya están las
librerías del sistema puestas.
En el laptop **no queda nada** corriendo (hubo timers de usuario unas horas ese día; se
desmontaron — las pruebas van en contenedores).

## Pendiente (en orden)

0. ~~⚠️ **`cowrie.json` crece sin tope y el colector lo lee entero.**~~ — **☑ resuelto el
   2026-08-10, y el pendiente estaba mal en casi todo.** logrotate **no estaba instalado** en VM1
   (los ficheros de `/etc/logrotate.d/` los dejaron otros paquetes): no rotaba nada. Y el arreglo
   que este punto proponía —logrotate diario— se probó y **corrompía el log**: Cowrie cae en
   `logtype = "plain"`, que es `open(path, "w")` sin `O_APPEND`, así que con `copytruncate` el fd
   conserva el offset y deja un agujero de **998.071 bytes de NULs**. Quedó con la rotación nativa
   (`logtype = rotating`, `CowrieDailyLogFile`, medianoche UTC) + un timer de retención a 14 días.
   El crecimiento real remedido sobre 79 min sostenidos es **~18 MB/día**, no 26.

   Lo que sí toca a este repo: rotar abría **un punto ciego diario de 2,5 h** —los pulls van a
   03:30/09:30/15:30/21:30 UTC y la rotación a las 00:00, así que lo escrito entre el pull de las
   21:30 y la medianoche no lo leía nadie—. Se arregló en el `hp-readonly` de synapse, que ahora
   sirve **el rotado de ayer más el fichero vivo**; `pull_honeypot.sh` no cambió. La idea de pedir
   sólo la cola queda descartada: con el log acotado a ≤48 h ya no hace falta. Detalle y
   verificación en `~/Projects/Motherbase/honeypot/EXPONER.md` §La rotación de Cowrie.
1. ⚠️ **Cerrar F-D contra dato real — se puede a partir del 2026-08-11.** Los honeypots se
   expusieron el 2026-08-10 y el store pasó de vacío a **28 IOCs / 75 observaciones / 2 payloads**
   en el primer pull. Lo único que falta para el criterio de cierre del rework es que **pase un
   segundo día**: `days_seen >= 2` sigue en 0 por definición. Si una IP vuelve, F-D se cierra con
   la frase que el criterio pide. Ver `docs/fases/F-D.md`.

   *(Contexto del acceso, que cambió: **el 22 de synapse es de Cowrie**; la administración va por
   **62022**, y el colector del CT 113 ya está reapuntado. As-built y trampas —Ubuntu 24.04 activa
   sshd por socket, `ListenStream` pelado bindea sólo IPv6, el REDIRECT hace que INPUT vea 2222— en
   `~/Projects/Motherbase/honeypot/EXPONER.md`.)*

   *(Lo de esta tanda que ya está hecho, 2026-08-10: el despliegue de las nueve fases —CT en
   `dc5e850`, reinstalado, `OWN_IPS` puesta, backfill corrido, `honeypot-pull.service` verificado
   con `[pull] higiene:` y `[pull] store:`—; los **tres bugs** que el despliegue destapó
   —`pytest` escribiendo en el store real, el `--dry-run` del backfill contando de más, y el CT sin
   generar PDF por falta de `libpango`—; y la **publicación de los informes al share** que sirve
   copyparty. As-built de todo en `docs/REWORK-ESTADO.md` §Despliegue. Falta ver una **corrida
   completa del pipeline** en el CT: estrena el manifiesto de F-H, las "Limitaciones" de F-I y el
   primer PDF con las plantillas de G-6 — el timer de las 07:04 la hace sola, y el informe crece
   ~9 % y cuesta ~$0,09 más por corrida.)*
2. ~~**CrowdSec en VM2**~~ — **☑ hecho el 2026-08-10** (CrowdSec 1.7.8 en ivory, detección pura,
   `cscli bouncers list` vacío y sin paquetes ni cadenas de bouncer). La premisa quedó **medida**:
   desde el REDIRECT de las 11:33 UTC, el sshd real de VM1 lleva **0 fallos de auth** e ivory **65
   desde 12 IPs** en la misma ventana de 72 min.

   Del lado de este repo: `pull_honeypot.sh` le pide `cscli decisions list -o json` también a VM2
   (a `raw/decisions_vm2.json`), y **el flag distingue por sensor** — se conserva `crowdsec`
   (booleano, su único consumidor es el comentario del CSV de MISP) y se agrega
   `crowdsec_sensors: ["vm1-crowdsec"|"vm2-crowdsec"]`. El sensor de CrowdSec **no** entra en
   `sensors`: ese conjunto es "dónde la vimos pegar" y alimenta el cruce de "vista por >1 sensor";
   una decisión es un juicio derivado del mismo sshd, no un avistamiento independiente. 7 tests
   nuevos —los primeros que cubren este camino—, 348 pasan.

   Verificado con una corrida real de `honeypot-pull.service`: `[pull] crowdsec: 1 IP(s) por
   vm2-crowdsec`, y esa IP (`45.148.10.152`) es justo el caso que justifica el cambio — pegó a
   **Cowrie en VM1** y está baneada por el **CrowdSec de VM2**, corroboración cruzada entre hosts.
   Trampa a no repetir: `crowdsec -no-api` **no** desconecta del LAPI, así que una corrida one-shot
   para medir empuja alertas reales con `created_at` de ahora. Medir con `cscli metrics` sobre el
   servicio en vivo. Detalle en `~/Projects/Motherbase/honeypot/EXPONER.md` §CrowdSec.
3. **Dos semanas de informes solos** (criterio de cierre de F0) — verificar cada tanto con
   `docs/DEPLOY.md` §4. Desde F-H eso se chequea con **`separatio --last-run`** (o
   `journalctl -u separatio.service`), no mirando si apareció el fichero. **Decidir si el CT 113
   entra en los jobs de backup** (hoy no está) — pesa más desde el 2026-08-10: `data/archivo.db`
   dejó de estar vacío.
3. Decidir si se archiva `Fennek115/ip_threatcheck` en GitHub.
4. **Prender `honeypot_recon` con GreyNoise real** (F-C, cuando el usuario lo pida): hoy queda
   construido, testeado y verificado con `LocalLists` real + GreyNoise mockeado a propósito — activar
   el toggle gasta cuota real (20/semana reservadas de las 25 medidas sin key).
5. ~~Verificar F-D contra dato real~~ — **ya no está bloqueada**: los honeypots se expusieron
   el 2026-08-10 y el store tiene dato real. Pasó al punto 1.
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
