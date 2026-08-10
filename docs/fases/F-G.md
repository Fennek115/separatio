# F-G · Deuda técnica

> Estado: **☐ track paralelo — cuando moleste** · Sin dependencias duras
> Origen: [`../IMPROVEMENTS.md`](../IMPROVEMENTS.md) §6 · Índice: [`../REWORK-ESTADO.md`](../REWORK-ESTADO.md)
>
> **Especificada por ítems.** A diferencia de las demás, esta fase **no se cierra de una vez**: se
> toma un ítem por sesión, cuando estorbe.

## Objetivo

No inventar trabajo nuevo. El roadmap de refactors de junio sigue vigente y el rework le agrega
razones concretas.

## ¿Ya está hecho?

```bash
cd ~/Projects/Intel
wc -l separatio/pipeline.py separatio/analyzer.py separatio/reporter.py \
      separatio/honeypot_collector.py
grep -c "^from separatio import config\|^from separatio.config import" separatio/*.py separatio/**/*.py
venv/bin/pytest tests/ -q | tail -1
```

## Los ítems, en orden de urgencia real

### G-1 · Partir `consolidate()` *(deuda que dejó F-A — la más barata)*

`separatio/honeypot_collector.py:consolidate()` es una función de **294 líneas** (medido: líneas
60–353). Salió así **a propósito**: el movimiento desde el heredoc de `tools/pull_honeypot.sh` se
hizo verbatim para poder verificar que no cambiaba la salida (y se verificó: `iocs.csv` y
`events.jsonl` idénticos byte a byte).

Ahora hay 11 tests que la cubren, así que partirla es seguro:

- `parse_cowrie(lines, cutoff, bump, record)` · `parse_web(...)` · `parse_beelzebub(...)`
- `parse_cowrie_downloads(tar_path, dl_meta, ...)`
- `write_artifacts(out, daydir, payload, events, payloads)`

**Verificación:** los mismos tests pasan sin tocarlos, y un `NO_PULL=1` sobre los `raw/` de siempre
produce salida idéntica.

### G-2 · `IMPROVEMENTS.md` §6.4 — configuración inyectable *(el rework lo empeoró)*

`config.py` como módulo global dificulta los tests. **F-A ya tuvo que rodearlo**:
`hygiene.build_classifier(config)` acepta `config=None` y cae al entorno precisamente porque no se
puede inyectar. F-B/F-C van a repetir el patrón (`open_store(path=None)` leyendo de config).

Propuesta de `IMPROVEMENTS.md`: un dataclass `Settings` (o `pydantic.BaseSettings`) inyectado en las
firmas. **Prerrequisito:** hacerlo *después* de F-C, para no mover el suelo mientras se agregan
tres módulos que leen config.

### G-3 · `IMPROVEMENTS.md` §6.3 — modularizar `pipeline.py` *(cerrado 2026-08-09)*

855 líneas y cada fase del rework le suma una etapa. Extraer: `dedup_by_cves` → `deduplicator.py`;
`_detect_ioc_type` + `export_iocs` → `ioc_processor.py` (reusando `enrichment.ioc_kind`); ruteo por
fases → `router.py`.

### G-4 · `IMPROVEMENTS.md` §6.5 — enriquecer el export de IOCs *(quick win)*

`export_iocs` corre **antes** de Stage 2.7, así que el CSV/JSON de IOCs sale sin los veredictos de
reputación. Reordenar (o re-exportar) para incluir `EnrichmentContext.export_rows()`.

Con F-C encima esto vale más: el export pasaría a llevar también el veredicto del honeypot.

### G-5 · `IMPROVEMENTS.md` §6.1 — abstracción de proveedores LLM *(cerrado 2026-08-09)*

`_llm_chat` hace dispatch por `if provider ==` y la rama de streaming de Ollama está **duplicada**.
Independiente del rework; se hace si se vuelve a tocar `analyzer.py`.

### G-6 · `IMPROVEMENTS.md` §6.2 — reporter con plantillas

CSS/HTML como strings de Python y un parser de Markdown por regex. Independiente del rework.

### G-7 · Bugs menores conocidos *(cerrado 2026-08-09)*

- Enricher OpenPhish falla con `Invalid IPv6 URL` (tolerado por el try/except de Stage 2.7, no
  rompe el run).
- Warnings cosméticos de trafilatura en Stage 1 (`discarding data: None`).

## La regla de esta fase

**Ningún refactor puede cambiar la salida del pipeline.** Se verifica con la suite completa y con un
`--dry-run` comparado antes/después — el mismo método que usó F-A para mover el heredoc:

```bash
venv/bin/pytest tests/ -q
venv/bin/separatio --dry-run --limit 5     # comparar el .md resultante con el previo
```

## Deuda que el rework va dejando

*(cada fase anota acá lo que difirió, al cerrar)*

- **F-A:** `consolidate()` sin partir → **G-1**.
- **F-G/G-3:** una clave **extra** en `PHASE_CATEGORY_MAP` (fuera de las cuatro canónicas) genera su
  fase en Stage 3 —se paga la llamada al LLM— y después `stage4_synthesis` **no la ensambla** en el
  informe final: el texto se tira. Hoy no pasa (la config tiene exactamente las cuatro canónicas),
  por eso G-3 lo preservó tal cual en vez de arreglarlo: el ítem no podía cambiar la salida.
  Arreglarlo es una línea (`CANONICAL_PHASES` → `phase_order()` en `stage4_synthesis`).
- **F-A:** `tools/pull_honeypot.sh` tuvo la IP pública de casa en claro desde el commit `8a53bad`
  en un repo público. Se redactó en los ficheros, pero **sigue en el historial de git**. Decidir si
  vale reescribir la historia o dejarlo (la IP es dinámica y ya cambió).

## As-built

*(un bloque por ítem cerrado, con su verificación)*

### G-1 · Partir `consolidate()` — cerrado 2026-08-09

`separatio/honeypot_collector.py` tenía `consolidate()` en 306 líneas (63–369). Se extrajeron,
tal como proponía el ítem, cinco funciones de módulo (nivel superior, no closures):

- `parse_cowrie(lines, cutoff, bump, record, att, dl_meta)` — necesita `att` además de `bump`/
  `record` porque el HASSH se escribe directo sobre la fila del atacante (`att[ip]["hassh"]`),
  no pasa por ninguna de las dos closures.
- `parse_web(lines, cutoff, bump, record)`
- `parse_beelzebub(lines, cutoff, bump, record)`
- `parse_cowrie_downloads(tarp, dl_meta, klass, payloads, events)`
- `write_artifacts(raw, out, daydir, payload, events, payloads) -> new_payloads` — la firma
  propuesta en el plan (`write_artifacts(out, daydir, payload, events, payloads)`) no traía `raw`,
  pero el paso (2) copia los crudos del día a `daydir/raw/` y necesita el directorio de origen;
  se agregó al firmarla. `bump`/`record`/`klass` siguen siendo closures dentro de `consolidate()`
  porque cierran sobre `att`/`hyg`/`events`/`payloads`/`classifier` — pasarlas explícitas hubiera
  significado seis parámetros por función sin ganar nada.

`consolidate()` quedó en **131 líneas** — ya no arma el CSV ni escribe a disco, sólo parsea las
cuatro fuentes, arma `attackers`/`payload` y delega el resto.

**Verificación** (regla de la fase: ningún refactor cambia la salida):

- `venv/bin/pytest tests/ -q` → **180 passed**, sin tocar ningún test.
- Comparación binaria antes/después sobre un `raw/` sintético que ejercita las cinco rutas
  (comando Cowrie con HASSH, login fallido, descarga con `shasum`+tar de 2º stage, request web,
  Beelzebub HTTP y TCP, decisión de CrowdSec): `attackers.json`, `iocs.csv` (rolling y por
  fecha), `events.jsonl`, `events.latest.jsonl`, `hashes.log` y `payloads/*.bin` salieron
  **idénticos byte a byte** entre la versión vieja y la nueva (único campo que cambia es
  `generated`, un timestamp de la corrida, esperado). El `raw/` real en disco
  (`data/honeypot/raw/`) es sólo tráfico propio (127.0.0.1, el laptop) y da 0 atacantes en ambas
  versiones — no ejercita las rutas interesantes, por eso el fixture sintético fue necesario.
- No hizo falta `NO_PULL=1` contra `tools/pull_honeypot.sh`: es el mismo `consolidate()` que
  invoca, así que el diff de arriba ya cubre ese camino.

Deuda que quedó igual: `pipeline.py` (970 líneas, **G-3**) y la config global (**G-2**) no se
tocaron — este ítem era sólo `honeypot_collector.py`.

### G-4 · Enriquecer el export de IOCs — cerrado 2026-08-09

`export_iocs()` corría antes de Stage 2.7 en las dos rutas del día (`--report-only` y la corrida
completa), así que el CSV/JSON de IOCs nunca llevaba el veredicto de reputación externa —
`EnrichmentContext.export_rows()` (ya existía, de F-4/Stage 2.7 original) estaba escrito y sin
consumidor.

Cambios, ambos en `separatio/pipeline.py`:

- `export_iocs()` ganó un cuarto parámetro opcional `enrichment=None`. Cuando se pasa un
  `EnrichmentContext`, cada fila del export lleva una columna nueva `reputation` con
  `"fuente:etiqueta"` por cada veredicto que matchea ese IOC (`"|"`-separado si hay más de uno,
  cadena vacía si no hay ninguno) — mismo criterio de un-string-por-celda que ya usaba `cves`. La
  columna se agrega siempre (con o sin `enrichment`) para que el esquema del CSV no cambie según
  el caso: sin `enrichment`, todas las filas quedan con `reputation=""`.
- Las dos llamadas a `export_iocs()` en `_run()` se movieron de **antes** de `stage25_correlate`/
  `stage27_enrich` a **después** de `stage27_enrich`, pasándole el `enrichment` ya calculado. El
  resto del orden de la corrida no cambió (cache, `mark_as_read`, `unload_model` siguen donde
  estaban).
- `run_weekly()` no se tocó: no corre Stage 2.7, así que sigue llamando a `export_iocs()` sin
  `enrichment` — la fila sale con `reputation=""`, igual que antes de este cambio.

Con `honeypot_recon` (F-C) todavía en `OFF` esto no cambia el export de producción hoy: sin ese
toggle, ningún IOC del honeypot entra al `ctx` de Stage 2.7 con el veredicto fuerte. El cambio
deja el mecanismo listo para cuando se prenda.

**Verificación:**

- `venv/bin/pytest tests/ -q` → **180 passed**, sin tocar ningún test (no había tests que
  ejercitaran `export_iocs` directamente — se buscó `iocs.csv`/`iocs_csv`/`reputation` en `tests/`
  y sólo aparecían en `test_honeypot_collector.py`, que prueba el CSV de otro módulo,
  `honeypot_collector.py`, no `pipeline.export_iocs`).
- Prueba manual con un `ArticleSummary` sintético (IOCs `1.2.3.4` + `evil.com`) y un
  `EnrichmentContext` con un veredicto de IPsum para `1.2.3.4`: la fila de `1.2.3.4` salió con
  `reputation: "IPsum:malicious"` en CSV y JSON, la de `evil.com` con `reputation: ""`, y llamando
  sin `enrichment` ambas filas salieron con `reputation: ""` — mismo esquema de columnas en los
  tres casos.
- `venv/bin/separatio --dry-run --limit 5` corrió limpio de punta a punta (`status: ok`, 5
  artículos resumidos) ejercitando el nuevo orden de llamadas real; el día no tenía IOCs en los 5
  artículos tomados, así que no se generó `iocs.csv` (comportamiento preexistente: `export_iocs`
  devuelve `{}` sin filas), pero confirma que mover la llamada no rompe la ruta de dry-run.

Deuda que sigue igual: G-2, G-3, G-5, G-6, G-7 sin tocar.

### G-3 · Modularizar `pipeline.py` — cerrado 2026-08-09

`pipeline.py` tenía **985 líneas** al empezar la sesión (el ítem decía 855 y el as-built de G-1
había medido 970: cada fase del rework le fue sumando etapa, que es justamente el argumento del
ítem). Quedó en **839** y tres módulos nuevos, todos hojas del grafo de imports —ninguno importa
`pipeline`—, así que se pueden testear sin levantar el pipeline entero (sin `load_dotenv`, sin
`logging.basicConfig`, sin crear `OUTPUT_DIR`):

| Módulo | Líneas | Qué se llevó |
|---|---|---|
| `separatio/deduplicator.py` | 58 | `dedup_by_cves` |
| `separatio/ioc_processor.py` | 120 | `detect_ioc_type` (era `_detect_ioc_type`) + `export_iocs` + `CSV_FIELDS` |
| `separatio/router.py` | 81 | `group_by_phase`, `CANONICAL_PHASES`, `CORRELATED_PHASES`, `TRENDING_PHASES`, `phase_order()`, `receives_correlation()`, `receives_trending()` |

Detalles que el ítem no preveía:

1. **No se reusó `enrichment.ioc_kind`**, contra lo que decía el plan. Las dos funciones parecen la
   misma pero tienen contratos distintos, y sustituir una por otra habría cambiado la columna `type`
   de `iocs.csv` — lo que la regla de esta fase prohíbe:

   | | `ioc_processor.detect_ioc_type` | `enrichment.ioc_kind` |
   |---|---|---|
   | hashes | `md5` / `sha1` / `sha256` | `hash` (los tres juntos) |
   | entrada | el IOC crudo del resumen | el IOC ya normalizado (minúsculas) |
   | hex en mayúsculas | lo reconoce | cae a `other` |
   | `1.2.3.4:puerto` | sólo con puerto numérico | cualquier cosa después de `:` |

   `ioc_kind` decide a qué enricher mandar un IOC; `detect_ioc_type` etiqueta una fila de un CSV que
   lee una persona. Quedaron separadas y la diferencia está tabulada en el docstring de
   `ioc_processor.py`. De paso se corrigió el comentario de `enrichment.py:49`, que apuntaba a
   `_detect_ioc_type del pipeline` (referencia ya rota) y afirmaba que "coincide" — no coincidía.

2. **El ruteo era más que `group_by_phase`.** El orden canónico de fases estaba escrito dos veces
   —`stage3_phases` lo calculaba como `canonical + extra`, `stage4_synthesis` tenía la lista suelta—
   y las dos reglas de contexto (`phase in CORRELATED_PHASES`, `phase == "threat_intel"`) vivían
   inline. Todo eso pasó a `router.py`. **La divergencia entre las dos listas se preservó a
   propósito**: una clave extra de `PHASE_CATEGORY_MAP` se genera en Stage 3 pero nunca se ensambla
   en el informe final, así que Stage 4 usa `CANONICAL_PHASES` y no `phase_order()`. Es un bug
   latente —una fase extra se pagaría al LLM y se tiraría—, pero arreglarlo cambiaría la salida:
   queda anotado abajo como deuda, no tocado acá.

3. **`csv` y `re` quedaron sin uso** en `pipeline.py` tras la extracción; se sacaron del bloque de
   imports.

Los nombres viejos siguen resolviendo desde `pipeline` (`pipeline.dedup_by_cves`,
`pipeline.export_iocs`, `pipeline.group_by_phase`, `pipeline.CORRELATED_PHASES`), porque los tres
módulos se importan al namespace del orquestador. Nada fuera de `pipeline.py` los usaba —se
verificó con un grep por todo el repo— pero la documentación sí los nombra así.

**Verificación** (regla de la fase: ningún refactor cambia la salida):

- **Equivalencia función a función contra el `pipeline.py` previo**, el método de G-1: se guardó una
  copia del módulo viejo y se compararon las dos implementaciones sobre entrada sintética —
  `detect_ioc_type` sobre 29 IOCs de borde (hex en mayúsculas, `1.2.3.4:abc`, `evil[.]com`,
  `hxxp://`, IPv6, vacío, sin TLD, unicode), `export_iocs` **byte a byte** con y sin
  `EnrichmentContext`, `dedup_by_cves` con tres pares de umbrales, y `group_by_phase` /
  `phase_order` contra la config real. Salida: `✓ sin diferencias entre pipeline.py previo a G-3 y
  los módulos extraídos` (0 diferencias sobre 44 comprobaciones).
- `venv/bin/pytest tests/ -q` → **228 passed** (183 previos sin tocar + **45 nuevos**:
  10 en `tests/test_deduplicator.py`, 22 en `tests/test_ioc_processor.py`, 13 en
  `tests/test_router.py`). Antes de esta sesión `pipeline.py` **no tenía un solo test** —ningún
  test del repo lo importaba—, así que las tres funciones extraídas pasaron de 0 a cobertura
  propia. Ese es el segundo beneficio del ítem, aparte de las 146 líneas.
- `venv/bin/separatio --dry-run --limit 5` antes y después: el informe
  `threat-briefing-2026-08-09.md` salió **idéntico** (`diff` vacío) y el `run-manifest.json` trae
  los mismos contadores y los mismos tres recortes (`per_feed 22/25`, `global 5/22`,
  `correlation 1/2`). El `summaries-cache` difiere sólo en el **orden** de dos entradas: Stage 2
  consume con `as_completed` sobre un `ThreadPoolExecutor`, así que ese orden nunca fue
  determinista — comparados como conjuntos, los 5 resúmenes son idénticos campo por campo.
- `venv/bin/separatio --dry-run --report-only`: la otra ruta que llama a `export_iocs` corrió limpia
  de punta a punta (`RESUMEN DE LA CORRIDA — [ok]`), incluida Stage 2.7 real.
- `run_weekly()` (tercera llamada a `export_iocs`) **no se ejercitó en vivo**: gasta una llamada LLM
  de informe semanal. La función que invoca es la misma, verificada byte a byte arriba.

Deuda que sigue igual: G-2, G-5, G-6 sin tocar. `pipeline.py` en 839 líneas sigue siendo el archivo
más grande después de `analyzer.py` (1241) y `reporter.py` (830) — el resto es orquestación real
(las etapas, `main`/`_run`, el caché), no lógica extraíble sin rediseñar, que es lo que G-2 propone.

### G-7 · Bugs menores conocidos — cerrado 2026-08-09

Los dos bugs eran del mismo tipo: una excepción de una dependencia que el try/except de Stage 2.7
ya toleraba, pero que perdía la fuente entera esa corrida en vez de la línea puntual que la
disparaba.

- **OpenPhish `Invalid IPv6 URL`**: causa confirmada — `urllib.parse.urlparse()` levanta
  `ValueError: Invalid IPv6 URL` ante un `[` suelto en el netloc (`urlparse("http://[malformed")`
  ya alcanza para reproducirlo, no hace falta IPv6 real). `_load()` la disparaba por línea del feed
  y `enrich()` por IOC extraído del artículo — una sola línea/IOC malformado tiraba `_load()` o el
  loop entero, y `run_enrichment()` marcaba **todo** OpenPhish como `failed` para el día, perdiendo
  también los hits válidos de las demás líneas. Se agregó `_safe_netloc()` en
  `separatio/enrichers/openphish.py` (`urlparse(...).netloc` envuelto en `try/except ValueError`,
  devuelve `""`) y se usa en los dos sitios en vez de `urlparse(...).netloc` directo. La línea/IOC
  malformado puntual ahora simplemente no aporta host; el resto del feed y del run siguen intactos.
- **`discarding data: None` de trafilatura**: no era un fallo — es `trafilatura/core.py:477`
  (`LOGGER.warning("discarding data: %s", options.source)`) avisando que descartó un documento por
  texto insuficiente/idioma/duplicado, control de flujo normal suyo que ya cae al fallback de
  `requests`+BeautifulSoup en `_fetch_url_content_inner`. Se bajó el logger propio de trafilatura
  (`logging.getLogger("trafilatura")`) a `ERROR` en `separatio/extractor.py`, junto al resto de la
  config de logging del módulo — no toca el logger raíz del pipeline ni ningún otro logger.

**Verificación:**

- `venv/bin/pytest tests/ -q` → **183 passed** (3 nuevos en `tests/test_openphish.py`:
  `_safe_netloc` sobre input malformado, `_load()` con una línea `http://[malformed` en medio del
  feed sin perder las otras dos, `enrich()` con un IOC malformado en el dict sin levantar).
- Reproducción directa del bug original antes del fix:
  `urlparse("http://[malformed")` → `ValueError: Invalid IPv6 URL` (confirmado en el intérprete del
  venv, misma versión de Python que corre el pipeline).
- `venv/bin/separatio --dry-run --limit 5` de punta a punta: `RESUMEN DE LA CORRIDA — [ok]`, sin
  ninguna línea `Invalid IPv6 URL` ni `discarding data` en la salida (antes del fix ambas aparecían
  de forma intermitente según el feed del día).

Deuda que sigue igual: G-2, G-3, G-5, G-6 sin tocar.

### G-5 · Abstracción de proveedores LLM — cerrado 2026-08-09

`analyzer._llm_chat` (285-369 en la numeración de `IMPROVEMENTS.md`) mezclaba las cuatro APIs con
`if provider == "ollama" / elif == "claude" / elif == "openai" / elif == "gemini"`, y el loop de
streaming de Ollama estaba copiado dos veces —en `generate_report` y `generate_phase_report`—, cada
copia con su propia variación de logging. Se hizo tal como proponía el plan: paquete
`separatio/providers/` con la clase abstracta `LLMProvider` (`chat()` para una respuesta completa,
`chat_stream()` opcional — la base cae a `chat()`, así que sólo el proveedor que streamea de verdad
la sobreescribe) y una fábrica `get_provider(name, ollama_host="")`.

| Módulo | Qué tiene |
|---|---|
| `providers/base.py` | `LLMProvider` (ABC), `ChatResult` (dataclass: `text`/`in_tok`/`out_tok`/`finish`), `get_api_key()` |
| `providers/ollama.py` | `OllamaProvider` — `chat()` y `chat_stream()` reales, el único lugar del repo con el loop de streaming (antes duplicado) |
| `providers/anthropic_provider.py` | `AnthropicProvider` — la única llamada con `output_schema`/`effort` (Claude/F-I) |
| `providers/openai_provider.py` | `OpenAIProvider` |
| `providers/gemini_provider.py` | `GeminiProvider` |
| `providers/__init__.py` | `_REGISTRY` + `get_provider()` — el único lugar con el nombre de los cuatro proveedores |

`analyzer.py` bajó de 1241 a **1154 líneas** (-87): `_build_options` y `_get_api_key` se movieron a
`providers/` (a `ollama.py` y `base.py` respectivamente — ninguno de los dos era específico de
`analyzer.py`), y `_llm_chat` quedó en 6 líneas de cuerpo: pide el proveedor a la fábrica, llama
`.chat()`, loguea el consumo con `_log_usage` (que no se tocó, sigue en `analyzer.py` porque conoce
`runlog`/el manifiesto — eso es de la orquestación, no del proveedor) y devuelve el texto limpio.
Nueva `_llm_chat_stream` (paralela a `_llm_chat` pero sin loguear consumo por sí sola — ver el quirk
abajo) es lo que ahora comparten las dos ramas Ollama de `generate_report`/`generate_phase_report`:
cada una le pasa su propio callback `on_token` (para el mensaje de log, que sí difiere: "Generando
informe..." contra "[{phase}] Generando...") y decide después qué hacer con el `ChatResult` que
vuelve.

**Un hallazgo, no arreglado a propósito** (misma disciplina que dejó la fase con
`PHASE_CATEGORY_MAP` en G-3): las dos ramas Ollama nunca se comportaron igual respecto al
manifiesto. `generate_phase_report` llamaba `_log_usage` (así que cada fase queda en
`run-manifest.json`); `generate_report` (el informe legacy de una sola llamada, `PHASE_REPORTS =
False`) **nunca la llamó** — el consumo de esa llamada no se registraba en ningún lado. Es un bug
menor y asimétrico, pero **arreglarlo habría cambiado la salida** (un `llm_calls` de más en el
manifiesto de una corrida `PHASE_REPORTS=False`), algo que la regla de esta fase prohíbe. Se
preservó literal: `generate_report` sigue sin loguear consumo para Ollama, `generate_phase_report`
sigue logueándolo. Queda anotado como deuda — arreglarlo es agregar `_log_usage` a la rama de
`generate_report`, un cambio de una línea el día que se pueda tocar la salida (o cuando
`PHASE_REPORTS=False` deje de ser código vivo, que es la situación real desde que el proveedor es
Claude).

Como el proveedor Ollama está descontinuado (**el CT 111 ya no existe**, ver `CLAUDE.md` de la
raíz), ni antes ni después del refactor hay forma de probar `OllamaProvider` contra un servidor
real — la única llamada real posible hoy es contra Claude, que es lo que se hizo.

**Verificación** (regla de la fase: ningún refactor puede cambiar la salida):

- `venv/bin/pytest tests/ -q` → **264 passed** (228 previos sin tocar + **36 nuevos**: 18 en
  `tests/test_providers.py` —cada proveedor con su SDK reemplazado por un doble en `sys.modules`
  (`openai` y `google.generativeai` ni siquiera están instalados en el venv — no son dependencias
  del proyecto — así que probarlos así es la única manera), incluida la fábrica, `get_api_key`, y
  el comportamiento por defecto de `chat_stream()` cayendo a `chat()`— y 18 en
  `tests/test_analyzer_llm.py`, que fijan con un `FakeProvider` inyectado en
  `analyzer.get_provider` el comportamiento exacto de `_llm_chat`, `_llm_chat_stream`,
  `generate_report`, `generate_phase_report`, `generate_synthesis_report`, `generate_weekly_report`
  y `summarize_article` — **incluido el quirk de logging de arriba**, verificado explícitamente
  (`test_generate_report_ollama_no_llama_log_usage` contra
  `test_generate_phase_report_ollama_si_llama_log_usage`). Antes de esta sesión ninguna de estas
  funciones tenía un solo test — el mismo punto de partida que tuvo `pipeline.py` antes de G-3.
- **Llamada real contra Claude** (la única API viva hoy) ejercitando las tres funciones que cambiaron
  más: `_llm_chat` directo (`stage=smoke-g5`, `claude-haiku-4-5-20251001`, devolvió `"OK"` limpio),
  `generate_phase_report` (`phase=general`, un `ArticleSummary` sintético) y
  `generate_synthesis_report` — las tres funcionaron de punta a punta contra la API real y quedaron
  en `runlog.current().llm_calls` con `stage="phase:general"` y `stage="synthesis"` respectivamente
  (`max_tokens=80` a propósito para que la llamada sea barata; salió truncada, esperado con ese
  tope, no es un fallo del refactor).
- `venv/bin/separatio --dry-run --limit 5`: el `.md` del informe salió **idéntico** al de antes del
  refactor (`diff` vacío). El manifiesto y el HTML difieren sólo en el timestamp de la corrida y en
  qué artículos tomó Miniflux esta vez (el pool de no leídos cambió entre una corrida y la otra —
  no es una regresión, es el mismo no-determinismo de origen externo que ya anotó G-3). **Esto no
  verifica el cambio real**: `--dry-run` nunca llama al LLM (`stage3_report`/`stage3_phases`
  devuelven texto `[DRY RUN]` fijo sin pasar por `generate_report`/`generate_phase_report`), así que
  las funciones que este ítem tocó están fuera de su alcance — de ahí que la verificación real haya
  sido la llamada contra Claude de arriba, no el dry-run.
- `venv/bin/python -m pyflakes separatio/analyzer.py separatio/providers/*.py` → limpio, sin
  imports sin usar (`_build_options`/`_get_api_key` se movieron completos, no quedaron a medias).

`pyproject.toml` ganó `separatio.providers` en `[tool.setuptools] packages` y se corrió
`pip install -e '.[dev]'` en esta sesión (mismo paso que F-B1 dejó anotado para `separatio.store`:
sin reinstalar, el subpaquete nuevo no se registra en un editable install).

Deuda que sigue igual: G-2, G-6 sin tocar. `unload_model()` (Ollama, `keep_alive=0` para liberar RAM
antes del swap de etapa) se dejó **fuera de `providers/`** a propósito: no es una llamada de chat,
no tiene equivalente en las APIs cloud, y forzarla a la interfaz `LLMProvider` habría sido una
abstracción sin segundo caso de uso.
