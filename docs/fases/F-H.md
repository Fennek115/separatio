# F-H · Observabilidad de la corrida

> Estado: **☑ HECHA el 2026-08-09** · Sin dependencias
> Índice: [`../REWORK-ESTADO.md`](../REWORK-ESTADO.md)
>
> As-built con salida real al final. Lo que el plan no había previsto está en
> §"Dónde ganó la máquina".

## Objetivo

Poder responder, después de cada corrida y sin leer 190 KB de log: **qué corrió, qué se usó, qué
falló y por qué, y qué datos NO llegaron al LLM.**

Va primero porque el pipeline **ya está en producción** corriendo solo todos los días, y el criterio
de cierre de F0 —dos semanas de informes sin intervención— hoy sólo se puede verificar mirando si
apareció el fichero. Eso no dice si el informe se generó con la mitad de las fuentes caídas.

## ¿Ya está hecho?

**Sí, desde el 2026-08-09.** Estos comandos ahora responden: el módulo existe, hay manifiesto,
`--last-run` imprime, el handler rota y el `logger.debug(msg)` ya no está.

```bash
cd ~/Projects/Intel
ls separatio/runlog.py 2>/dev/null || echo "→ no existe el módulo de manifiesto"
ls separatio/reports/$(date +%F)/run-manifest.json 2>/dev/null || echo "→ sin manifiesto de hoy"
venv/bin/separatio --last-run 2>/dev/null || echo "→ sin comando de consulta"
ls -la separatio/reports/pipeline.log*                     # ¿hay rotación? (esperado: .1, .2…)
grep -n "RotatingFileHandler" separatio/pipeline.py || echo "→ log sin rotación"
grep -n "logger.debug(msg)" separatio/analyzer.py && echo "→ el consumo de tokens sigue invisible"
```

## Contexto mínimo — el diagnóstico, medido el 2026-08-09

### Lo que se descarta en silencio antes de llegar al LLM

| Dónde | Qué se pierde | ¿Se declara hoy? |
|---|---|---|
| `enrichment.py:130` | `format_for_prompt` corta a **25 veredictos por fuente** | **no** |
| `analyzer.py:649` | `_format_phase_items` corta **IOCs a 8 por artículo** | **no** |
| `pipeline.py:676` | El enrichment sólo llega a `vulnerability` y `threat_intel`: **LATAM y general nunca lo ven** | no |
| `history.py:60,66,78` | Trending corta a 8 actores / 6 CVEs / 5 deltas | no |
| `pipeline.py:364` | `truncate_text(ARTICLE_MAX_TOKENS=2500)` corta el cuerpo del artículo | marcado en el texto, **no contado** |
| `pipeline.py:316` | `PER_FEED_LIMIT=10` y `MAX_ARTICLES=120` recortan el lote | parcial |
| `extractor.py:70` | `FETCH_HARD_TIMEOUT` abandona el fetch → el artículo entra **sólo con el título** | WARNING suelto |
| `enrichers/honeypot.py:64` | `max_notes=10`, `sample_uris[:3]` | no |
| Stage 3/4 | `_format_phase_items` con `PHASE_ARTICLE_LIMITS` | ✅ **sí** — el prompt dice "N adicionales cubiertos en estadísticas". Es el único que lo hace bien y es el modelo a seguir |

### Lo que no se ve del gasto

`analyzer._log_usage` escribe los tokens con `logger.debug(msg)` y `basicConfig` está en
`level=INFO`: **el consumo nunca aparece**. Sólo se ve cuando el output se trunca, y ahí es una
advertencia suelta sin totales.

### Lo que no se ve de los fallos

Los enrichers caídos quedan en `ctx.sources_failed` y se loguean como WARNING, pero no se persiste
nada consultable. Después de una semana no hay forma de responder "¿cuántas veces falló OpenPhish
este mes?". Y `main()` termina con **código 0 casi siempre**, así que `systemctl status` da verde
aunque la corrida haya sido a medias.

### El log

`separatio/reports/pipeline.log` son **188 KB sin rotación**, en modo append: crece para siempre y
no hay forma de aislar una corrida de otra.

## Pasos

### 1. `separatio/runlog.py` — el manifiesto

```python
@dataclass
class Drop:
    where: str        # "enrichment.format_for_prompt"
    kind: str         # cap | truncate | filter | failure
    shown: int
    total: int
    detail: str = ""  # "IPsum" / "articulo 42" / …

@dataclass
class LlmCall:
    stage: str; model: str
    in_tokens: int; out_tokens: int
    finish_reason: str; truncated: bool; duration_s: float

@dataclass
class Failure:
    component: str    # "enricher:OpenPhish" / "stage:3"
    error_type: str
    message: str

@dataclass
class RunManifest:
    date: str
    mode: str                     # full | dry-run | report-only | weekly
    started_at: str
    finished_at: str | None = None
    status: str = "ok"            # ok | degraded | failed
    stages: dict = field(default_factory=dict)   # nombre -> {ok, duration_s, error}
    counts: dict = field(default_factory=dict)   # articulos_disponibles, tomados, resumidos, fallidos…
    drops: list[Drop] = field(default_factory=list)
    llm_calls: list[LlmCall] = field(default_factory=list)
    failures: list[Failure] = field(default_factory=list)
    sources: dict = field(default_factory=dict)  # enricher -> "ok" | "failed: <motivo>"

    def totals(self) -> dict:
        """{'in_tokens': n, 'out_tokens': n, 'llamadas': n, 'truncadas': n, 'datos_omitidos': n}"""
```

**API de instrumentación** — sin cambiar firmas por todo el árbol:

```python
def start_run(date: str, mode: str) -> RunManifest: ...
def current() -> RunManifest | _NoOp:
    """El manifiesto activo, o un no-op si no hay corrida iniciada."""
def record_drop(where, shown, total, detail="", kind="cap") -> None: ...
def record_llm(stage, model, in_tok, out_tok, finish, max_tokens, duration_s) -> None: ...
def record_failure(component, exc) -> None: ...
def record_stage(name, ok, duration_s, error=None) -> None: ...
def finish_run(path: str | Path) -> RunManifest: ...
```

> **Por qué un singleton de módulo y no inyección.** El manifiesto es transversal como el `logger`:
> lo tocan `extractor`, `enrichment`, `history` y `analyzer`, que no comparten firma. Inyectarlo
> obligaría a cambiar ocho funciones y contradice el objetivo de no tocar el pipeline. Es la misma
> excepción que ya se acepta para `logging`.
>
> **El no-op es la pieza que lo hace seguro:** si nadie llamó a `start_run` (tests, import suelto,
> `ipcheck` como CLI), `record_drop` no hace nada y no falla. Instrumentar nunca puede romper.

### 2. Instrumentar los ocho puntos de recorte

Una línea en cada uno. Ejemplo del más importante:

```python
# separatio/enrichment.py, en format_for_prompt
for source, items in by_source.items():
    lines.append(f"  ▸ {source}:")
    if len(items) > cap:
        runlog.record_drop("enrichment.format_for_prompt", cap, len(items), detail=source)
    for v in items[:cap]:
        ...
```

Los ocho: `enrichment.format_for_prompt` · `analyzer._format_phase_items` (artículos **e** IOCs) ·
`history.format_for_prompt` · `extractor.truncate_text` · `pipeline.stage1_fetch` (por feed y
global) · `extractor.extract_article_text` (fallback a título) · `pipeline.stage2_summarize`
(fallidos) · `enrichers/honeypot.py`.

`truncate_text` hoy devuelve sólo el texto; que devuelva el texto y registre el drop internamente
(tiene el largo original y el recortado).

### 3. Tokens visibles

En `analyzer._log_usage`: `logger.debug` → **`logger.info`**, y además `runlog.record_llm(...)`.
El coste de una corrida pasa a ser una línea del log y un total en el manifiesto.

### 4. Rotación del log

En `pipeline.py`, cambiar `logging.FileHandler` por
`logging.handlers.RotatingFileHandler(maxBytes=5*1024*1024, backupCount=5)` — stdlib, sin
dependencias. Y una línea separadora al inicio de cada corrida con el modo y la fecha, para poder
aislar corridas dentro del mismo fichero.

Config: `LOG_MAX_BYTES = 5_242_880`, `LOG_BACKUP_COUNT = 5`, `LOG_LEVEL = "INFO"`.

### 5. `status` y código de salida

Reglas, en `finish_run`:

| `status` | Cuándo | Exit code |
|---|---|---|
| `ok` | Todas las etapas OK y ninguna fuente caída | 0 |
| `degraded` | El informe se generó, pero hubo fuentes caídas, etapas fallidas no críticas o salidas truncadas | 0 |
| `failed` | No se generó informe | 1 |

`degraded` sale con 0 a propósito: si saliera con 1, el timer marcaría la unidad como fallida todos
los días que un feed esté caído y el usuario dejaría de mirarlo. El estado se consulta con
`--last-run`, no con el exit code.

### 6. Salida: el manifiesto y el resumen

- `reports/YYYY-MM-DD/run-manifest.json` — escritura **atómica**, reusando el patrón de
  `history.save_history` (`separatio/history.py:101`: tmp + `fsync` + `os.replace`). Bajo
  `--dry-run` cae solo en `reports/dryrun/…` porque `OUTPUT_DIR` ya está redirigido.
- Un bloque al final del log, legible:

```
══════════════════════════════════════════════════
  RESUMEN DE LA CORRIDA — 2026-08-09  [degraded]
══════════════════════════════════════════════════
  Duración:     8m 42s
  Artículos:    120 disponibles → 120 tomados → 116 resumidos, 4 fallidos
  LLM:          9 llamadas · 214.380 in / 18.902 out · 1 truncada (fase vulnerability)
  Enrichers:    5 ok (IPsum, ipcheck, Ransomware.live, onion-lookup, MalwareBazaar)
                1 FALLIDA: OpenPhish — InvalidURL: Invalid IPv6 URL
  Datos NO enviados al LLM:
    · 43 veredictos de enrichment recortados (IPsum 38/63, ipcheck 5/30)
    · 12 IOCs recortados en 3 artículos (tope de 8 por artículo)
    · 7 artículos truncados por ARTICLE_MAX_TOKENS
    · 2 artículos entraron sólo con el título (fetch abandonado por timeout)
    · enrichment NO llegó a las fases latam y general (por diseño actual)
══════════════════════════════════════════════════
```

Ese bloque es el entregable de la fase: **es lo que el usuario pidió, en once líneas.**

### 7. `separatio --last-run`

Flag nuevo en `main()`: lee el `run-manifest.json` más reciente de `OUTPUT_DIR` y reimprime el
resumen sin correr nada. `--last-run --json` escupe el manifiesto crudo.

### 8. `tests/test_runlog.py`

| Test | Qué fija |
|---|---|
| `test_sin_start_run_las_llamadas_son_noop` | `record_drop` sin corrida activa no falla ni acumula |
| `test_record_drop_acumula` | 3 drops de fuentes distintas |
| `test_totales_de_tokens` | Suma in/out y cuenta truncadas |
| `test_status_ok_sin_fallos` | |
| `test_status_degraded_con_fuente_caida` | Un `Failure` de enricher ⇒ `degraded`, exit 0 |
| `test_status_failed_sin_informe` | Etapa 3 fallida ⇒ `failed`, exit 1 |
| `test_manifiesto_se_escribe_atomico` | No queda `.tmp`; contenido válido tras `finish_run` |
| `test_manifiesto_es_json_valido_con_acentos` | `ensure_ascii=False`, se relee bien |
| `test_resumen_lista_los_drops` | El bloque de texto menciona los recortes reales |
| `test_last_run_lee_el_mas_reciente` | Con dos manifiestos de fechas distintas |
| `test_drop_registra_shown_y_total` | 25/68 y no sólo "hubo recorte" |

Y **un test de integración del recorte real**, que es el que importa:

| `test_format_for_prompt_registra_el_recorte` | 30 veredictos de una fuente ⇒ un `Drop(shown=25, total=30)` |
| `test_format_phase_items_registra_iocs_recortados` | Un artículo con 12 IOCs ⇒ `Drop(shown=8, total=12)` |

## Criterio de hecho

1. Una corrida real (o `--report-only`, que es barata) produce `run-manifest.json` **y** el bloque
   de resumen en el log.
2. El manifiesto lista **al menos un recorte real con sus números** (`shown`/`total`) y el consumo
   de tokens de todas las llamadas.
3. **Un fallo inyectado se ve:** apagar una key (p.ej. `ABUSECH_API_KEY=` vacía) y correr ⇒
   `status: degraded` con el enricher y el motivo declarados. ⚠️ **Corregido al ejecutar:** sin
   key, MalwareBazaar **no falla — se salta en silencio** (`enrichers/malwarebazaar.py:81`,
   `return` temprano), así que nunca llega a `failures`. Lo que se ve es
   `sources["MalwareBazaar"] = "skipped: sin ABUSECH_API_KEY"` y la línea `OMITIDA:` del resumen.
   Ver §"Dónde ganó la máquina" (1).
4. `venv/bin/separatio --last-run` reimprime el resumen.
5. La suite sigue verde.

```bash
venv/bin/separatio --report-only
cat separatio/reports/$(date +%F)/run-manifest.json | python3 -m json.tool | head -40
venv/bin/separatio --last-run
ABUSECH_API_KEY= venv/bin/separatio --report-only && venv/bin/separatio --last-run | grep -A3 FALLIDA
venv/bin/pytest tests/ -q
```

## As-built — 2026-08-09

Estado al empezar (bloque "¿Ya está hecho?"): **nada hecho**. Sin `runlog.py`, sin manifiesto,
`--last-run` inexistente, `pipeline.log` en 192 881 bytes sin rotación y `logger.debug(msg)` vivo en
`analyzer.py:282`.

### Qué se construyó

| Archivo | Qué |
|---|---|
| `separatio/runlog.py` (nuevo, 480 líneas) | El manifiesto: `Drop`/`LlmCall`/`Failure`/`RunManifest`, el singleton con no-op, escritura atómica, `summary_text()` y `find_latest_manifest()` |
| `separatio/config.py` | `LOG_MAX_BYTES=5_242_880`, `LOG_BACKUP_COUNT=5`, `LOG_LEVEL="INFO"`, `ENRICH_PROMPT_MAX_PER_SOURCE=25` |
| `separatio/pipeline.py` | `RotatingFileHandler`; `main()` partido en `main()`+`_run()` para que el manifiesto se cierre en `finally` pase lo que pase; etapas envueltas en `runlog.stage(...)`; `--last-run [--json]`; `ENRICHED_PHASES` |
| `separatio/analyzer.py` | `_log_usage` → **INFO** + `record_llm`; `stage=` en las 5 llamadas LLM; `PROMPT_IOCS_PER_ARTICLE` |
| `separatio/extractor.py` | `truncate_text` y el fallback a título registran su propio recorte |
| `separatio/enrichment.py`, `history.py`, `enrichers/honeypot.py`, `enrichers/malwarebazaar.py` | Recortes y estado de fuente instrumentados |
| `tests/test_runlog.py` (nuevo) | 21 tests. Suite total: **73 → 94**, sin red |

Los **diez** puntos de recorte instrumentados (los ocho del plan + dos que aparecieron):
`enrichment.format_for_prompt` · `analyzer._format_phase_items` (artículos **e** IOCs) ·
`analyzer.build_report_prompt.iocs` *(extra)* · `history.format_for_prompt` ·
`extractor.truncate_text` · `extractor.extract_article_text` · `pipeline.stage1_fetch` (por feed y
global) · `pipeline.stage2_summarize` · `pipeline.stage3_phases.enrichment` *(extra: las fases sin
enrichment)* · `enrichers/honeypot.py` (notas y URIs).

### Salida real — `--report-only`, con `ABUSECH_API_KEY` vacía a propósito

```
══════════════════════════════════════════════════
  RESUMEN DE LA CORRIDA — 2026-08-09  [degraded]
══════════════════════════════════════════════════
  Modo:         report-only
  Duración:     7m 31s
  Artículos:    120 desde caché
  LLM:          5 llamadas · 52.897 in / 21.076 out
  Enrichers:    5 ok (IPsum, OpenPhish, ipcheck, Ransomware.live, onion-lookup)
                OMITIDA: MalwareBazaar — sin ABUSECH_API_KEY
  Datos NO enviados al LLM:
    · 34 artículos no enviados al prompt de fase (general 20/54)
    · 8 IOCs recortados por el tope por artículo (UNC6671 Rebrands: Multi-Brand Vishing Ex 8/10, Living off the coding agent: Two tales o 8/10, ChainDrop Worm Infects 400+ npm Packages 8/10, +2 más)
    · 2 fases que NO reciben enrichment, por diseño actual (sin enrichment: latam, general 2/4)
══════════════════════════════════════════════════
```

`venv/bin/separatio --last-run` reimprime exactamente eso (más la ruta del manifiesto) y sale con
**0**, como debe: `degraded` no pone la unit en rojo.

Fragmento del `run-manifest.json` (3 795 bytes, `reports/2026-08-09/`):

```json
"status": "degraded",
"stages": { "cache": {"ok": true, "duration_s": 0.0},
            "stage2.5": {"ok": true, "duration_s": 0.21},
            "stage3_phases": {"ok": true, "duration_s": 189.31},
            "stage4": {"ok": true, "duration_s": 35.12} },
"counts": { "articulos_cache": 120 },
"drops": [ {"where": "pipeline.stage3_phases.enrichment", "kind": "filter",
            "shown": 2, "total": 4, "detail": "sin enrichment: latam, general"},
           {"where": "analyzer._format_phase_items.iocs", "kind": "cap",
            "shown": 8, "total": 10, "detail": "UNC6671 Rebrands: Multi-Brand Vishing Ex"} ],
"llm_calls": [
  {"stage": "phase:vulnerability", "model": "claude-sonnet-5",           "in_tokens": 14346, "out_tokens": 8583, "duration_s": 77.11},
  {"stage": "phase:threat_intel",  "model": "claude-sonnet-5",           "in_tokens": 20092, "out_tokens": 4662, "duration_s": 50.98},
  {"stage": "phase:latam",         "model": "claude-haiku-4-5-20251001", "in_tokens": 4279,  "out_tokens": 3647, "duration_s": 36.52},
  {"stage": "phase:general",       "model": "claude-haiku-4-5-20251001", "in_tokens": 8111,  "out_tokens": 2121, "duration_s": 24.69},
  {"stage": "synthesis",           "model": "claude-opus-5",             "in_tokens": 6069,  "out_tokens": 2063, "duration_s": 35.11} ],
"sources": { "IPsum": "ok", "OpenPhish": "ok", "ipcheck": "ok", "Ransomware.live": "ok",
             "onion-lookup": "ok", "MalwareBazaar": "skipped: sin ABUSECH_API_KEY" },
"totals": { "in_tokens": 52897, "out_tokens": 21076, "llamadas": 5,
            "truncadas": 0, "datos_omitidos": 44 }
```

Y el `--dry-run --limit 5` (sin LLM, aislado en `reports/dryrun/`), que ejercita las etapas 1–2:

```
  RESUMEN DE LA CORRIDA — 2026-08-09  [ok]
  Modo:         dry-run
  Duración:     6s
  Artículos:    25 en el pool → 5 tomados → 5 resumidos, 0 fallidos
  Datos NO enviados al LLM:
    · 15 artículos descartados por el tope por feed (10/25)
    · 5 artículos descartados por MAX_ARTICLES (5/10)
```

**Dato que el proyecto no tenía hasta hoy:** una corrida de informe cuesta **~53 K tokens de
entrada y ~21 K de salida en 5 llamadas**, y las fases no truncan (0 truncadas — confirma que los
`PHASE_MAX_TOKENS` subidos el 2026-08-08 fueron suficientes).

### Dónde ganó la máquina

1. **`ABUSECH_API_KEY=` vacía no produce un fallo.** El plan (criterio 3) daba por hecho que el
   enricher entraría a `failures`; en realidad `malwarebazaar.py` hace `return` temprano y
   `run_enrichment` lo marca **ok** porque no lanzó. Una fuente habilitada que no consulta nada
   quedaba indistinguible de una que dijo "no hay nada". Se agregó el estado **`skipped`**:
   el enricher lo declara y `record_source` **no lo deja pisar con `ok`**. Cuenta como `degraded`.
   Es el hallazgo más útil de la fase: el plan buscaba ver los fallos y apareció una categoría peor,
   la fuente muda.
2. **`articulos_disponibles` no existe.** Con `PER_FEED_LIMIT` activo, Stage 1 le pide a Miniflux
   `limit*5` entradas: lo que se contaba como "disponibles" era el **pool consultado**, no el total
   de no leídos. La clave se llama `articulos_pool` y el resumen dice "en el pool".
3. **La API real es más grande que la especificada.** Además de las siete funciones del plan:
   `record_count`, `record_source`, `record_report`, `expect_no_report`, `reset`, el context manager
   `stage()`, `write_manifest`, `load_manifest`, `find_latest_manifest`. Ninguna cambia firmas del
   pipeline; `stage()` es lo que evita repetir el `time.monotonic()` en siete lugares.
4. **`_format_phase_items` sí cambió de firma** (tercer parámetro `phase=""`, con default), para que
   el drop diga *cuál* fase recortó. Es interna a `analyzer.py` y no rompe a nadie.
5. **Un día sin artículos no es un fallo.** El status `failed` se definió como "no se generó
   informe", pero eso convertiría en rojo un día en que Miniflux no tiene nada nuevo. Se agregó
   `expect_no_report(motivo)`: esos casos son `degraded` y salen con 0.
6. **`--last-run` en dry-run necesita `--dry-run --last-run`**, porque `--dry-run` redirige
   `OUTPUT_DIR` a `reports/dryrun/` y el manifiesto del dry-run vive ahí.

### Artefactos de prueba que quedaron en el laptop

El laptop **no** tiene corrida propia del día (la real corre en el CT 113), así que para probar
`--report-only` se sembró `reports/2026-08-09/summaries-cache-2026-08-09.json` **copiando la caché
del 2026-08-08**. En consecuencia `reports/2026-08-09/` del laptop contiene un informe fechado hoy
con noticias de ayer: es material de prueba, no un informe. `history.json` **no** se tocó
(`--report-only` no pasa por Stage 2.6).

### Lo que no se pudo observar

La **rotación efectiva** del log: el fichero está en 215 KB de los 5 MB que la disparan. Se verificó
en runtime que el handler activo es `RotatingFileHandler maxBytes=5242880 backupCount=5` sobre
`separatio/reports/pipeline.log`. El primer `.1` aparecerá solo.

## Pendientes que deja

1. ⚠️ **Desplegar al CT 113** (junto con lo de F-A, que también está sin desplegar): `git pull` en
   `/opt/intel/app`. A partir de ahí `journalctl -u separatio.service` muestra el resumen de cada
   corrida — que es lo que faltaba para verificar el cierre de F0 sin leer el log entero.
2. Decidir si se agrega `OnFailure=` a la unit systemd ahora que el exit code significa algo
   (0 = ok/degraded, 1 = sin informe).
3. **F-I hereda el manifiesto**: los `drops` son material de prompt — el modelo tiene que saber lo
   que no tiene. En particular el drop `pipeline.stage3_phases.enrichment`, que hoy sólo se declara
   en el manifiesto y no en el informe.
4. Cuando exista el store (F-B1), agregar una tabla `run` para consultar la serie histórica
   —"¿cuántas veces falló OpenPhish este mes?"— en vez de leer manifiestos sueltos.
5. Menor: `_format_phase_items` registra el drop de artículos **una vez por fase**, y
   `build_report_prompt` (modo legacy, `PHASE_REPORTS=False`) lo registra bajo la misma clave con
   `detail="informe consolidado"`. Si algún día se separan las claves, el resumen queda más claro.
