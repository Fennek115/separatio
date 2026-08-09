# F-I · Afinado de prompts: sacarle todo a lo que ya se le pasa

> Estado: **☑ HECHA el 2026-08-09** · Depende de: **F-H** (el manifiesto alimenta el prompt)
> Índice: [`../REWORK-ESTADO.md`](../REWORK-ESTADO.md)
>
> Los seis pasos se ejecutaron tal como estaban escritos. Salida real en [§As-built](#as-built).

## Objetivo

Que el LLM aproveche todo lo que el pipeline ya recolecta — y que **sepa lo que no tiene**.

## ¿Ya está hecho?

```bash
cd ~/Projects/Intel
grep -n "def coverage_block" separatio/runlog.py   || echo "→ los prompts no declaran faltantes"
grep -n "PROMPT_CAPS" separatio/config.py          || echo "→ los topes siguen hardcodeados"
grep -n "enrichment=enrichment" separatio/pipeline.py || echo "→ latam/general no ven enrichment"
grep -n "ARTICLE_SUMMARY_SCHEMA" separatio/analyzer.py || echo "→ sin salida estructurada"
venv/bin/pytest tests/test_analyzer_prompts.py -q  || echo "→ los tests de la fase no existen o fallan"
```

**Respuesta al 2026-08-09 (cierre):** las cinco líneas responden que sí. La fase está hecha; el
A/B vivió en el scratchpad de la sesión, no en el repo (`separatio/reports/` está gitignored y los
informes del día se regeneran) — los números están abajo, en el as-built.

## Contexto mínimo

La base de los prompts está bien: system prompt por fase (`VULN_`, `THREAT_`, `LATAM_`, `GENERAL_`,
`SYNTHESIS_SYSTEM_PROMPT`), formato de salida exacto, sección `REGLAS`, y bloques de correlación y
trending inyectados. Lo que falta son cuatro cosas concretas.

### Los datos de los modelos, verificados

| Modelo | Dónde se usa | Contexto | Salida máx | Precio in/out por millón |
|---|---|---|---|---|
| `claude-haiku-4-5` | Stage 2 (extracción), fases latam y general | 200K | 64K | $1 / $5 |
| `claude-sonnet-5` | Fases vulnerability y threat_intel | **1M** | 128K | $3 / $15 |
| `claude-opus-5` | Stage 4 (síntesis) | **1M** | 128K | $5 / $25 |

**Los topes actuales son de la era Ollama con `num_ctx=2048`.** Con 1M de contexto, cortar a 25
veredictos por fuente y 8 IOCs por artículo no ahorra nada relevante: ahorra centavos y cuesta
señal. El manifiesto de F-H da el número real de tokens para decidirlo con dato en vez de a ojo.

## Pasos

### 1. Declarar cobertura y faltantes

Un bloque nuevo, generado **desde el manifiesto de F-H**, inyectado en los cuatro prompts de fase y
en el de síntesis:

```
COBERTURA DE ESTA CORRIDA
(lo que este análisis SÍ y NO tiene — no afirmes con confianza sobre lo que falta):
  · Artículos: 116 de 120 resumidos. 4 fallaron en extracción.
  · 2 artículos entraron sólo con el título (no se pudo bajar el cuerpo).
  · 7 artículos con el cuerpo truncado.
  · Enrichment: 5 fuentes OK. FALLÓ OpenPhish → la cobertura de phishing de hoy es PARCIAL.
  · Se muestran 35 de 78 artículos de esta fase (los de mayor severidad).
  · 43 veredictos de reputación quedaron fuera del prompt por tope de tamaño.

REGLA: si una fuente falló, no afirmes ausencia de esa clase de amenaza — decí que no se pudo
verificar.
```

La última línea es la que más importa. Hoy, si OpenPhish falla, el informe puede decir "no se
observó actividad de phishing" cuando lo cierto es que **nadie miró**.

Implementación: `runlog.RunManifest.coverage_block()` (F-H ya tiene los datos) y una llamada en
`_build_pre_analysis` / cada `build_*_prompt`. El precedente ya existe: `build_vuln_prompt` genera
la nota *"Se muestran N artículos…; M adicionales"* — esto la generaliza a todo lo demás.

### 2. Revisar los topes contra el modelo real

Todos a `config.py`, en un solo lugar:

```python
PROMPT_CAPS = {
    "verdicts_per_source":  60,   # era 25 (config.ENRICH_PROMPT_MAX_PER_SOURCE)
    "iocs_per_article":     20,   # era 8  hardcodeado en analyzer.py
    "trending_actors":      12,   # era 8  hardcodeado en history.py
    "trending_new_actors":  12,   # era 8  hardcodeado en history.py
    "trending_cves":        10,   # era 6  hardcodeado en history.py
    "trending_deltas":       8,   # era 5  hardcodeado en history.py
}
```

*(As-built: quedó así. `honeypot_notes` **no** entró — `HONEYPOT_MAX_NOTES` ya vivía en `config.py`
y moverlo sólo habría roto el call site del enricher sin ganar nada. En cambio aparecieron dos topes
del bloque de trending que el plan no había listado, `trending_new_actors` y `trending_deltas`,
igual de hardcodeados que los otros.)*

**El método, no el número.** Los valores de arriba son un punto de partida; la fase los fija
midiendo con el manifiesto de F-H: correr con los topes viejos y con los nuevos sobre el mismo
caché, y comparar `in_tokens`. Con Sonnet 5 a $3 por millón de entrada, **10.000 tokens extra por
fase cuestan 3 centavos de dólar** — el tope no se justifica por costo; se justifica sólo si el
informe empeora por ruido, que es lo que mide el A/B.

`PHASE_ARTICLE_LIMITS` (vuln 50 / threat 35) **se queda como está**: ese recorte sí es sustantivo y
además ya se declara en el prompt.

### 3. El enrichment a todas las fases

Hoy: `correlation=correlation if phase in ("vulnerability", "threat_intel") else None`
(`pipeline.py:676`). LATAM y general nunca ven que una IP del artículo esté en una blocklist o haya
pegado al honeypot propio.

**No basta con pasar `correlation` a las cuatro.** El enrichment viaja de contrabando dentro de
`CorrelationContext.extra_blocks` — un atajo de la época en que no se querían tocar las firmas de
`analyzer.py`. Pasarlo entero llevaría también KEV y EPSS a LATAM, que es ruido.

La fase separa las dos cosas:

- `stage27_enrich` **deja de** hacer `correlation.extra_blocks.append(block)` y devuelve el `ctx`.
- `generate_phase_report` y `build_*_prompt` reciben un parámetro `enrichment` propio.
- Cada fase recibe lo que le sirve: correlación (KEV/EPSS) a vulnerability y threat_intel;
  **enrichment a las cuatro**; trending a threat_intel.

Es exactamente el refactor que `IMPROVEMENTS.md` §6 anticipaba, y ahora hay una razón concreta.

### 4. Campos estructurados nuevos en Stage 2

Al JSON de `build_summary_prompt`:

```python
"attack_techniques": ["IDs MITRE ATT&CK explícitos, ej: T1566.001. Vacío si no se mencionan"],
"exploitation_status": "active|poc|none|unknown",
"confidence": "alta|media|baja",
```

Hoy esto vive enterrado en la prosa de `summary`, donde el correlator no lo puede cruzar. Con
campos propios, `correlator.py` puede hacer con las técnicas lo mismo que ya hace con CVEs y
actores: **corroboración entre fuentes** ("T1566 mencionada por 4 medios distintos hoy") y
`history.py` puede trendearlas.

Cambios de acompañamiento:

- `ArticleSummary` (dataclass) suma los tres campos con `default_factory` / default.
- La carga del caché (`load_summaries_cache`) tiene que **tolerar cachés viejos sin los campos** —
  usar `.get()` con default, no indexación. Si no, `--report-only` sobre un caché de ayer explota.
- `correlator.build_correlation_context` suma `corroborated_techniques` (mismo patrón que
  `corroborated_cves`).

### 5. Garantizar el JSON en vez de reintentarlo

Hoy Stage 2 pide *"Responde SOLO con este JSON"* y `stage2_summarize` **reintenta una vez** ante
`JSONDecodeError`. Cada reintento es una llamada pagada de más.

Los tres modelos del pipeline —`claude-haiku-4-5`, `claude-sonnet-5` y `claude-opus-5`— **soportan
salida estructurada**, que garantiza JSON válido contra un esquema:

```python
resp = client.messages.create(
    model=..., max_tokens=...,
    output_config={"format": {"type": "json_schema", "schema": ARTICLE_SUMMARY_SCHEMA}},
    ...
)
```

Va en `_llm_chat` como parámetro opcional (`output_schema=None`), usado **sólo por Stage 2** — las
fases 3 y 4 producen Markdown, no JSON.

Cuatro límites del esquema que hay que respetar al escribirlo:

1. **Todo objeto necesita `additionalProperties: false`** y su lista `required`.
2. **No se pueden expresar los topes** (`"máx 5 actores"`, `"máx 10 CVEs"`): las restricciones
   numéricas y de longitud, y las de array complejas, no están soportadas. Esos límites **siguen en
   el texto del prompt**, no en el esquema.
3. La primera petición con un esquema nuevo paga una **compilación**; después se cachea 24 h. Con
   una corrida diaria eso significa pagarla todos los días — es un costo fijo chico, pero hay que
   saberlo antes de sorprenderse en el manifiesto.
4. Si la respuesta se trunca por `max_tokens` (`stop_reason: "max_tokens"`), el JSON puede quedar
   incompleto igual. El manejo de error se conserva; lo que baja es la frecuencia.

Al terminar, el reintento por `JSONDecodeError` se conserva como red, pero el manifiesto de F-H debe
mostrar **cero reintentos** en una corrida normal. Ese es el número que prueba que sirvió.

### 6. `effort`: la palanca de coste que nunca se tocó

`output_config.effort` no se setea en ninguna llamada, así que todas corren en el default `high`.
Sonnet 5 y Opus 5 aceptan la escala completa (`low`/`medium`/`high`/`xhigh`/`max`); **Haiku 4.5 no
acepta `effort`** — pasárselo es un error, así que Stage 2 y las fases latam/general quedan afuera.

```python
PHASE_EFFORT = {"vulnerability": "high", "threat_intel": "high", "synthesis": "high"}
```

Se deja en `high` (el default actual, sin cambio de conducta) y la fase **mide** `medium` en el A/B.
Si el informe no empeora, es una reducción directa de tokens de razonamiento en las tres llamadas
más caras del día.

> **Nota para no perseguir un fantasma:** el prompt caching **no aplica acá**. El prefijo estable de
> Stage 2 (`SUMMARY_SYSTEM_PROMPT`) son ~50 tokens y el mínimo cacheable de Haiku 4.5 es **4096**;
> las fases 3 y 4 corren una vez al día, muy por encima del TTL. No hay nada que ganar.

## Validación: A/B sobre el mismo caché

Es la decisión del usuario y es lo que hace verificable la fase. `--report-only` regenera el informe
desde `summaries-cache-YYYY-MM-DD.json` **sin volver a llamar a Stage 2**, así que comparar cuesta
sólo las llamadas de Stage 3/4:

```bash
# 1. Línea base con los prompts viejos (antes de tocar nada)
git stash                       # o correr desde el commit anterior
venv/bin/separatio --report-only
cp -r separatio/reports/$(date +%F) /tmp/.../ab/antes
git stash pop

# 2. Con los prompts nuevos, sobre EL MISMO caché
venv/bin/separatio --report-only
cp -r separatio/reports/$(date +%F) /tmp/.../ab/despues

# 3. Comparar
diff <(wc -w /tmp/.../ab/antes/reports/*.md) <(wc -w /tmp/.../ab/despues/reports/*.md)
diff /tmp/.../ab/antes/run-manifest.json /tmp/.../ab/despues/run-manifest.json | grep -i token
```

Qué mirar, en este orden:

1. **¿Aparece el bloque de cobertura y es correcto?** (cotejarlo contra el manifiesto)
2. **¿El informe usa datos que antes no llegaban?** — buscar en el Markdown nuevo IOCs o veredictos
   que estaban recortados en el viejo.
3. **¿Cuánto subió la entrada?** — del manifiesto, en tokens y traducido a dólares con la tabla de
   arriba.
4. **¿Empeoró algo?** — secciones más ruidosas, repetición, pérdida de foco.

Los cuatro puntos, con los dos informes citados, van al as-built.

## Criterio de hecho

1. El informe generado **declara explícitamente** al menos un faltante real (una fuente caída, un
   recorte, o artículos sólo-título).
2. El A/B está hecho y documentado con los cuatro puntos de arriba.
3. Un IOC o veredicto que **antes se recortaba** aparece en el informe nuevo.
4. El manifiesto muestra **0 reintentos de JSON** en Stage 2.
5. `pytest` verde y `separatio --dry-run` intacto.

## Ficheros

`separatio/analyzer.py` (prompts, `_format_phase_items`, `_llm_chat`, `ArticleSummary`) ·
`separatio/enrichment.py` (`format_for_prompt`) · `separatio/history.py` (`format_for_prompt`) ·
`separatio/pipeline.py` (`stage27_enrich`, `stage3_phases`, `load_summaries_cache`) ·
`separatio/correlator.py` (técnicas corroboradas) · `separatio/config.py` ·
`separatio/runlog.py` (`coverage_block`, de F-H) · `tests/test_analyzer_prompts.py` (nuevo)

## Tests

| Test | Qué fija |
|---|---|
| `test_bloque_de_cobertura_lista_las_fuentes_caidas` | Manifiesto con un `Failure` ⇒ el bloque lo nombra |
| `test_bloque_de_cobertura_lista_los_recortes` | Con dos `Drop` ⇒ ambos aparecen |
| `test_sin_faltantes_no_se_inyecta_el_bloque` | Corrida limpia ⇒ prompt sin ruido |
| `test_los_topes_salen_de_config` | Cambiar `PROMPT_CAPS` cambia el prompt |
| `test_enrichment_llega_a_las_cuatro_fases` | Regresión del cambio 3 |
| `test_correlacion_no_llega_a_latam` | La contraparte: KEV/EPSS no se filtra donde no sirve |
| `test_cache_viejo_sin_campos_nuevos_carga` | `load_summaries_cache` sobre un JSON sin `attack_techniques` |
| `test_tecnicas_corroboradas_entre_fuentes` | 2 medios con T1566 ⇒ corroborada |
| `test_esquema_json_es_valido` | El esquema de Stage 2 tiene `additionalProperties: false` y `required` |

## As-built

Ejecutada el **2026-08-09**. 115 tests (94 + 21 nuevos en `tests/test_analyzer_prompts.py`).

### El bloque de cobertura, real

Salida literal de `runlog.coverage_block("general")` sobre el manifiesto de la corrida del A/B:

```
COBERTURA DE ESTA CORRIDA
(lo que este análisis SÍ y NO tiene — no afirmes con confianza sobre lo que falta):
  · Artículos: 120 cargados del caché del día (no se volvió a consultar Miniflux).
  · Enrichment: 6 fuentes OK (IPsum, MalwareBazaar, OpenPhish, Ransomware.live, ipcheck, onion-lookup).
  · Se muestran 20 de 54 artículos de la fase 'general' (los de mayor severidad); los 34 restantes no están en el listado.

REGLA: si una fuente falló o se omitió, NO afirmes ausencia de esa clase de amenaza — decí que no
se pudo verificar. Si hubo recortes, no presentes el listado como exhaustivo.
```

El bloque es **por fase**: el de `latam` sale sin la línea del recorte de `general` (ese recorte no
cambia nada de lo que LATAM tiene que escribir). La síntesis lo pide sin fase y ve todo.

### A/B sobre el mismo caché — los cuatro puntos

Línea base: la corrida `--report-only` de las 04:59 del 2026-08-09, con el código anterior
(su manifiesto todavía trae la clave vieja `pipeline.stage3_phases.enrichment`). Comparación:
misma caché de 120 resúmenes, mismos modelos, mismos `PHASE_MAX_TOKENS`.

**1. ¿Aparece el bloque de cobertura y es correcto?** Sí, y el informe lo declara: **cinco** líneas
`**Limitaciones de esta corrida:**`, una por fase más la síntesis. Antes: **cero**. La del panorama
general cita el número exacto del manifiesto:

> **Limitaciones de esta corrida:** Se muestran 20 de 54 artículos del pool "general"; se omitieron
> 34 artículos de severidad inferior. […] no se verificó cobertura completa de phishing/C2 externos.

**2. ¿El informe usa datos que antes no llegaban?** Sí, por los dos caminos:

- *Tope de IOCs 8 → 20*: de los 8 IOCs que el tope viejo dejaba fuera, aparecen ahora en el informe
  `setupsso[.]com` e `idokta[.]com` (dominios de la campaña de vishing de UNC6671) y la wallet
  `0xE1f2395ee43e45A1556EC6438a88c31B83493103` del gusano ChainDrop. Ninguno estaba en el informe viejo.
- *Enrichment a las cuatro fases*: LATAM menciona a **Qilin** (viene de las notas de Ransomware.live,
  que antes no veía) y el panorama general cita **IPsum, ipcheck y MalwareBazaar** por nombre. En el
  informe viejo, las dos secciones tenían **cero** menciones de enrichment externo.

**3. ¿Cuánto subió la entrada?**

| | llamadas | in | out | coste (lista) | coste (intro Sonnet 5) |
|---|---|---|---|---|---|
| antes    | 5 | 52.897 | 21.076 | $0,4251 | $0,3245 |
| después  | 5 | 56.696 | 26.732 | $0,5190 | $0,3940 |
| **Δ**    | — | **+3.799** | **+5.656** | **+$0,0939 (+22 %)** | +$0,0695 |

**El delta es mayormente de salida, no de entrada**: el prompt creció 3.799 tokens (+7 %) y la
respuesta 5.656 (+27 %) — se paga más porque el modelo *escribe* más con el material nuevo, no
porque el contexto sea más caro. Proyectado: **+$2,82 al mes** con una corrida diaria. Ninguna fase
se acercó a truncar (`vulnerability` 76 % del límite, el resto ≤73 %, las cinco `finish=end_turn`).

**4. ¿Empeoró algo?** No. Por sección: Vulnerability +316 palabras, LATAM +183 (las dos que
recibieron datos nuevos), Threat Intel −93 y General −41 (más cortas, no más largas). Repetición:
2 coincidencias sobre 274 frases contra 0 sobre 249 — las dos son la misma celda de URL repetida en
tres filas de una tabla, no prosa duplicada.

### Salida estructurada de Stage 2 (criterio 4)

Verificada contra la API con dos artículos de prueba (`scratchpad/check_stage2.py`), sin tocar el
informe del día. Haiku 4.5 acepta `output_config.format` y extrae bien los tres campos nuevos:

```
  Critical RCE in Acme VPN exploited in the wild (CVE-2026-4242)
    attack_techniques   : ['T1566.001', 'T1078']
    exploitation_status : active          confidence: alta
  Weekly roundup: security industry news
    attack_techniques   : []
    exploitation_status : none            confidence: alta

  reintentos de JSON en Stage 2: 0
```

El contador `stage2_reintentos_json` es nuevo (`runlog.bump_count`): es el número que hace
auditable el criterio 4 en cada corrida real, sin leer el log.

### Lo que el documento no preveía

1. **`--report-only` no puede verificar el criterio 4**: salta Stage 2 por definición. Se verificó
   con un script aparte contra la API en vez de gastar una corrida completa.
2. **Etiqueta equivocada en el manifiesto de F-H** (`extractor.truncate_text`): el drop cuenta
   *caracteres*, no artículos, y el resumen del dry-run informaba "33245 artículos truncados" sobre
   81 artículos. Corregida en `DROP_LABELS` al verla en una corrida real.
3. **`effort` se decide por modelo, no por nombre de fase** (`analyzer._effort_for`): Haiku 4.5
   devuelve 400 si se le pasa `effort`, y `latam`/`general` corren en Haiku *hoy*. Filtrar por
   `"haiku" in model` hace que si mañana una de esas fases pasa a Sonnet herede el effort sola.
4. **La regla de declarar faltantes tiene que estar en el prompt aunque no haya faltantes.** El
   bloque de cobertura se omite si la corrida está limpia, pero `_LIMITS_RULE` va siempre (dice
   explícitamente "si no hay faltantes declarados, omití esa línea"). Sin eso el modelo sabía lo que
   le faltaba y no lo escribía: el criterio 1 no se cumplía.
5. **`ENRICHED_PHASES` pasó a llamarse `CORRELATED_PHASES`** en `pipeline.py`: con el enrichment
   yendo a las cuatro fases, el nombre viejo mentía. La constante ahora es sólo de correlación
   KEV/EPSS, y el drop asociado también (`pipeline.stage3_phases.correlation`).

## Pendientes que deja

1. **Decidir si `effort: "medium"` entra en producción.** F-I dejó `PHASE_EFFORT` en `high` (el
   default de siempre, sin cambio de conducta) y la palanca cableada y testeada. El A/B midió el
   efecto de los *prompts*, no el del effort: medirlo es cambiar tres valores en `config.py` y
   repetir el `--report-only`. Con la salida siendo el 70 % del coste, es la palanca con más
   recorrido que queda.
2. **Los campos nuevos todavía no se trendean.** `correlator` ya corrobora técnicas ATT&CK entre
   fuentes; falta que `history.py` las meta en la ventana de 14 días como hace con actores y CVEs.
   Necesita días de corridas con el campo poblado — hoy el caché histórico no lo tiene.
3. **`exploitation_status` es material de triage, no sólo de prompt.** Cuando exista el store (F-B1)
   es un candidato natural a columna: "CVEs con `active` que además volvieron N días".
4. **Vigilar `PHASE_MAX_TOKENS["vulnerability"]`**: 12.198 de 16.000 (76 %) es el más ajustado. Si
   un día de muchos CVEs lo hace truncar, el manifiesto lo va a decir (`finish=max_tokens`,
   status `degraded`) — no hay que adelantarse, pero hay que mirarlo.
5. **Desplegar al CT 113** junto con F-A y F-H (el mismo `git pull`).
