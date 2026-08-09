# F-I · Afinado de prompts: sacarle todo a lo que ya se le pasa

> Estado: **☐ pendiente — sesión 2** · Depende de: **F-H** (el manifiesto alimenta el prompt)
> Índice: [`../REWORK-ESTADO.md`](../REWORK-ESTADO.md)
>
> **Completamente especificada. Ejecutar y documentar.**

## Objetivo

Que el LLM aproveche todo lo que el pipeline ya recolecta — y que **sepa lo que no tiene**.

## ¿Ya está hecho?

```bash
cd ~/Projects/Intel
grep -n "COBERTURA\|cobertura" separatio/analyzer.py || echo "→ los prompts no declaran faltantes"
grep -n "PROMPT_CAPS" separatio/config.py || echo "→ los topes siguen hardcodeados"
grep -n "correlation if phase in" separatio/pipeline.py   # si sigue, latam/general no ven enrichment
grep -n "output_config\|attack_techniques" separatio/analyzer.py || echo "→ sin salida estructurada ni campos nuevos"
ls separatio/reports/ab/ 2>/dev/null || echo "→ sin comparación A/B"
```

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
    "verdicts_per_source":   60,   # era 25 hardcodeado (enrichment.py:130)
    "iocs_per_article":      20,   # era 8  hardcodeado (analyzer.py:649)
    "trending_actors":       12,   # era 8  (history.py:60)
    "trending_cves":         10,   # era 6  (history.py:69)
    "honeypot_notes":        10,   # ya era config (HONEYPOT_MAX_NOTES)
}
```

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

*(vacío hasta el cierre — los dos informes del A/B, el bloque de cobertura real y el delta de tokens
en dólares)*

## Pendientes que deja

*(a completar. Previsible: decidir si `effort: "medium"` queda en producción según lo que muestre el
A/B, y si el esquema de Stage 2 se extiende a más campos una vez que se vea qué extrae bien)*
