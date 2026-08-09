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

### G-3 · `IMPROVEMENTS.md` §6.3 — modularizar `pipeline.py`

855 líneas y cada fase del rework le suma una etapa. Extraer: `dedup_by_cves` → `deduplicator.py`;
`_detect_ioc_type` + `export_iocs` → `ioc_processor.py` (reusando `enrichment.ioc_kind`); ruteo por
fases → `router.py`.

### G-4 · `IMPROVEMENTS.md` §6.5 — enriquecer el export de IOCs *(quick win)*

`export_iocs` corre **antes** de Stage 2.7, así que el CSV/JSON de IOCs sale sin los veredictos de
reputación. Reordenar (o re-exportar) para incluir `EnrichmentContext.export_rows()`.

Con F-C encima esto vale más: el export pasaría a llevar también el veredicto del honeypot.

### G-5 · `IMPROVEMENTS.md` §6.1 — abstracción de proveedores LLM

`_llm_chat` hace dispatch por `if provider ==` y la rama de streaming de Ollama está **duplicada**.
Independiente del rework; se hace si se vuelve a tocar `analyzer.py`.

### G-6 · `IMPROVEMENTS.md` §6.2 — reporter con plantillas

CSS/HTML como strings de Python y un parser de Markdown por regex. Independiente del rework.

### G-7 · Bugs menores conocidos

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
- **F-A:** `tools/pull_honeypot.sh` tuvo la IP pública de casa en claro desde el commit `8a53bad`
  en un repo público. Se redactó en los ficheros, pero **sigue en el historial de git**. Decidir si
  vale reescribir la historia o dejarlo (la IP es dinámica y ya cambió).

## As-built

*(un bloque por ítem cerrado, con su verificación)*
