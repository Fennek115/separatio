# F-B2 · Ingesta idempotente y backfill

> Estado: **☐ pendiente — sesión 2** · Depende de: **F-B1**
> Diseño: [`../PLAN-REWORK.md`](../PLAN-REWORK.md) §F-B · Índice: [`../REWORK-ESTADO.md`](../REWORK-ESTADO.md)
>
> **Completamente especificada. Ejecutar y documentar.**

## Objetivo

Que el store se llene solo: el colector escribe lo que captura en cada pull, y lo que ya está en
disco desde antes entra por un backfill. A partir de acá Separatio **tiene memoria**.

## ¿Ya está hecho?

```bash
cd ~/Projects/Intel
q() { [ -s data/archivo.db ] && sqlite3 data/archivo.db "$1" || echo "→ sin store"; }

q "select count(*) from ioc"
q "select count(*) from observation"
q "select kind, count(*) from ioc group by kind"
grep -n "store" separatio/honeypot_collector.py || echo "→ el colector todavía no escribe"
ls separatio/store/backfill.py 2>/dev/null || echo "→ sin backfill"
```

## Contexto mínimo

**El invariante:** el colector escribe, el pipeline lee. `honeypot_collector.consolidate()` corre 4
veces al día (00/06/12/18:30 en el CT 113) y es el productor natural del dato; el informe de las
07:00 abre el store en modo lectura. Así una ingesta rota no puede tumbar el informe.

**Los artefactos en disco siguen siendo la fuente de verdad.** El store es una *vista* consultable
de lo que ya está en `by-date/`, `events.jsonl`, `hashes.log` y `attackers.json`. Si el `.db` se
borra, se reconstruye con el backfill. Esto es lo que permite que la escritura al store vaya
envuelta en try/except sin perder nada.

**Tolerancia obligatoria a snapshots viejos.** Hallazgo de F-A, verificado contra el disco:
`by-date/2026-08-08/` **no tiene** `events.jsonl` ni `payloads/`, y no existe `hashes.log` — el
colector los genera desde commits posteriores a esa corrida. El backfill lee lo que haya y no
asume nada.

## Pasos

### 1. `separatio/store/ingest.py` — la función de ingesta

Una sola entrada, para que el colector y el backfill compartan código:

```python
def ingest_run(conn, *, attackers: dict, events: list[dict],
               hashes: list[dict] | None = None) -> dict:
    """Vuelca una corrida del colector al store. Idempotente.

    attackers: el payload completo de attackers.json (con su clave `hygiene`).
    events:    las filas de events.jsonl.
    hashes:    filas de hashes.log, si las hay.

    Devuelve {"iocs_nuevos": n, "observaciones_nuevas": n, "payloads_nuevos": n}
    para que el caller lo loguee."""
```

Qué escribe, en orden:

| De | A | Notas |
|---|---|---|
| `attackers[].ip` | `ioc` (kind `ip`) | Con `klass` y `scanner_name` del campo `class` que dejó F-A. **Las `self` ya no llegan**: el colector las excluye antes |
| `attackers[].hassh[]` | `ioc` (kind `hassh`) | Es lo que hace posible la correlación de F-D. Una fila por fingerprint |
| `events[]` | `observation` | `origin="honeypot"`, con `sensor`/`service`/`action`/`sha256` |
| cada HASSH visto | `observation` | Ligada al HASSH, con la IP en `action` (`from <ip>`) — así el `JOIN` de F-D es directo |
| `hashes[]` / `events[].sha256` | `payload` | `first_seen`/`last_seen`/`times_seen` |

**Idempotencia:** toda la escritura de `observation` pasa por `add_observation()` (F-B1), que hace
`INSERT OR IGNORE` contra `dedup_key`. `upsert_ioc` es un `ON CONFLICT DO UPDATE`. Reingerir la
misma ventana no duplica ni infla `times_seen` de más… salvo por lo de abajo.

> ⚠️ **La trampa de `times_seen`.** `upsert_ioc` incrementa `times_seen` en cada llamada, así que
> reingerir la misma ventana lo infla. La solución especificada: **incrementar `times_seen` sólo
> cuando `add_observation` devolvió `True`** (fila nueva). Es decir, el contador del IOC se deriva
> de las observaciones realmente insertadas, no de las veces que se lo tocó. El test
> `test_reingerir_no_infla_times_seen` fija esto.

**`days_seen`:** se incrementa sólo si `ts[:10] != ioc.last_day`, y se actualiza `last_day`. Lo
consume F-D.

### 2. `separatio/honeypot_collector.py` — cablear la escritura

Al final de `consolidate()`, después de escribir los artefactos en disco:

```python
    # El store es una VISTA de lo que ya está en disco: si falla, se loguea y se
    # sigue. Los artefactos son la fuente de verdad y el backfill puede rehacerlo.
    store_stats = None
    try:
        from separatio.store.db import store as _store
        from separatio.store.ingest import ingest_run
        with _store() as conn:
            if conn is not None:
                store_stats = ingest_run(conn, attackers=payload, events=events,
                                         hashes=None)
    except Exception as e:                       # noqa: BLE001 — nunca romper el pull
        logger.warning(f"[pull] store: no se pudo ingerir ({e})")
```

Y una línea más en la salida de `main()`, al lado de la de higiene:

```
[pull]   store: 3 IOCs nuevos, 47 observaciones nuevas, 1 payload nuevo
```

`sqlite3` es stdlib, así que el colector sigue corriendo con el `python3` del sistema y sin venv —
la restricción que F-A dejó fijada.

### 3. `separatio/store/backfill.py` — lo que ya está en disco

```bash
python3 -m separatio.store.backfill                 # todo data/honeypot/by-date/*/
python3 -m separatio.store.backfill --since 2026-08-01
python3 -m separatio.store.backfill --dry-run       # cuenta sin escribir
```

Recorre `data/honeypot/by-date/*/` en orden de fecha y por cada carpeta:

- lee `attackers.json` (**siempre existe**),
- lee `events.jsonl` **si existe** (no está en el snapshot del 2026-08-08),
- lee `payloads/*.bin` **si existen** para poblar `payload`,
- y al final el `hashes.log` de la raíz si está.

Corre `prune_observations(conn, config.STORE_RETENTION_DAYS)` al terminar.

> **Ojo con los snapshots anteriores a F-A**: traen la IP propia como atacante y **sin** el campo
> `class`. El backfill tiene que aplicar `hygiene.build_classifier()` a los IOCs que no traigan
> clase, para no envenenar el store con lo que F-A ya sacó del pipeline. Es el caso del snapshot
> del 2026-08-08, que es literalmente el laptop del usuario.

### 4. `tests/test_store_ingest.py`

| Test | Qué fija |
|---|---|
| `test_ingesta_crea_iocs_y_observaciones` | Cuentas básicas sobre un `attackers`+`events` sintético |
| `test_reingerir_la_misma_ventana_no_duplica` | **El criterio de hecho**: dos `ingest_run` ⇒ mismo `count(*)` en `observation` |
| `test_reingerir_no_infla_times_seen` | La trampa de arriba |
| `test_days_seen_sube_al_dia_siguiente` | Dos ventanas de días distintos ⇒ `days_seen == 2` |
| `test_hassh_entra_como_ioc_propio` | `select count(*) from ioc where kind='hassh'` |
| `test_hassh_se_liga_a_sus_ips` | El `JOIN` que va a usar F-D devuelve las IPs |
| `test_la_clase_de_higiene_persiste` | `klass='scanner'`, `scanner_name='censys'` |
| `test_backfill_tolera_snapshot_sin_events` | Carpeta con sólo `attackers.json` ⇒ no explota |
| `test_backfill_clasifica_snapshots_viejos` | Un snapshot sin `class` con la IP propia ⇒ no entra al store |
| `test_backfill_es_idempotente` | Correrlo dos veces deja las mismas filas |
| `test_el_pull_sigue_funcionando_sin_store` | `STORE_ENABLED=0` ⇒ `consolidate` produce los mismos artefactos |

El último es el que protege la producción: el colector tiene que seguir funcionando igual con el
store apagado o roto.

## Criterio de hecho

```bash
# 1. Ingerir dos veces la misma ventana deja el mismo número de filas
NO_PULL=1 OUT_DIR=<tmp> RAW_DIR=<raw> ./tools/pull_honeypot.sh 720
sqlite3 data/archivo.db "select count(*) from observation"     # → N
NO_PULL=1 OUT_DIR=<tmp> RAW_DIR=<raw> ./tools/pull_honeypot.sh 720
sqlite3 data/archivo.db "select count(*) from observation"     # → N  (idéntico)

# 2. El backfill de lo que ya hay en disco corre y no duplica
python3 -m separatio.store.backfill
python3 -m separatio.store.backfill      # segunda pasada: mismas cuentas

# 3. El pipeline no se enteró
venv/bin/separatio --dry-run --limit 5
venv/bin/pytest tests/ -q
```

## As-built

*(vacío hasta el cierre — pegar la salida literal, incluidos los dos `count(*)` iguales)*

## Pendientes que deja

*(a completar. Previsible: desplegar al CT 113 con `git pull`; el store se crea solo en el primer
pull. Y decidir si `data/archivo.db` entra al backup del CT — hoy el 113 no está en los jobs)*
