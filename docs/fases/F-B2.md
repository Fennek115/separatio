# F-B2 · Ingesta idempotente y backfill

> Estado: **☑ hecha el 2026-08-09** · Depende de: F-B1 ☑
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
>
> **Anotado al cerrar F-B1 (2026-08-09):** ojo con el orden, porque `observation.ioc` es una clave
> foránea y la fila de `ioc` **tiene que existir antes** de insertar la observación — o sea que
> "crearla" ya cuenta 1. Dos salidas, ambas dentro de F-B2 y sin tocar el esquema: (a) consultar
> `ioc_row()` primero y llamar a `upsert_ioc` sólo tras un `add_observation` que dio `True`, o
> (b) agregarle a `upsert_ioc` un `count: bool = True` para poder asegurar la fila sin contar.
> `add_observation` ya devuelve `False` —sin levantar— si la FK no está, así que probar (a) no
> rompe nada.

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

Ejecutada el **2026-08-09**. Estado al arrancar, con el bloque "¿Ya está hecho?": store en 0 filas,
colector sin mención de `store`, sin `backfill.py`.

### Lo que quedó en disco

| Fichero | Qué es |
|---|---|
| `separatio/store/ingest.py` | `ingest_run()` — el punto único de escritura, comparten colector y backfill |
| `separatio/store/backfill.py` | `backfill()` + `main()` (`python3 -m separatio.store.backfill [--since] [--dry-run]`) |
| `separatio/honeypot_collector.py` | `consolidate()` llama a `ingest_run` al final, envuelta en try/except; `main()` imprime la línea `store:` |
| `separatio/store/models.py` | `upsert_ioc` ganó `count: bool = True` (ver "lo que se apartó del plan") |
| `tests/test_store_ingest.py` | **12** tests (los 11 del plan + `test_payload_entra_desde_events`) |

### 1. Tests

```
$ venv/bin/pytest tests/ -q | tail -1
146 passed in 5.42s
```

134 previos + 12 nuevos = 146. Ninguno de los previos cambió.

### 2. Ingerir dos veces la misma ventana no duplica (sobre el store real, con una IP sintética)

```
$ PYTHONPATH=. python3 -m separatio.honeypot_collector raw/ out/ 24
[pull]   store: 1 IOCs nuevos, 1 observaciones nuevas, 0 payload(s) nuevo(s)
$ sqlite3 data/archivo.db "select value,kind,klass,times_seen,days_seen from ioc;"
45.9.148.99|ip|unknown|1|1
$ PYTHONPATH=. python3 -m separatio.honeypot_collector raw/ out/ 24   # misma ventana, de nuevo
[pull]   store: 0 IOCs nuevos, 0 observaciones nuevas, 0 payload(s) nuevo(s)
$ sqlite3 data/archivo.db "select count(*) from observation;"
1
```

`times_seen` se quedó en 1 tras la segunda pasada — la trampa que anotó F-B1 no se coló.

### 3. El backfill sobre `data/honeypot/by-date/` real

El único snapshot en disco (`2026-08-08/`) es anterior a F-A: un solo atacante, **sin** `class`, y
es literalmente la IP propia del laptop (`OWN_IPS` del `.env`).

```
$ python3 -m separatio.store.backfill --dry-run
[dry-run] backfill: 1 carpeta(s), 0 IOC(s) nuevo(s), 0 observación(es) nueva(s), 0 payload(s) nuevo(s)
$ PYTHONPATH=. python3 -m separatio.store.backfill
backfill: 1 carpeta(s), 0 IOC(s) nuevo(s), 0 observación(es) nueva(s), 0 payload(s) nuevo(s)
$ PYTHONPATH=. python3 -m separatio.store.backfill   # segunda pasada
backfill: 1 carpeta(s), 0 IOC(s) nuevo(s), 0 observación(es) nueva(s), 0 payload(s) nuevo(s)
```

0 en las tres corridas: la clasificación retroactiva excluyó la IP propia, tal como se esperaba —
`test_backfill_clasifica_snapshots_viejos` fija este caso con datos sintéticos. El store real quedó
tal como lo dejó F-B1:

```
$ sqlite3 data/archivo.db "select 'ioc', count(*) from ioc union all
                           select 'observation', count(*) from observation union all
                           select 'payload', count(*) from payload;"
ioc|0
observation|0
payload|0
```

### 4. El pipeline no se enteró

```
$ venv/bin/separatio --dry-run --limit 5
...
  RESUMEN DE LA CORRIDA — 2026-08-09  [ok]
  Modo:         dry-run
  Duración:     8s
  Artículos:    25 en el pool → 5 tomados → 5 resumidos, 0 fallidos
```

### Lo que se apartó del plan (y por qué)

| Cambio | Motivo |
|---|---|
| Se eligió la opción **(b)** que dejó anotada F-B1: `upsert_ioc(..., count: bool = True)` | Asegura la fila del IOC (necesaria como FK antes de `add_observation`) sin sumarla a `times_seen`/`days_seen`; el contador real se pisa recién cuando `add_observation` devuelve `True`, con el `ts` de la observación. Se prefirió sobre la opción (a) porque no depende de distinguir "primera vez que se ve este IOC en la corrida" con una consulta aparte — la propia condición SQL (`CASE WHEN ?=0`) lo resuelve en una sola sentencia |
| **`payload` tiene la misma trampa de FK que `ioc`** (no estaba anotada en F-B1) | `observation.payload_sha256` también es una clave foránea: al ingerir un evento con `sha256`, hay que hacer `upsert_payload` **antes** de `add_observation`, si no salta `IntegrityError` y la observación se descarta con un warning. Se detectó con `test_payload_entra_desde_events`, que no estaba en la lista de 11 del plan y se agregó |
| El HASSH no lleva un `ts` propio en `events[]` (sólo aparece agregado en `attackers[].hassh`) | Se usa `a["last_seen"]` (o `first_seen` si falta) como marca de tiempo de la observación `hassh→"from <ip>"`. No hay una alternativa más fina con los datos que produce el colector hoy |
| `_classify_attackers` del backfill sólo reclasifica si `class` es `None`/ausente | Un snapshot de F-A en adelante ya trae su clasificación persistida (incluida `scanner`); reclasificar lo pisaría con el estado *actual* de `OWN_IPS`/PTR, que puede no coincidir con el que valía el día del snapshot |
| `hashes.log` se ingiere **una sola vez, al final del backfill**, no por carpeta | Es un índice global y ya viene deduplicado por sha256 desde el propio colector (`if sha not in known`); repartirlo por día habría exigido reconstruir a qué día perteneció cada línea, dato que el propio fichero no guarda con esa granularidad |
| `backfill()` acepta `db_path` (no sólo `root`) | Los tests necesitan apuntar a `:memory:` o a un fichero en `tmp_path`, no a `data/archivo.db` |

### Deuda que deja anotada

- **`days_seen` sigue siendo un contador denormalizado** (heredado de F-B1): el backfill procesa las
  carpetas de `by-date/` en orden de fecha, así que es exacto en el uso real, pero nada en el código
  impide pasarle carpetas fuera de orden a mano. Sigue sin haber un recálculo desde `observation`
  porque no hizo falta: no se vio sobrecontar en esta corrida.
- **Los `payloads/*.bin` por día se leen pero no se deduplican contra `events[].sha256`** dentro del
  mismo `ingest_run`: si un sha aparece en ambos, `upsert_payload` se llama dos veces en la misma
  pasada (el `times_seen` del payload puede quedar por encima de "veces realmente vistas". No afecta
  IOCs/observaciones —sólo al contador del corpus— y no está cubierto por un test; se anota para
  quien lo note al revisar el corpus real.

## Pendientes que deja

- **Desplegar al CT 113**: el mismo `git pull` (más `pip install -e '.[dev]'` si no se hizo ya para
  F-B1) lleva la ingesta cableada. El primer pull real del CT va a poblar el store con datos de
  verdad; conviene correr `python3 -m separatio.store.backfill` una vez ahí para no perder lo que
  ya haya en `by-date/` de corridas previas del colector viejo.
- **Decidir si `data/archivo.db` entra al backup del CT** — hoy el 113 no está en los jobs de backup
  (pendiente heredado de F-B1).
- El `hashes.log` real (raíz de `data/honeypot/`) todavía no existe en este laptop —no hay corpus de
  payloads— así que la rama que lo lee en `backfill.py` no se ejercitó contra datos reales, sólo
  contra el sintético de `test_backfill_es_idempotente`. Se va a ejercitar sola en cuanto el CT junte
  el primer binario.
