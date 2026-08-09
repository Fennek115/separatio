# F-B1 · El store: esquema y capa de acceso

> Estado: **☐ pendiente — sesión 1 del rework tras F-A** · Depende de: F-A ☑
> Diseño: [`../PLAN-REWORK.md`](../PLAN-REWORK.md) §3 y §4 · Índice: [`../REWORK-ESTADO.md`](../REWORK-ESTADO.md)
>
> **Esta fase está completamente especificada. No hay que diseñar nada: ejecutar y documentar.**

## Objetivo

Dejar el fichero SQLite creado, migrable y con una capa de acceso testeada — **sin que nada del
pipeline cambie de conducta todavía**. Es la fase de menor riesgo del rework y la que habilita
todas las demás.

## ¿Ya está hecho?

```bash
cd ~/Projects/Intel
# ⚠️ `sqlite3 <fichero>` CREA el fichero aunque sólo se lea: hay que guardar la consulta,
#    si no el propio bloque de verificación deja una base vacía y miente en la corrida
#    siguiente. Este helper lo usan todas las fases.
q() { [ -s data/archivo.db ] && sqlite3 data/archivo.db "$1" || echo "→ sin store"; }

ls separatio/store/ 2>/dev/null || echo "→ no existe el paquete store"
ls -la data/archivo.db 2>/dev/null || echo "→ no existe el fichero de base"
q ".tables"
q "select value from meta where key='schema_version'"
q "pragma journal_mode"                        # esperado: wal
venv/bin/pytest tests/ -q | tail -1            # baseline al cerrar F-A: 73 passed
```

## Contexto mínimo

**La decisión ya está tomada y no se rediscute: SQLite embebido, no Yeti ni MISP.** Motivos en
`PLAN-REWORK.md` §3 — el CT 113 tiene 512 MiB de RAM y 3,2 G libres, ArangoDB (Yeti) no entra,
MISP resuelve un problema de compartición que acá no existe, y SQLite es stdlib (cero dependencias
nuevas), transaccional en WAL y consultable a mano, que es el objetivo declarado.

**Invariante del rework, decidido el 2026-08-09:** el **colector** escribe en el store (F-B2) y el
**pipeline sólo lee**. Esta fase no cablea ninguna de las dos cosas: sólo deja la capa lista.

## Pasos

### 1. `separatio/store/schema.sql` — el DDL, literal

Es el de `PLAN-REWORK.md` §4 con tres cambios que salieron de F-A y de leer el código. Van
comentados en el fichero para que se entienda por qué están.

```sql
-- Identidad: una fila por indicador, para siempre.
CREATE TABLE IF NOT EXISTS ioc (
  value        TEXT PRIMARY KEY,      -- normalizado (lowercase, defanged)
  kind         TEXT NOT NULL,         -- ip | domain | url | hash | hassh
  first_seen   TEXT NOT NULL,
  last_seen    TEXT NOT NULL,
  times_seen   INTEGER NOT NULL DEFAULT 0,
  days_seen    INTEGER NOT NULL DEFAULT 0,  -- nº de días DISTINTOS: la métrica de reincidencia
  last_day     TEXT,                  -- YYYY-MM-DD del último día contado (para days_seen)
  klass        TEXT,                  -- self | scanner | unknown  ← de separatio/hygiene.py (F-A)
  scanner_name TEXT                   -- censys | shodan | …       ← idem
);

-- Cada avistamiento. Append-only. Es el log crudo del SIEM.
CREATE TABLE IF NOT EXISTS observation (
  id             INTEGER PRIMARY KEY,
  ioc            TEXT NOT NULL REFERENCES ioc(value),
  ts             TEXT NOT NULL,
  origin         TEXT NOT NULL,       -- honeypot | news | feed
  sensor         TEXT,                -- vm1-cowrie | vm1-web | vm2-services | <feed> | <medio>
  service        TEXT,                -- ssh | web | redis | docker | ...
  action         TEXT,                -- comando/URI/técnica, recortado
  payload_sha256 TEXT REFERENCES payload(sha256),
  dedup_key      TEXT NOT NULL UNIQUE -- idempotencia por INSERT OR IGNORE (ver F-B2)
);

-- El cache de enriquecimiento: el corazón del ahorro de cuota.
CREATE TABLE IF NOT EXISTS enrichment (
  ioc        TEXT NOT NULL,
  source     TEXT NOT NULL,      -- greynoise | abuseipdb | virustotal | otx | ipsum | ...
  verdict    TEXT,               -- etiqueta corta
  detail     TEXT,               -- JSON crudo de la respuesta
  fetched_at TEXT NOT NULL,
  expires_at TEXT,               -- NULL = no expira (p.ej. familia de un hash)
  PRIMARY KEY (ioc, source)
);

-- Corpus de payloads, content-addressed. Refleja payloads/ en disco.
CREATE TABLE IF NOT EXISTS payload (
  sha256     TEXT PRIMARY KEY,
  size       INTEGER,
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  times_seen INTEGER NOT NULL DEFAULT 1,
  family     TEXT,               -- de MalwareBazaar, si se conoce
  yara_hits  TEXT                -- CSV de reglas que matchearon (F-F)
);

-- Metadatos del esquema (versionado de migraciones).
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

-- Índices: cada uno responde a una consulta concreta de las fases siguientes.
CREATE INDEX IF NOT EXISTS idx_obs_ioc      ON observation(ioc);
CREATE INDEX IF NOT EXISTS idx_obs_ts       ON observation(ts);        -- poda por retención
CREATE INDEX IF NOT EXISTS idx_enr_budget   ON enrichment(source, fetched_at);  -- cuota (F-C)
CREATE INDEX IF NOT EXISTS idx_ioc_days     ON ioc(days_seen);         -- reincidencia (F-D)
CREATE INDEX IF NOT EXISTS idx_ioc_kind     ON ioc(kind);
```

**Los tres cambios respecto del plan original, y por qué:**

| Cambio | Motivo |
|---|---|
| `ioc.klass` + `ioc.scanner_name` | La clasificación de F-A tiene que **sobrevivir al store**. Es lo que le permite a F-C descartar escáneres sin gastar una consulta |
| `ioc.last_day` | `days_seen` cuenta días *distintos*: sin recordar el último día contado no se puede incrementar bien. F-D depende de esto |
| `observation.dedup_key UNIQUE` | La idempotencia se resuelve con `INSERT OR IGNORE` contra un índice único, no con un `SELECT` previo por fila. El pull corre cada 6 h |

### 2. `separatio/store/db.py` — apertura y migraciones

```python
SCHEMA_VERSION = 1

def open_store(path: str | Path | None = None,
               *, read_only: bool = False) -> sqlite3.Connection | None:
    """Abre el store y lo migra. Devuelve None si no se puede — nunca levanta."""

def migrate(conn: sqlite3.Connection) -> int:
    """Aplica el DDL y actualiza meta.schema_version. Idempotente. Devuelve la versión."""

@contextmanager
def store(path=None, *, read_only=False):
    """Context manager: cede la conexión (o None) y commitea/cierra al salir."""
```

PRAGMAs que `open_store` tiene que aplicar, en este orden:

```python
conn.execute("PRAGMA journal_mode=WAL")     # el pull (cada 6h) y el pipeline (07:00) se solapan
conn.execute("PRAGMA foreign_keys=ON")
conn.execute("PRAGMA busy_timeout=5000")    # 5s antes de dar 'database is locked'
conn.execute("PRAGMA synchronous=NORMAL")   # suficiente con WAL; menos fsync en el disco del CT
conn.row_factory = sqlite3.Row
```

> **La regla que esta fase no puede violar:** si el fichero no se puede abrir, `open_store` **loguea
> y devuelve `None`**. Nadie aborta, nadie propaga la excepción. Es el mismo patrón tolerante a
> fallos que ya usan `pipeline.stage27_enrich` (`separatio/pipeline.py:494`) y
> `history.load_history` (`separatio/history.py:88`). El informe diario está en producción.

`read_only=True` abre con URI `file:…?mode=ro` — es como lo va a abrir el pipeline a partir de F-C.

### 3. `separatio/store/models.py` — acceso, sin ORM

Consultas parametrizadas y nada más: es más simple y no agrega dependencias.

```python
def upsert_ioc(conn, value: str, kind: str, ts: str,
               klass: str | None = None, scanner_name: str | None = None) -> None:
    """INSERT ... ON CONFLICT(value) DO UPDATE: last_seen, times_seen+1, y days_seen+1
    sólo si la fecha (ts[:10]) difiere de last_day."""

def add_observation(conn, ioc: str, ts: str, origin: str, *, sensor=None,
                    service=None, action=None, payload_sha256=None) -> bool:
    """INSERT OR IGNORE con dedup_key. Devuelve True si la fila era nueva."""

def get_cached(conn, ioc: str, source: str, *, now: str | None = None) -> dict | None:
    """Veredicto cacheado y NO vencido, o None. expires_at NULL = no expira."""

def put_cached(conn, ioc: str, source: str, verdict: str,
               detail: str = "", ttl_days: int | None = None) -> None:
    """Upsert del cache. ttl_days None ⇒ expires_at NULL."""

def quota_used(conn, source: str, *, window: str = "day", now=None) -> int:
    """Consultas hechas a `source` en la ventana ('day' | 'week'). Es el presupuesto de F-C,
    contado contra el store para que sobreviva a reinicios."""

def upsert_payload(conn, sha256: str, size: int, ts: str,
                   family: str | None = None) -> None: ...

def prune_observations(conn, keep_days: int) -> int:
    """Borra observaciones más viejas que keep_days. Devuelve cuántas borró."""

def ioc_row(conn, value: str) -> dict | None: ...
def recent_ips(conn, hours: int, *, origin="honeypot") -> list[dict]:
    """Las IPs vistas en la ventana, con klass/days_seen/times_seen. Entrada de F-C."""
```

`dedup_key` se calcula **dentro de `add_observation`**, no lo pasa el caller:
`sha256(f"{ts}|{ioc}|{sensor}|{action}".encode()).hexdigest()[:32]`.

### 4. `separatio/config.py` — la configuración nueva

```python
STORE_ENABLED         = _env_bool("STORE_ENABLED", True)
STORE_PATH            = str(REPO_ROOT / "data" / "archivo.db")   # REPO_ROOT lo dejó F-A
STORE_RETENTION_DAYS  = 180     # observation se poda; ioc/payload/enrichment son permanentes
```

`_env_bool` ya existe en `config.py` (lo agregó F-A). `data/` está gitignored, así que el `.db` no
se commitea.

### 5. `tests/test_store.py` — todos en `:memory:`

Nombres exactos a escribir:

| Test | Qué fija |
|---|---|
| `test_migrate_crea_las_cinco_tablas` | `.tables` tras migrar |
| `test_migrate_es_idempotente` | Correr `migrate` dos veces no cambia `schema_version` ni el esquema |
| `test_open_store_devuelve_none_si_no_puede_abrir` | Ruta imposible (p.ej. un directorio) → `None`, sin excepción |
| `test_wal_activado` | `pragma journal_mode` == `wal` (sobre fichero, no `:memory:`) |
| `test_upsert_ioc_crea_y_actualiza` | `times_seen` sube, `last_seen` avanza |
| `test_days_seen_cuenta_dias_distintos` | Dos observaciones el mismo día ⇒ `days_seen == 1`; al día siguiente ⇒ 2 |
| `test_upsert_ioc_guarda_la_clase_de_higiene` | `klass`/`scanner_name` persisten |
| `test_add_observation_es_idempotente` | Misma `(ts, ioc, sensor, action)` dos veces ⇒ una fila, segundo `add` devuelve `False` |
| `test_add_observation_distingue_acciones` | Cambiar `action` sí crea fila nueva |
| `test_cache_devuelve_none_si_vencio` | `ttl_days=0` ⇒ `get_cached` es `None` |
| `test_cache_sin_ttl_no_vence` | `ttl_days=None` ⇒ siempre devuelve |
| `test_quota_used_cuenta_por_ventana` | Una entrada de hace 3 días cuenta en `week` y no en `day` |
| `test_prune_observations_respeta_retencion` | Borra lo viejo, deja lo nuevo |
| `test_recent_ips_filtra_por_ventana_y_origen` | Sólo honeypot y sólo dentro de las horas pedidas |

`:memory:` es rápido y no toca disco; sólo `test_wal_activado` usa `tmp_path`.

## Criterio de hecho

Las cuatro cosas, verificadas con comando:

1. `venv/bin/pytest tests/ -q` → **73 previos + los nuevos**, todos verdes.
2. `sqlite3 data/archivo.db ".tables"` muestra las 5 tablas y
   `pragma journal_mode` devuelve `wal`.
3. Correr la migración dos veces deja `schema_version` en 1 y el esquema idéntico.
4. `venv/bin/separatio --dry-run --limit 5` produce lo mismo que antes — **el pipeline no cambió de
   conducta**.

## As-built

*(vacío hasta el cierre — salida literal de los cuatro comandos de arriba)*

## Pendientes que deja

*(a completar: típicamente el despliegue al CT 113, que en esta fase es sólo `git pull` — no hace
falta variable nueva porque `STORE_PATH` sale de `REPO_ROOT`)*
