-- schema.sql — el archivo de inteligencia (F-B1 del rework).
--
-- SQLite embebido, no Yeti ni MISP: el CT 113 tiene 512 MiB de RAM (ArangoDB no
-- entra), MISP resuelve un problema de compartición que acá no existe, y sqlite3
-- es biblioteca estándar — cero dependencias nuevas, transaccional en WAL y
-- consultable a mano, que es justamente el objetivo declarado.
--
-- Invariante del rework: el COLECTOR escribe (F-B2) y el PIPELINE sólo lee
-- (salvo el cache de `enrichment`, que escribe F-C).
--
-- Todo el DDL es idempotente (IF NOT EXISTS): `migrate()` lo puede correr las
-- veces que haga falta. La versión vive en `meta.schema_version`.

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

-- Corpus de payloads, content-addressed. Refleja payloads/ en disco.
-- Va antes que `observation` porque ésta lo referencia por clave foránea.
CREATE TABLE IF NOT EXISTS payload (
  sha256     TEXT PRIMARY KEY,
  size       INTEGER,
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  times_seen INTEGER NOT NULL DEFAULT 1,
  family     TEXT,               -- de MalwareBazaar, si se conoce
  yara_hits  TEXT                -- CSV de reglas que matchearon (F-F)
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

-- Metadatos del esquema (versionado de migraciones).
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

-- Índices: cada uno responde a una consulta concreta de las fases siguientes.
CREATE INDEX IF NOT EXISTS idx_obs_ioc      ON observation(ioc);
CREATE INDEX IF NOT EXISTS idx_obs_ts       ON observation(ts);        -- poda por retención
CREATE INDEX IF NOT EXISTS idx_enr_budget   ON enrichment(source, fetched_at);  -- cuota (F-C)
CREATE INDEX IF NOT EXISTS idx_ioc_days     ON ioc(days_seen);         -- reincidencia (F-D)
CREATE INDEX IF NOT EXISTS idx_ioc_kind     ON ioc(kind);
