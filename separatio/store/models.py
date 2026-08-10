"""
models.py — acceso al store, sin ORM (F-B1 del rework).

Consultas parametrizadas y nada más: es más simple, no agrega dependencias
(invariante 5) y deja el SQL a la vista, que es lo que se va a querer leer
cuando algo no cuadre.

Ninguna de estas funciones abre ni cierra la conexión: la reciben. El ciclo de
vida lo maneja `db.store()`.

Formato de tiempo: **ISO-8601 UTC** (`2026-08-09T07:00:00+00:00`). Las ventanas
(`quota_used`, `prune_observations`, `recent_ips`) comparan cadenas, así que un
formato mezclado —`…Z` contra `…+00:00`— rompería las comparaciones en silencio:
`_iso()` normaliza todo lo que entra.
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# Ventanas soportadas por `quota_used`, en días.
QUOTA_WINDOWS: dict[str, int] = {"day": 1, "week": 7}


# ─────────────────────────────────────────────
# TIEMPO
# ─────────────────────────────────────────────

def now_iso() -> str:
    """Ahora, en el formato canónico del store."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _iso(value) -> str:
    """Normaliza a ISO-8601 UTC. Tolera datetime, 'Z' final y naive.

    Si no se puede parsear se devuelve la cadena tal cual: perder el dato es
    peor que guardarlo con un formato raro, y queda visible al consultar."""
    if value is None:
        return now_iso()
    if isinstance(value, datetime):
        d = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc).isoformat(timespec="seconds")
    text = str(value).strip()
    try:
        d = datetime.fromisoformat(text.replace("Z", "+00:00"))
        d = d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc).isoformat(timespec="seconds")
    except ValueError:
        return text


def _shift(ts: str, days: float) -> str:
    """`ts` desplazado en días, en el formato canónico."""
    try:
        d = datetime.fromisoformat(_iso(ts))
    except ValueError:                                   # pragma: no cover
        d = datetime.now(timezone.utc)
    return (d + timedelta(days=days)).isoformat(timespec="seconds")


# ─────────────────────────────────────────────
# IOCs
# ─────────────────────────────────────────────

def upsert_ioc(conn: sqlite3.Connection, value: str, kind: str, ts: str,
               klass: str | None = None, scanner_name: str | None = None, *,
               count: bool = True) -> None:
    """Crea o actualiza el indicador: `last_seen`, `times_seen`+1 y `days_seen`+1
    sólo si el día (`ts[:10]`) difiere de `last_day`.

    `days_seen` es la métrica de reincidencia de F-D y es un contador
    denormalizado: es exacto si los avistamientos llegan en orden cronológico
    —que es como los produce el colector— y puede sobrecontar si un backfill los
    mete alternando días. El backfill de F-B2 lo recalcula desde `observation`.

    `klass`/`scanner_name` sólo pisan lo guardado cuando vienen informados: una
    corrida sin PTR no borra la clasificación que dejó otra que sí lo tenía.

    `count=False` (F-B2) asegura la fila —necesaria como FK antes de insertar una
    `observation`— sin sumarla a `times_seen`/`days_seen`. El contador del IOC se
    deriva de las observaciones realmente insertadas (`add_observation` ⇒ True),
    no de las veces que se lo tocó: es la trampa que anotó el cierre de F-B1.
    """
    ts = _iso(ts)
    day = ts[:10]
    bump = 1 if count else 0
    last_day_new = day if count else None
    conn.execute(
        """
        INSERT INTO ioc (value, kind, first_seen, last_seen, times_seen,
                         days_seen, last_day, klass, scanner_name)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(value) DO UPDATE SET
          first_seen   = MIN(ioc.first_seen, excluded.first_seen),
          last_seen    = MAX(ioc.last_seen,  excluded.last_seen),
          times_seen   = ioc.times_seen + ?,
          days_seen    = ioc.days_seen + (CASE WHEN ? = 0 THEN 0
                                            WHEN ioc.last_day IS NULL
                                                 OR ioc.last_day <> ?
                                            THEN 1 ELSE 0 END),
          last_day     = CASE WHEN ? = 0 THEN ioc.last_day
                               ELSE MAX(COALESCE(ioc.last_day, ''), ?) END,
          klass        = COALESCE(excluded.klass, ioc.klass),
          scanner_name = COALESCE(excluded.scanner_name, ioc.scanner_name)
        """,
        (value, kind, ts, ts, bump, bump, last_day_new, klass, scanner_name,
         bump, bump, day, bump, day),
    )


def ioc_row(conn: sqlite3.Connection, value: str) -> dict | None:
    """La fila del indicador, o None si nunca se vio."""
    row = conn.execute("SELECT * FROM ioc WHERE value = ?", (value,)).fetchone()
    return dict(row) if row else None


# ─────────────────────────────────────────────
# OBSERVACIONES
# ─────────────────────────────────────────────

def dedup_key(ts: str, ioc: str, sensor, action) -> str:
    """La clave de idempotencia. La calcula `add_observation`, no el caller:
    si la calculara cada llamador, dos de ellos la calcularían distinto."""
    raw = f"{_iso(ts)}|{ioc}|{sensor or ''}|{action or ''}"
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:32]


def add_observation(conn: sqlite3.Connection, ioc: str, ts: str, origin: str, *,
                    sensor: str | None = None, service: str | None = None,
                    action: str | None = None,
                    payload_sha256: str | None = None) -> bool:
    """`INSERT OR IGNORE` contra el índice único de `dedup_key`. True si era nueva.

    La idempotencia se resuelve con el índice y no con un `SELECT` previo por
    fila: el pull corre cada 6 h y reprocesa la misma ventana.

    Devuelve False —sin levantar— si el `ioc` no existe todavía en la tabla
    `ioc` (violación de FK): el caller tiene que haber hecho `upsert_ioc` antes,
    pero una fila mal formada no puede tumbar la corrida del colector.
    """
    ts = _iso(ts)
    try:
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO observation
              (ioc, ts, origin, sensor, service, action, payload_sha256, dedup_key)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (ioc, ts, origin, sensor, service, action, payload_sha256,
             dedup_key(ts, ioc, sensor, action)),
        )
    except sqlite3.IntegrityError as e:
        # `OR IGNORE` no cubre las claves foráneas: eso sí llega acá.
        logger.warning(f"    store: observación descartada para {ioc} ({e})")
        return False
    return cur.rowcount > 0


def prune_observations(conn: sqlite3.Connection, keep_days: int, *,
                       now: str | None = None) -> int:
    """Borra observaciones más viejas que `keep_days`. Devuelve cuántas borró.

    Sólo se poda `observation`: `ioc`, `payload` y `enrichment` son permanentes
    —son la memoria— y ocupan órdenes de magnitud menos."""
    cutoff = _shift(now or now_iso(), -abs(keep_days))
    cur = conn.execute("DELETE FROM observation WHERE ts < ?", (cutoff,))
    return cur.rowcount


def recent_ips(conn: sqlite3.Connection, hours: int, *,
               origin: str = "honeypot", now: str | None = None) -> list[dict]:
    """Las IPs vistas en la ventana, con `klass`/`days_seen`/`times_seen`.

    Es la entrada de F-C: de acá sale a quién vale la pena gastarle una consulta
    de GreyNoise (y a quién no, porque ya se sabe que es un escáner). `sensors`
    y `has_payload` (F-C) son el 2º y 3er criterio de prioridad del residuo:
    envió payload o lo vio más de un sensor pesa más que sólo `times_seen`."""
    cutoff = _shift(now or now_iso(), -abs(hours) / 24.0)
    rows = conn.execute(
        """
        SELECT i.value, i.kind, i.klass, i.scanner_name, i.days_seen,
               i.times_seen, i.first_seen, i.last_seen,
               COUNT(*)                          AS hits,
               MAX(o.ts)                         AS last_ts,
               COUNT(DISTINCT o.sensor)           AS sensors,
               MAX(o.payload_sha256 IS NOT NULL)  AS has_payload
        FROM observation o
        JOIN ioc i ON i.value = o.ioc
        WHERE o.origin = ? AND o.ts >= ? AND i.kind = 'ip'
        GROUP BY i.value
        ORDER BY last_ts DESC
        """,
        (origin, cutoff),
    ).fetchall()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────
# CACHE DE ENRIQUECIMIENTO
# ─────────────────────────────────────────────

def get_cached(conn: sqlite3.Connection, ioc: str, source: str, *,
               now: str | None = None) -> dict | None:
    """Veredicto cacheado y **no vencido**, o None. `expires_at` NULL = no expira."""
    row = conn.execute(
        """
        SELECT * FROM enrichment
        WHERE ioc = ? AND source = ?
          AND (expires_at IS NULL OR expires_at > ?)
        """,
        (ioc, source, _iso(now or now_iso())),
    ).fetchone()
    return dict(row) if row else None


def put_cached(conn: sqlite3.Connection, ioc: str, source: str, verdict: str,
               detail: str = "", ttl_days: int | None = None, *,
               now: str | None = None) -> None:
    """Upsert del cache. `ttl_days=None` ⇒ `expires_at` NULL (no expira).

    Ojo con la diferencia: `ttl_days=None` es *nunca vence* (la familia de un
    hash no cambia); `ttl_days=0` es *ya venció*."""
    fetched = _iso(now or now_iso())
    expires = None if ttl_days is None else _shift(fetched, ttl_days)
    conn.execute(
        """
        INSERT INTO enrichment (ioc, source, verdict, detail, fetched_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(ioc, source) DO UPDATE SET
          verdict    = excluded.verdict,
          detail     = excluded.detail,
          fetched_at = excluded.fetched_at,
          expires_at = excluded.expires_at
        """,
        (ioc, source, verdict, detail, fetched, expires),
    )


def quota_used(conn: sqlite3.Connection, source: str, *, window: str = "day",
               now: str | None = None) -> int:
    """Consultas hechas a `source` en la ventana (`'day'` | `'week'`).

    Es el presupuesto de F-C —GreyNoise da 25 consultas por semana— contado
    contra el store y no en memoria, para que sobreviva a reinicios y a que el
    pipeline y el colector sean procesos distintos."""
    days = QUOTA_WINDOWS.get(window)
    if days is None:
        raise ValueError(f"ventana desconocida: {window!r} (esperado {sorted(QUOTA_WINDOWS)})")
    cutoff = _shift(now or now_iso(), -days)
    row = conn.execute(
        "SELECT COUNT(*) FROM enrichment WHERE source = ? AND fetched_at >= ?",
        (source, cutoff),
    ).fetchone()
    return int(row[0])


# ─────────────────────────────────────────────
# PAYLOADS
# ─────────────────────────────────────────────

def upsert_payload(conn: sqlite3.Connection, sha256: str, size: int, ts: str,
                   family: str | None = None) -> None:
    """Crea o actualiza el payload del corpus. Content-addressed: la clave es el
    hash, así que reencontrar el mismo binario sube `times_seen` y nada más."""
    ts = _iso(ts)
    conn.execute(
        """
        INSERT INTO payload (sha256, size, first_seen, last_seen, times_seen, family)
        VALUES (?, ?, ?, ?, 1, ?)
        ON CONFLICT(sha256) DO UPDATE SET
          size       = COALESCE(excluded.size, payload.size),
          first_seen = MIN(payload.first_seen, excluded.first_seen),
          last_seen  = MAX(payload.last_seen,  excluded.last_seen),
          times_seen = payload.times_seen + 1,
          family     = COALESCE(excluded.family, payload.family)
        """,
        (sha256, size, ts, ts, family),
    )
