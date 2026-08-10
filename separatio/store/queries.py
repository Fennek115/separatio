"""
queries.py — reincidencia (F-D del rework).

Con el store poblado esto es casi gratis: `days_seen`/`times_seen` ya los
mantiene la ingesta de F-B2 (`models.upsert_ioc`) y el HASSH ya entra como IOC
propio (`ingest.py`, sección HASSH). Esta fase es sobre todo consultas y
redacción: convertir filas en frases que el LLM pueda citar.

`ip_recurrence` cuenta días DISTINTOS **dentro de la ventana** consultando
`observation` (no el `days_seen` denormalizado de `ioc`, que es de la vida
entera del indicador) — es la diferencia entre "volvió 5 de los últimos 14
días" y "volvió 5 veces alguna vez".
"""

from __future__ import annotations

import sqlite3

from . import models


def ip_recurrence(conn: sqlite3.Connection, ip: str, window_days: int = 14,
                  *, now: str | None = None) -> dict | None:
    """`{'days_seen': 5, 'window_days': 14, 'first_seen': '...', 'times_seen': 41}`
    o None si la IP nunca se vio. `days_seen` cuenta días distintos dentro de
    `window_days`, no la vida entera del indicador."""
    cutoff = models._shift(now or models.now_iso(), -abs(window_days))
    row = conn.execute(
        """
        SELECT i.value, i.first_seen, i.times_seen,
               COUNT(DISTINCT substr(o.ts, 1, 10)) AS days_in_window
          FROM ioc i JOIN observation o ON o.ioc = i.value
         WHERE i.value = ?
           AND o.ts >= ?
         GROUP BY i.value
        """,
        (ip, cutoff),
    ).fetchone()
    if row is None:
        return None
    return {
        "days_seen": row["days_in_window"],
        "window_days": window_days,
        "first_seen": row["first_seen"],
        "times_seen": row["times_seen"],
    }


def payload_history(conn: sqlite3.Connection, sha256: str) -> dict | None:
    """`{'first_seen': '2026-07-02', 'times_seen': 4, 'family': 'Mirai'}` o None."""
    row = conn.execute(
        "SELECT sha256, first_seen, last_seen, times_seen, family, yara_hits "
        "FROM payload WHERE sha256 = ?",
        (sha256,),
    ).fetchone()
    return dict(row) if row else None


def hassh_fanout(conn: sqlite3.Connection, min_ips: int = 3, window_days: int = 30,
                 *, now: str | None = None) -> list[dict]:
    """`[{'hassh': 'xx', 'ips': ['1.2.3.4', ...], 'n_ips': 12, 'days_seen': 6}]`.

    Un mismo HASSH desde muchas IPs es la huella de una botnet — ninguna
    blocklist lo dice, porque la IP es justo lo que el atacante rota. El
    `action` de las observaciones de HASSH es `"from <ip>"` (`ingest.py`)."""
    cutoff = models._shift(now or models.now_iso(), -abs(window_days))
    rows = conn.execute(
        """
        SELECT h.value AS hassh, h.days_seen,
               COUNT(DISTINCT o.action) AS n_ips,
               GROUP_CONCAT(DISTINCT o.action) AS ips
          FROM ioc h JOIN observation o ON o.ioc = h.value
         WHERE h.kind = 'hassh'
           AND o.ts >= ?
         GROUP BY h.value
        HAVING n_ips >= ?
         ORDER BY n_ips DESC
        """,
        (cutoff, min_ips),
    ).fetchall()
    out = []
    for r in rows:
        ips = sorted({raw[5:] for raw in (r["ips"] or "").split(",") if raw.startswith("from ")})
        out.append({"hassh": r["hassh"], "ips": ips, "n_ips": r["n_ips"],
                    "days_seen": r["days_seen"]})
    return out


def top_recurrent(conn: sqlite3.Connection, limit: int = 10, window_days: int = 14,
                  *, now: str | None = None) -> list[dict]:
    """Las IPs más reincidentes de la ventana, ordenadas por `days_seen`
    descendente. Alimenta la nota de contexto del enricher."""
    cutoff = models._shift(now or models.now_iso(), -abs(window_days))
    rows = conn.execute(
        """
        SELECT i.value, i.times_seen,
               COUNT(DISTINCT substr(o.ts, 1, 10)) AS days_in_window
          FROM ioc i JOIN observation o ON o.ioc = i.value
         WHERE i.kind = 'ip'
           AND o.ts >= ?
         GROUP BY i.value
        ORDER BY days_in_window DESC, i.times_seen DESC
        LIMIT ?
        """,
        (cutoff, limit),
    ).fetchall()
    return [{"value": r["value"], "days_seen": r["days_in_window"],
             "times_seen": r["times_seen"], "window_days": window_days} for r in rows]
