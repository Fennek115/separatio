"""
ingest.py — vuelca una corrida del colector al store (F-B2 del rework).

Punto único de entrada para que el colector (en vivo) y el backfill (lo que ya
hay en disco) compartan el mismo código: `honeypot_collector.consolidate()` lo
llama al final de cada pull, y `store.backfill` lo llama una vez por carpeta de
`by-date/`.

Orden de escritura, por la FK `observation.ioc → ioc.value`: cada IOC se
**asegura** primero con `upsert_ioc(..., count=False)` —crea la fila si hace
falta, sin sumarla a `times_seen`/`days_seen`— y sólo se cuenta cuando
`add_observation()` devuelve `True` (fila realmente nueva). Así reingerir la
misma ventana no infla los contadores: es la trampa que anotó el cierre de
F-B1 y la resuelve la opción (b) que dejó escrita (`count:` en `upsert_ioc`).
"""

from __future__ import annotations

from separatio.hygiene import SELF

from . import models


def _attacker_rows(attackers: dict | list) -> list[dict]:
    if isinstance(attackers, dict):
        return attackers.get("attackers", []) or []
    return list(attackers or [])


def ingest_run(conn, *, attackers: dict, events: list[dict],
               hashes: list[dict] | None = None) -> dict:
    """Vuelca una corrida del colector al store. Idempotente.

    attackers: el payload completo de attackers.json (con su clave `hygiene`).
    events:    las filas de events.jsonl.
    hashes:    filas de hashes.log, si las hay (las usa el backfill).

    Devuelve {"iocs_nuevos": n, "observaciones_nuevas": n, "payloads_nuevos": n}
    para que el caller lo loguee."""
    iocs_nuevos = 0
    observaciones_nuevas = 0
    payloads_nuevos = 0

    meta_by_ip: dict[str, tuple[str | None, str | None]] = {}

    # 1) Asegurar la fila de cada IOC (IP + HASSH) — sin contarla como avistamiento.
    for a in _attacker_rows(attackers):
        ip = a.get("ip")
        if not ip or a.get("class") == SELF:
            continue
        klass = a.get("class")
        scanner_name = a.get("scanner_name")
        meta_by_ip[ip] = (klass, scanner_name)
        ts0 = a.get("first_seen") or a.get("last_seen") or models.now_iso()
        existed = models.ioc_row(conn, ip) is not None
        models.upsert_ioc(conn, ip, "ip", ts0, klass=klass, scanner_name=scanner_name,
                          count=False)
        if not existed:
            iocs_nuevos += 1

        hassh_ts = a.get("last_seen") or ts0
        for h in a.get("hassh", []) or []:
            h_existed = models.ioc_row(conn, h) is not None
            models.upsert_ioc(conn, h, "hassh", hassh_ts, count=False)
            if not h_existed:
                iocs_nuevos += 1
            added = models.add_observation(conn, h, hassh_ts, "honeypot",
                                           sensor="vm1-cowrie", service="ssh",
                                           action=f"from {ip}")
            if added:
                observaciones_nuevas += 1
                models.upsert_ioc(conn, h, "hassh", hassh_ts, count=True)

    # 2) Observaciones desde events[]. Cada una nueva cuenta al IOC y, si trae
    #    payload, al corpus.
    for e in events or []:
        ip = e.get("ip")
        if not ip or ip not in meta_by_ip:
            continue                        # self/desconocido: sin fila de IOC
        ts = e.get("ts") or models.now_iso()
        sha = e.get("sha256")
        if sha:
            # `observation.payload_sha256` es FK: el payload tiene que existir
            # antes de intentar la observación, igual que el IOC.
            p_existed = conn.execute(
                "SELECT 1 FROM payload WHERE sha256 = ?", (sha,)).fetchone() is not None
            models.upsert_payload(conn, sha, e.get("size") or 0, ts)
            if not p_existed:
                payloads_nuevos += 1
        added = models.add_observation(conn, ip, ts, "honeypot",
                                       sensor=e.get("sensor"), service=e.get("service"),
                                       action=e.get("action"), payload_sha256=sha)
        if not added:
            continue
        observaciones_nuevas += 1
        klass, scanner_name = meta_by_ip[ip]
        models.upsert_ioc(conn, ip, "ip", ts, klass=klass, scanner_name=scanner_name,
                          count=True)

    # 3) `hashes.log` (sólo el backfill lo trae): el índice del corpus completo,
    #    ya deduplicado por el propio colector — una fila por sha256.
    for h in hashes or []:
        sha = h.get("sha256") or h.get("sha")
        if not sha:
            continue
        ts = h.get("date") or h.get("ts") or models.now_iso()
        p_existed = conn.execute(
            "SELECT 1 FROM payload WHERE sha256 = ?", (sha,)).fetchone() is not None
        models.upsert_payload(conn, sha, h.get("size") or 0, ts)
        if not p_existed:
            payloads_nuevos += 1

    return {"iocs_nuevos": iocs_nuevos, "observaciones_nuevas": observaciones_nuevas,
            "payloads_nuevos": payloads_nuevos}
