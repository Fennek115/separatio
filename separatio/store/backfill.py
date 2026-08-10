"""
backfill.py — ingesta retroactiva de lo que ya hay en disco (F-B2 del rework).

Recorre `data/honeypot/by-date/*/` en orden de fecha y vuelca cada carpeta al
store con `ingest_run` — el mismo código que usa el colector en vivo (ver
`honeypot_collector.consolidate`). Es lo que reconstruye `data/archivo.db` si
se borra: los artefactos en disco son la fuente de verdad (invariante 3 del
rework), el store es una vista.

Tolerancia obligatoria a snapshots viejos: `by-date/2026-08-08/` no tiene
`events.jsonl` ni `payloads/`, y sus atacantes no traen `class`/`scanner_name`
(son anteriores a F-A) — se clasifican acá mismo para no meter la IP propia del
laptop al store.

Uso:
    python3 -m separatio.store.backfill                 # todo by-date/*/
    python3 -m separatio.store.backfill --since 2026-08-01
    python3 -m separatio.store.backfill --dry-run        # qué cambiaría, sin tocar el store
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import tempfile
from pathlib import Path

from separatio import config
from separatio.hygiene import SELF, build_classifier
from separatio.store import models
from separatio.store.db import MEMORY, default_path, store
from separatio.store.ingest import ingest_run

TOTAL_KEYS = ("carpetas", "iocs_nuevos", "observaciones_nuevas", "payloads_nuevos")


def _read_events(daydir: Path) -> list[dict]:
    p = daydir / "events.jsonl"
    if not p.exists():
        return []
    rows = []
    for line in p.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _read_payloads_dir(daydir: Path) -> list[dict]:
    """`payloads/*.bin` del snapshot del día: sha256 (del nombre) y tamaño. Cubre
    binarios que por lo que sea no quedaron referenciados en `events.jsonl`."""
    pdir = daydir / "payloads"
    if not pdir.is_dir():
        return []
    return [{"sha256": f.stem, "size": f.stat().st_size} for f in pdir.glob("*.bin")]


def _read_hashlog(root: Path) -> list[dict]:
    p = root.parent / "hashes.log"
    if not p.exists():
        return []
    rows = []
    for line in p.read_text(errors="ignore").splitlines():
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 5:
            continue
        sha, date, sensor, service, size = parts[0], parts[1], parts[2], parts[3], parts[4]
        rows.append({"sha256": sha, "date": date, "sensor": sensor, "service": service,
                    "size": int(size) if size.isdigit() else 0})
    return rows


def _classify_attackers(payload: dict, classifier) -> dict:
    """Completa `class`/`scanner_name` en los atacantes que no lo traigan
    (snapshots anteriores a F-A) y saca a los que resulten `self`."""
    classified = []
    for a in payload.get("attackers", []) or []:
        if a.get("class") is None:
            cls, name = classifier.classify(a["ip"])
            a = {**a, "class": cls, "scanner_name": name}
        if a.get("class") == SELF:
            continue
        classified.append(a)
    return {**payload, "attackers": classified}


def backfill(root: Path | str | None = None, *, since: str | None = None,
            dry_run: bool = False, classifier=None,
            db_path: str | Path | None = None) -> dict:
    """Recorre `by-date/*/` en orden y vuelca cada carpeta al store con
    `ingest_run`. Devuelve los totales acumulados; con `dry_run` son igual de
    exactos, porque la ingesta corre contra una copia temporal del store."""
    root = Path(root) if root else Path(config.REPO_ROOT) / "data" / "honeypot" / "by-date"
    classifier = classifier or build_classifier(config)
    totals = {k: 0 for k in TOTAL_KEYS}

    if not root.is_dir():
        return totals

    dirs = sorted(p for p in root.iterdir() if p.is_dir())
    if since:
        dirs = [p for p in dirs if p.name >= since]

    if dry_run:
        # Se ingiere **de verdad**, pero contra una copia temporal del store: los
        # totales salen del mismo `ingest_run` que la corrida real, así que dicen
        # exactamente qué cambiaría, y el fichero de producción no se toca.
        #
        # Antes esto contaba `len(attackers)` y `len(events)` sin comprobar si
        # insertarían, y mentía: el 2026-08-10 anunció 2 observaciones donde la
        # corrida real insertó 0, porque los eventos de Cowrie traen `ip: "?"` y
        # no generan observación. Un dry-run que no predice no sirve.
        origen = str(db_path) if db_path else default_path()
        with tempfile.TemporaryDirectory(prefix="backfill-dryrun-") as tmp:
            copia = str(Path(tmp) / "archivo.db")
            if origen != MEMORY and Path(origen).is_file():
                # `backup()` y no `copy2`: respeta el WAL, que puede tener commits
                # que todavía no están en el fichero principal.
                src = sqlite3.connect(origen)
                dst = sqlite3.connect(copia)
                try:
                    with dst:
                        src.backup(dst)
                finally:
                    src.close()
                    dst.close()
            return backfill(root, since=since, classifier=classifier, db_path=copia)

    with store(db_path, read_only=False) as conn:
        if conn is None:
            print("backfill: sin store (STORE_ENABLED=0 o no se pudo abrir)", file=sys.stderr)
            return totals
        for daydir in dirs:
            att_path = daydir / "attackers.json"
            if not att_path.exists():
                continue
            payload = _classify_attackers(json.loads(att_path.read_text()), classifier)
            events = _read_events(daydir)
            hashes = _read_payloads_dir(daydir)
            stats = ingest_run(conn, attackers=payload, events=events, hashes=hashes)
            totals["carpetas"] += 1
            for k in ("iocs_nuevos", "observaciones_nuevas", "payloads_nuevos"):
                totals[k] += stats[k]

        # El hashes.log es el índice global del corpus, no por día: se ingiere
        # una sola vez, al final.
        global_hashes = _read_hashlog(root)
        if global_hashes:
            stats = ingest_run(conn, attackers={"attackers": []}, events=[],
                               hashes=global_hashes)
            totals["payloads_nuevos"] += stats["payloads_nuevos"]

        models.prune_observations(conn, config.STORE_RETENTION_DAYS)

    return totals


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    ap = argparse.ArgumentParser(description="Backfill del store desde by-date/")
    ap.add_argument("--since", default=None, help="YYYY-MM-DD: sólo carpetas desde acá")
    ap.add_argument("--dry-run", action="store_true",
                    help="ingiere contra una copia temporal y reporta el cambio real")
    args = ap.parse_args(argv)

    totals = backfill(since=args.since, dry_run=args.dry_run)
    tag = "[dry-run] " if args.dry_run else ""
    print(f"{tag}backfill: {totals['carpetas']} carpeta(s), "
          f"{totals['iocs_nuevos']} IOC(s) nuevo(s), "
          f"{totals['observaciones_nuevas']} observación(es) nueva(s), "
          f"{totals['payloads_nuevos']} payload(s) nuevo(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
