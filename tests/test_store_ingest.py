"""
Tests de la ingesta (F-B2 del rework): `separatio.store.ingest.ingest_run` y
`separatio.store.backfill`.

Todo sobre `:memory:` o `tmp_path`: rápido, sin red, sin tocar `data/archivo.db`.
El tiempo se pasa siempre explícito, como en `tests/test_store.py`.
"""

import json

from separatio.honeypot_collector import consolidate
from separatio.hygiene import IpClassifier
from separatio.store import backfill as backfill_mod
from separatio.store import db, models
from separatio.store.ingest import ingest_run

DAY = "2026-08-09T07:00:00+00:00"
NEXT_DAY = "2026-08-10T07:15:00+00:00"

IP = "45.9.148.99"


def _conn():
    c = db.open_store(db.MEMORY)
    assert c is not None
    return c


def _attackers(ip=IP, ts=DAY, klass="unknown", scanner_name=None, hassh=None):
    return {
        "generated": ts, "window_hours": 720,
        "hygiene": {"self_excluded": 0, "self_hits": 0, "self_ips": [],
                   "scanners": {}, "unknown_ips": 1},
        "attackers": [{
            "ip": ip, "hits": 1, "kinds": ["cowrie"], "sensors": ["vm1-cowrie"],
            "first_seen": ts, "last_seen": ts, "sample_uris": [], "crowdsec": False,
            "class": klass, "scanner_name": scanner_name, "hassh": list(hassh or []),
        }],
    }


def _events(ip=IP, ts=DAY, action="login root:root (login.failed)", sha256=None, size=0):
    return [{"ts": ts, "ip": ip, "sensor": "vm1-cowrie", "service": "ssh",
             "action": action, "sha256": sha256, "size": size}]


# ─────────────────────────────────────────────
# ingest_run
# ─────────────────────────────────────────────

def test_ingesta_crea_iocs_y_observaciones():
    conn = _conn()
    stats = ingest_run(conn, attackers=_attackers(), events=_events())

    assert stats["iocs_nuevos"] == 1
    assert stats["observaciones_nuevas"] == 1
    row = models.ioc_row(conn, IP)
    assert row["kind"] == "ip"
    assert row["times_seen"] == 1
    assert conn.execute("SELECT COUNT(*) FROM observation").fetchone()[0] == 1


def test_reingerir_la_misma_ventana_no_duplica():
    conn = _conn()
    ingest_run(conn, attackers=_attackers(), events=_events())
    n1 = conn.execute("SELECT COUNT(*) FROM observation").fetchone()[0]

    ingest_run(conn, attackers=_attackers(), events=_events())
    n2 = conn.execute("SELECT COUNT(*) FROM observation").fetchone()[0]

    assert n1 == n2 == 1


def test_reingerir_no_infla_times_seen():
    conn = _conn()
    ingest_run(conn, attackers=_attackers(), events=_events())
    ingest_run(conn, attackers=_attackers(), events=_events())

    assert models.ioc_row(conn, IP)["times_seen"] == 1


def test_days_seen_sube_al_dia_siguiente():
    conn = _conn()
    ingest_run(conn, attackers=_attackers(ts=DAY), events=_events(ts=DAY))
    ingest_run(conn, attackers=_attackers(ts=NEXT_DAY), events=_events(ts=NEXT_DAY))

    row = models.ioc_row(conn, IP)
    assert row["days_seen"] == 2
    assert row["times_seen"] == 2


def test_hassh_entra_como_ioc_propio():
    conn = _conn()
    ingest_run(conn, attackers=_attackers(hassh=["deadbeefcafe"]), events=[])

    n = conn.execute("SELECT COUNT(*) FROM ioc WHERE kind='hassh'").fetchone()[0]
    assert n == 1
    row = models.ioc_row(conn, "deadbeefcafe")
    assert row is not None and row["kind"] == "hassh"


def test_hassh_se_liga_a_sus_ips():
    conn = _conn()
    ingest_run(conn, attackers=_attackers(hassh=["deadbeefcafe"]), events=[])

    rows = conn.execute(
        "SELECT action FROM observation WHERE ioc = ?", ("deadbeefcafe",)).fetchall()
    assert [r[0] for r in rows] == [f"from {IP}"]


def test_la_clase_de_higiene_persiste():
    conn = _conn()
    ingest_run(conn, attackers=_attackers(klass="scanner", scanner_name="censys"),
              events=_events())

    row = models.ioc_row(conn, IP)
    assert row["klass"] == "scanner"
    assert row["scanner_name"] == "censys"


def test_payload_entra_desde_events():
    conn = _conn()
    sha = "a" * 64
    ingest_run(conn, attackers=_attackers(),
              events=_events(sha256=sha, size=128, action="download evil.sh"))

    row = conn.execute("SELECT size, times_seen FROM payload WHERE sha256=?", (sha,)).fetchone()
    assert tuple(row) == (128, 1)


# ─────────────────────────────────────────────
# backfill
# ─────────────────────────────────────────────

def _clf():
    return IpClassifier(own_ips=["190.21.171.52"], use_ptr=False)


def test_backfill_tolera_snapshot_sin_events(tmp_path):
    by_date = tmp_path / "by-date"
    daydir = by_date / "2026-08-08"
    daydir.mkdir(parents=True)
    (daydir / "attackers.json").write_text(json.dumps(_attackers()))

    totals = backfill_mod.backfill(root=by_date, classifier=_clf(), db_path=db.MEMORY)

    assert totals["carpetas"] == 1
    assert totals["iocs_nuevos"] == 1
    assert totals["observaciones_nuevas"] == 0


def test_backfill_clasifica_snapshots_viejos(tmp_path):
    by_date = tmp_path / "by-date"
    daydir = by_date / "2026-08-08"
    daydir.mkdir(parents=True)
    propia = {
        "generated": DAY, "window_hours": 24,
        "attackers": [{"ip": "190.21.171.52", "hits": 3, "kinds": ["web"],
                       "sensors": ["vm1-web"], "first_seen": DAY, "last_seen": DAY,
                       "sample_uris": [], "crowdsec": False}],
    }
    (daydir / "attackers.json").write_text(json.dumps(propia))

    dbfile = str(tmp_path / "archivo.db")
    totals = backfill_mod.backfill(root=by_date, classifier=_clf(), db_path=dbfile)

    assert totals["iocs_nuevos"] == 0
    conn = db.open_store(dbfile)
    assert models.ioc_row(conn, "190.21.171.52") is None


def test_backfill_es_idempotente(tmp_path):
    by_date = tmp_path / "by-date"
    daydir = by_date / "2026-08-09"
    daydir.mkdir(parents=True)
    (daydir / "attackers.json").write_text(json.dumps(_attackers()))
    (daydir / "events.jsonl").write_text(json.dumps(_events()[0]) + "\n")

    conn = db.open_store(db.MEMORY)
    dbfile = str(tmp_path / "archivo.db")
    backfill_mod.backfill(root=by_date, classifier=_clf(), db_path=dbfile)
    backfill_mod.backfill(root=by_date, classifier=_clf(), db_path=dbfile)

    c2 = db.open_store(dbfile)
    n_ioc = c2.execute("SELECT COUNT(*) FROM ioc").fetchone()[0]
    n_obs = c2.execute("SELECT COUNT(*) FROM observation").fetchone()[0]
    assert (n_ioc, n_obs) == (1, 1)


# ─────────────────────────────────────────────
# el pull no depende del store
# ─────────────────────────────────────────────

def test_el_pull_sigue_funcionando_sin_store(tmp_path, monkeypatch):
    from separatio import config

    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "web.json").write_text(json.dumps({
        "ts": DAY, "ip": IP, "host": "h", "method": "GET",
        "uri": "/.env", "status": 404, "ua": "curl/8", "body": "",
    }) + "\n")

    monkeypatch.setattr(config, "STORE_ENABLED", False)
    out = tmp_path / "out"
    r = consolidate(raw, out, 24, classifier=_clf())

    assert r["store"] is None
    assert (out / "attackers.json").exists()
    assert [a["ip"] for a in r["attackers"]] == [IP]
