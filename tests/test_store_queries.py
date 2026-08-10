"""
Tests de `separatio/store/queries.py` — reincidencia (F-D del rework).

Mismo patrón que `test_store.py`: todo en `:memory:`, con `now`/`ts` siempre
explícitos para no depender del reloj. La excepción es el último test
(`test_el_veredicto_incluye_la_reincidencia`), que ejercita el enricher entero
—`_run()` calcula su propio `now` con el reloj real, como ya hace
`test_honeypot_recon.py`— así que usa offsets de días sobre un ancla capturada
una sola vez, para no cruzar de fecha calendario entre observaciones.
"""

from datetime import datetime, timedelta, timezone

import pytest

from separatio.store import db, models, queries

NOW = "2026-08-09T12:00:00+00:00"


@pytest.fixture
def conn():
    c = db.open_store(db.MEMORY)
    assert c is not None
    try:
        yield c
    finally:
        c.close()


def _seed_hassh(conn, value, ts, from_ip):
    models.upsert_ioc(conn, value, "hassh", ts, count=False)
    models.add_observation(conn, value, ts, "honeypot", sensor="vm1-cowrie",
                           service="ssh", action=f"from {from_ip}")


# ─────────────────────────────────────────────
# ip_recurrence
# ─────────────────────────────────────────────

def test_ip_recurrence_cuenta_dias_distintos(conn):
    ip = "1.2.3.4"
    models.upsert_ioc(conn, ip, "ip", "2026-08-01T00:00:00+00:00", count=False)
    for ts in ("2026-08-01T08:00:00+00:00", "2026-08-01T09:00:00+00:00",
               "2026-08-01T10:00:00+00:00"):
        models.add_observation(conn, ip, ts, "honeypot", sensor="vm1-cowrie")
    assert queries.ip_recurrence(conn, ip, window_days=14, now=NOW)["days_seen"] == 1

    for ts in ("2026-08-02T08:00:00+00:00", "2026-08-03T08:00:00+00:00"):
        models.add_observation(conn, ip, ts, "honeypot", sensor="vm1-cowrie")
    assert queries.ip_recurrence(conn, ip, window_days=14, now=NOW)["days_seen"] == 3


def test_ip_recurrence_respeta_la_ventana(conn):
    ip = "2.2.2.2"
    models.upsert_ioc(conn, ip, "ip", "2026-07-01T00:00:00+00:00", count=False)
    models.add_observation(conn, ip, "2026-07-20T00:00:00+00:00", "honeypot")  # 20 días antes de NOW
    assert queries.ip_recurrence(conn, ip, window_days=14, now=NOW) is None

    models.add_observation(conn, ip, "2026-08-05T00:00:00+00:00", "honeypot")  # dentro de la ventana
    rec = queries.ip_recurrence(conn, ip, window_days=14, now=NOW)
    assert rec["days_seen"] == 1


def test_ip_recurrence_devuelve_none_si_no_existe(conn):
    assert queries.ip_recurrence(conn, "9.9.9.9", now=NOW) is None


# ─────────────────────────────────────────────
# payload_history
# ─────────────────────────────────────────────

def test_payload_history_devuelve_first_seen(conn):
    sha = "a" * 64
    models.upsert_payload(conn, sha, 100, "2026-07-02T00:00:00+00:00", family="Mirai")
    models.upsert_payload(conn, sha, 100, "2026-07-10T00:00:00+00:00")
    models.upsert_payload(conn, sha, 100, "2026-07-15T00:00:00+00:00")
    info = queries.payload_history(conn, sha)
    assert info["first_seen"].startswith("2026-07-02")
    assert info["times_seen"] == 3
    assert info["family"] == "Mirai"


# ─────────────────────────────────────────────
# hassh_fanout
# ─────────────────────────────────────────────

def test_hassh_fanout_agrupa_por_fingerprint(conn):
    h = "deadbeef" * 4
    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        _seed_hassh(conn, h, "2026-08-05T00:00:00+00:00", ip)
    out = queries.hassh_fanout(conn, min_ips=2, window_days=30, now=NOW)
    assert len(out) == 1
    assert out[0]["hassh"] == h
    assert out[0]["n_ips"] == 3
    assert sorted(out[0]["ips"]) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_hassh_fanout_respeta_min_ips(conn):
    h_big, h_small = "b" * 32, "c" * 32
    for ip in ("11.0.0.1", "11.0.0.2", "11.0.0.3"):
        _seed_hassh(conn, h_big, "2026-08-05T00:00:00+00:00", ip)
    for ip in ("11.0.0.4", "11.0.0.5"):
        _seed_hassh(conn, h_small, "2026-08-05T00:00:00+00:00", ip)
    out = queries.hassh_fanout(conn, min_ips=3, window_days=30, now=NOW)
    hasshes = {r["hassh"] for r in out}
    assert h_big in hasshes
    assert h_small not in hasshes


def test_hassh_fanout_no_cuenta_la_misma_ip_dos_veces(conn):
    h = "d" * 32
    _seed_hassh(conn, h, "2026-08-05T00:00:00+00:00", "12.0.0.1")
    _seed_hassh(conn, h, "2026-08-06T00:00:00+00:00", "12.0.0.1")  # misma IP, otro día
    out = queries.hassh_fanout(conn, min_ips=1, window_days=30, now=NOW)
    assert out[0]["n_ips"] == 1


# ─────────────────────────────────────────────
# top_recurrent
# ─────────────────────────────────────────────

def test_top_recurrent_ordena_por_days_seen(conn):
    ip_a = "20.0.0.1"
    models.upsert_ioc(conn, ip_a, "ip", "2026-08-01T00:00:00+00:00", count=False)
    for ts in ("2026-08-01T00:00:00+00:00", "2026-08-03T00:00:00+00:00",
               "2026-08-05T00:00:00+00:00"):
        models.add_observation(conn, ip_a, ts, "honeypot")

    ip_b = "20.0.0.2"
    models.upsert_ioc(conn, ip_b, "ip", "2026-08-07T00:00:00+00:00", count=False)
    models.add_observation(conn, ip_b, "2026-08-07T00:00:00+00:00", "honeypot")

    out = queries.top_recurrent(conn, limit=10, window_days=14, now=NOW)
    values = [r["value"] for r in out]
    assert values.index(ip_a) < values.index(ip_b)
    assert out[0]["value"] == ip_a
    assert out[0]["days_seen"] == 3


# ─────────────────────────────────────────────
# El enricher cita la reincidencia (F-D §2)
# ─────────────────────────────────────────────

def test_el_veredicto_incluye_la_reincidencia(conn):
    from separatio.enrichers.honeypot_recon import HoneypotReconEnricher
    from separatio.enrichment import EnrichmentContext

    base = datetime.now(timezone.utc)

    def offset(days: float) -> str:
        return (base + timedelta(days=days)).isoformat(timespec="seconds")

    ip = "30.0.0.1"
    models.upsert_ioc(conn, ip, "ip", offset(-5), count=False)
    for d in (-5, -3, -1):
        models.add_observation(conn, ip, offset(d), "honeypot", sensor="vm1-cowrie")

    class FakeLists:
        def lookup(self, ip):
            return []

    class FakeSession:
        vt_quota_exhausted = True

    e = HoneypotReconEnricher(window_hours=48,
                              quotas={"greynoise": {"limit": 20, "window": "week"}},
                              lists=FakeLists())
    e._check_greynoise = lambda ip: {"status": "ok", "noise": False, "classification": "unknown"}
    e._cascade = lambda ip: (FakeSession(), {"level_reached": 1})
    ctx = EnrichmentContext()
    e._run(conn, ctx)

    assert len(ctx.verdicts) == 1
    assert "volvió 3 de los últimos 14 días" in ctx.verdicts[0].detail
