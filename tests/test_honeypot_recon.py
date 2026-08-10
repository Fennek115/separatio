"""
Tests del enricher inverso (F-C del rework): `HoneypotReconEnricher`.

Todo sobre `:memory:`, sin red: `_check_greynoise`/`_cascade` se pisan a nivel
de instancia (son atributos de instancia lisos, no quedan bindeados como
método — llamarlos vía `self._check_greynoise(ip)` invoca al doble tal cual).
`LocalLists` se inyecta con un doble (`FakeLists`) por constructor.

Los tests llaman a `_run(conn, ctx)` directamente (no a `enrich`, que abre el
store real): es el mismo patrón de caja blanca que ya usa `test_store_ingest.py`
para no depender de `db.open_store()` con un `:memory:` por conexión (cada
`:memory:` es una base aislada — pasar la misma conexión es la única forma de
compartir estado entre `_run` y las aserciones)."""

from datetime import datetime, timedelta, timezone

from separatio.enrichers import honeypot_recon as hr
from separatio.enrichers.honeypot_recon import HoneypotReconEnricher
from separatio.enrichment import EnrichmentContext
from separatio.lists import ListHit
from separatio.store import db, models

DAY = "2026-08-09T07:00:00+00:00"


def _conn():
    c = db.open_store(db.MEMORY)
    assert c is not None
    return c


def _now(offset_days: float = 0.0) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=offset_days)).isoformat(timespec="seconds")


def _seed(conn, ip, *, klass=None, sensor="vm1-cowrie", payload=None, ts=None):
    ts = ts or _now()
    models.upsert_ioc(conn, ip, "ip", ts, klass=klass)
    if payload:
        models.upsert_payload(conn, payload, 10, ts)
    models.add_observation(conn, ip, ts, "honeypot", sensor=sensor, payload_sha256=payload)


class FakeLists:
    def __init__(self, hits: dict[str, list[ListHit]] | None = None):
        self.hits = hits or {}

    def lookup(self, ip):
        return self.hits.get(ip, [])


class FakeSession:
    def __init__(self, vt_quota_exhausted: bool = False):
        self.vt_quota_exhausted = vt_quota_exhausted


def _enricher(*, quota_limit=20, max_escalate=5, lists=None):
    return HoneypotReconEnricher(
        window_hours=26,
        max_escalate=max_escalate,
        quotas={"greynoise": {"limit": quota_limit, "window": "week"}},
        lists=lists if lists is not None else FakeLists(),
    )


def _gn_noise(calls):
    def fn(ip):
        calls.append(ip)
        return {"status": "ok", "noise": True, "classification": "scanner"}
    return fn


def _gn_signal(calls):
    def fn(ip):
        calls.append(ip)
        return {"status": "ok", "noise": False, "classification": "unknown"}
    return fn


def _cascade_fake(calls, level_reached=1):
    def fn(ip):
        calls.append(ip)
        full = {"level_reached": level_reached,
               "abuseipdb": {"status": "ok", "abuse_score": 0},
               "virustotal": {}, "otx": {}}
        return FakeSession(), full
    return fn


# ─────────────────────────────────────────────
# 0. HIGIENE
# ─────────────────────────────────────────────

def test_los_escaneres_no_consumen_cuota():
    conn = _conn()
    _seed(conn, "1.1.1.1", klass="scanner")
    calls = []
    e = _enricher()
    e._check_greynoise = _gn_noise(calls)
    e._run(conn, EnrichmentContext())
    assert calls == []


# ─────────────────────────────────────────────
# 1. CACHE
# ─────────────────────────────────────────────

def test_el_cache_evita_la_consulta():
    conn = _conn()
    _seed(conn, "2.2.2.2")
    models.put_cached(conn, "2.2.2.2", "greynoise", "noise", "cache viejo", ttl_days=7, now=_now())
    calls = []
    e = _enricher()
    e._check_greynoise = _gn_noise(calls)
    e._run(conn, EnrichmentContext())
    assert calls == []


def test_el_cache_vencido_si_consulta():
    conn = _conn()
    _seed(conn, "3.3.3.3")
    # fetched hace 8 días, ttl 7 → vencido hoy.
    models.put_cached(conn, "3.3.3.3", "greynoise", "noise", "viejo",
                      ttl_days=7, now=_now(-8))
    calls = []
    e = _enricher()
    e._check_greynoise = _gn_noise(calls)
    e._run(conn, EnrichmentContext())
    assert calls == ["3.3.3.3"]


def test_el_presupuesto_sale_del_store():
    """El presupuesto se cuenta contra `enrichment`, no en una variable de
    instancia: dos objetos `HoneypotReconEnricher` distintos sobre el mismo
    store ven el mismo consumo acumulado."""
    conn = _conn()
    _seed(conn, "4.4.4.1")
    _seed(conn, "4.4.4.2")
    _seed(conn, "4.4.4.3")

    calls = []
    e1 = _enricher(quota_limit=2)
    e1._check_greynoise = _gn_noise(calls)
    e1._run(conn, EnrichmentContext())
    assert len(calls) == 2      # todo el presupuesto de 2 se gasta en la 1ª pasada

    e2 = _enricher(quota_limit=2)   # instancia nueva, mismo store
    e2._check_greynoise = _gn_noise(calls)
    e2._run(conn, EnrichmentContext())
    assert len(calls) == 2      # sin presupuesto restante: la 2ª pasada no consulta nada


# ─────────────────────────────────────────────
# 2. LISTAS
# ─────────────────────────────────────────────

def test_un_acierto_en_lista_local_termina():
    conn = _conn()
    _seed(conn, "5.5.5.5")
    lists = FakeLists({"5.5.5.5": [ListHit(source="jamesbrine")]})
    calls = []
    e = _enricher(lists=lists)
    e._check_greynoise = _gn_noise(calls)
    ctx = EnrichmentContext()
    e._run(conn, ctx)
    assert calls == []
    assert any("5.5.5.5" in text and "jamesbrine" in text for _, text in ctx.notes)


def test_solo_el_residuo_llega_a_greynoise():
    conn = _conn()
    for ip in ("6.6.6.1", "6.6.6.2", "6.6.6.3"):
        _seed(conn, ip)
    for ip in ("6.6.6.4", "6.6.6.5"):
        _seed(conn, ip)
    lists = FakeLists({ip: [ListHit(source="ipsum")] for ip in ("6.6.6.1", "6.6.6.2", "6.6.6.3")})
    calls = []
    e = _enricher(lists=lists)
    e._check_greynoise = _gn_noise(calls)
    e._run(conn, EnrichmentContext())
    assert sorted(calls) == ["6.6.6.4", "6.6.6.5"]


# ─────────────────────────────────────────────
# 3. RESIDUO → GreyNoise → cascada
# ─────────────────────────────────────────────

def test_noise_false_emite_senal_fuerte():
    conn = _conn()
    _seed(conn, "7.7.7.7")
    e = _enricher()
    e._check_greynoise = _gn_signal([])
    e._cascade = _cascade_fake([])
    ctx = EnrichmentContext()
    e._run(conn, ctx)
    assert len(ctx.verdicts) == 1
    v = ctx.verdicts[0]
    assert v.ioc == "7.7.7.7" and v.label == "posible actividad dirigida"


def test_noise_true_no_emite_veredicto():
    conn = _conn()
    _seed(conn, "8.8.8.8")
    e = _enricher()
    e._check_greynoise = _gn_noise([])
    ctx = EnrichmentContext()
    e._run(conn, ctx)
    assert ctx.verdicts == []
    assert any("8.8.8.8" in text for _, text in ctx.notes)


def test_solo_noise_false_escala_a_la_cascada():
    conn = _conn()
    _seed(conn, "9.9.9.1")   # va a decir noise=False
    _seed(conn, "9.9.9.2")   # va a decir noise=True

    def gn(ip):
        return {"status": "ok", "noise": ip != "9.9.9.1", "classification": "x"}

    cascade_calls = []
    e = _enricher()
    e._check_greynoise = gn
    e._cascade = _cascade_fake(cascade_calls)
    e._run(conn, EnrichmentContext())
    assert cascade_calls == ["9.9.9.1"]


def test_la_cuota_agotada_frena_las_consultas():
    conn = _conn()
    _seed(conn, "10.10.10.10")
    now = _now()
    for i in range(5):
        models.put_cached(conn, f"250.0.0.{i}", "greynoise", "noise", "", ttl_days=7, now=now)
    calls = []
    e = _enricher(quota_limit=5)   # ya usadas 5/5 → presupuesto 0
    e._check_greynoise = _gn_noise(calls)
    e._run(conn, EnrichmentContext())
    assert calls == []


def test_orden_de_prioridad_del_residuo():
    conn = _conn()
    # a: 1 día, sin payload, 1 sensor, 1 hit         → última prioridad
    _seed(conn, "11.0.0.1", sensor="vm1-cowrie")
    # b: 1 día, CON payload                          → sube por encima de a
    _seed(conn, "11.0.0.2", sensor="vm1-cowrie", payload="a" * 64)
    # c: 1 día, sin payload, 2 sensores (dos observaciones, sensores distintos)
    models.upsert_ioc(conn, "11.0.0.3", "ip", _now())
    models.add_observation(conn, "11.0.0.3", _now(), "honeypot", sensor="vm1-cowrie")
    models.add_observation(conn, "11.0.0.3", _now(), "honeypot", sensor="vm2-services")

    order = []
    e = _enricher()
    e._check_greynoise = _gn_noise(order)
    e._run(conn, EnrichmentContext())
    # payload pesa más que multi-sensor, que pesa más que un solo hit sin nada.
    assert order == ["11.0.0.2", "11.0.0.3", "11.0.0.1"]


def test_max_escalate_acota_la_cascada():
    conn = _conn()
    ips = [f"12.0.0.{i}" for i in range(10)]
    for ip in ips:
        _seed(conn, ip)
    cascade_calls = []
    e = _enricher(quota_limit=20, max_escalate=5)
    e._check_greynoise = _gn_signal([])
    e._cascade = _cascade_fake(cascade_calls)
    ctx = EnrichmentContext()
    e._run(conn, ctx)
    assert len(cascade_calls) == 5
    # nada se pierde en silencio: las 10 igual emiten veredicto de señal fuerte.
    assert len(ctx.verdicts) == 10


# ─────────────────────────────────────────────
# Store ausente / cascada sin duplicar GreyNoise
# ─────────────────────────────────────────────

def test_sin_store_el_enricher_no_hace_nada(monkeypatch):
    monkeypatch.setattr(hr.db, "open_store", lambda *a, **k: None)
    e = _enricher()
    ctx = EnrichmentContext()
    e.enrich({}, ctx)   # no debe levantar
    assert ctx.verdicts == [] and ctx.notes == []


def test_greynoise_no_se_consulta_dos_veces(monkeypatch):
    from ipcheck import ip_enricher as ie

    captured = {}

    class _FakeIpEnricher:
        def __init__(self, keys, disabled=frozenset()):
            captured["disabled"] = disabled
            self.vt_quota_exhausted = False

        def enrich(self, ip):
            return {"level_reached": 1}

    monkeypatch.setattr(ie, "IpEnricher", _FakeIpEnricher)
    HoneypotReconEnricher._cascade("13.13.13.13")
    assert captured["disabled"] == {"greynoise"}
