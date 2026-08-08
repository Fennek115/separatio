"""Tests de la librería ip_enricher — lógica pura + cascada por niveles sin red."""

from ipcheck import ip_enricher as ie
from ipcheck.ip_enricher import ApiKeys, IpEnricher


# ── Claves ────────────────────────────────────────────────

def test_apikeys_active():
    assert ApiKeys.active("realkey") is True
    assert ApiKeys.active("") is False
    assert ApiKeys.active("TU_API_KEY_AQUI") is False
    assert ApiKeys.active(None) is False


# ── Clasificación de riesgo (pura) ────────────────────────

def test_risk_level_thresholds():
    assert ie.risk_level(80, 0, "benign", 0, False, False) == "CRITICO"
    assert ie.risk_level(0, 5, "benign", 0, False, False) == "CRITICO"
    assert ie.risk_level(0, 0, "malicious", 0, False, False) == "CRITICO"
    assert ie.risk_level(0, 0, "benign", 0, True, False) == "CRITICO"   # threatfox
    assert ie.risk_level(50, 0, "benign", 0, False, False) == "ALTO"
    assert ie.risk_level(0, 0, "benign", 5, False, False) == "ALTO"
    assert ie.risk_level(20, 0, "benign", 0, False, False) == "MEDIO"
    assert ie.risk_level(0, 0, "benign", 0, False, True) == "MEDIO"     # urlhaus
    assert ie.risk_level(0, 0, "benign", 0, False, False) == "BAJO"


# ── Decisión de niveles (pura) ────────────────────────────

def test_decidir_nivel_riot_corta():
    gn = {"status": "ok", "riot": True, "name": "Cloudflare DNS"}
    pasar, motivo = ie.decidir_nivel(gn, None, None)
    assert pasar is False and "RIOT" in motivo


def test_decidir_nivel_benign_datacenter_corta():
    gn = {"status": "ok", "riot": False, "classification": "benign"}
    ipapi = {"status": "ok", "hosting": True}
    shodan = {"status": "ok", "ports": [443]}
    pasar, _ = ie.decidir_nivel(gn, ipapi, shodan)
    assert pasar is False


def test_decidir_nivel_puerto_sospechoso_no_corta():
    gn = {"status": "ok", "riot": False, "classification": "benign"}
    ipapi = {"status": "ok", "hosting": True}
    shodan = {"status": "ok", "ports": [4444]}   # puerto C2
    pasar, _ = ie.decidir_nivel(gn, ipapi, shodan)
    assert pasar is True


def test_debe_pasar_nivel3_signals():
    necesita, motivo = ie.debe_pasar_nivel3(
        {"status": "ok", "abuse_score": 40}, None, None, None)
    assert necesita is True and "AbuseIPDB" in motivo
    necesita, _ = ie.debe_pasar_nivel3(
        {"status": "ok", "abuse_score": 0}, {"status": "ok", "pulse_count": 0}, None, None)
    assert necesita is False


# ── Cascada completa con HTTP monkeypatcheado ─────────────

def _patch_all(monkeypatch, **overrides):
    """Devuelve 'ok' vacíos por defecto; overrides reemplaza por fuente."""
    defaults = {
        "check_ipapi":     {"status": "ok", "hosting": False, "proxy": False, "country_code": "US"},
        "check_greynoise": {"status": "ok", "riot": False, "classification": "unknown"},
        "check_shodan":    {"status": "ok", "ports": [], "vulns": []},
        "check_abuseipdb": {"status": "ok", "abuse_score": 0},
        "check_otx":       {"status": "ok", "pulse_count": 0},
        "check_virustotal":{"status": "ok", "malicious": 0},
        "check_urlhaus":   {"status": "ok", "found": False},
        "check_threatfox": {"status": "ok", "found": False},
    }
    defaults.update(overrides)
    for fn_name, ret in defaults.items():
        monkeypatch.setattr(ie, fn_name, (lambda r: (lambda *a, **k: r))(ret))


def test_cascade_stops_at_level1_on_riot(monkeypatch):
    _patch_all(monkeypatch, check_greynoise={"status": "ok", "riot": True, "name": "Google"})
    enr = IpEnricher(ApiKeys(abuseipdb="k", virustotal="k", otx="k", abusech="k"))
    r = enr.enrich("8.8.8.8")
    assert r["level_reached"] == 1
    assert r["risk"] == "BAJO"
    assert enr.stats["abuseipdb"]["ok"] == 0   # nunca se llamó


def test_cascade_reaches_level3_and_flags_critical(monkeypatch):
    _patch_all(
        monkeypatch,
        check_abuseipdb={"status": "ok", "abuse_score": 95},
        check_virustotal={"status": "ok", "malicious": 10},
        check_threatfox={"status": "ok", "found": True, "malware": ["Cobalt Strike"]},
    )
    enr = IpEnricher(ApiKeys(abuseipdb="k", virustotal="k", otx="k", abusech="k"))
    r = enr.enrich("185.220.101.45")
    assert r["level_reached"] == 3
    assert r["risk"] == "CRITICO"


def test_vt_quota_exhausted_marks_incomplete(monkeypatch):
    _patch_all(
        monkeypatch,
        check_abuseipdb={"status": "ok", "abuse_score": 60},
        check_virustotal={"status": "quota", "http_code": 429},
    )
    enr = IpEnricher(ApiKeys(abuseipdb="k", virustotal="k", otx="k", abusech="k"))
    r = enr.enrich("1.2.3.4")
    assert r["level_complete"] is False
    assert enr.vt_quota_exhausted is True


def test_disabled_source_is_skipped(monkeypatch):
    _patch_all(monkeypatch)
    enr = IpEnricher(ApiKeys(abuseipdb="k", virustotal="k", otx="k", abusech="k"),
                     disabled={"virustotal"})
    # Forzamos señales en Nivel 2 para llegar a Nivel 3
    monkeypatch.setattr(ie, "check_abuseipdb", lambda *a, **k: {"status": "ok", "abuse_score": 60})
    r = enr.enrich("1.2.3.4")
    assert r["virustotal"] is None
    assert enr.stats["virustotal"]["skipped"] == 1
