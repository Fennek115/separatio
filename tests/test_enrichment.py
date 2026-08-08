"""Tests de la capa de enrichment (Stage 2.7) — deterministas, sin red."""

from separatio.analyzer import ArticleSummary
from separatio.enrichment import (
    Enricher, EnrichmentContext, IocVerdict,
    collect_iocs, ioc_kind, normalize_ioc, run_enrichment,
)


def _summary(aid, feed, iocs):
    return ArticleSummary(article_id=aid, title=f"t{aid}", url="u",
                          feed_title=feed, feed_category="Threat Intel",
                          published_at="", iocs=iocs)


def test_ioc_kind():
    assert ioc_kind("1.2.3.4") == "ip"
    assert ioc_kind("1.2.3.4:8080") == "ip"
    assert ioc_kind("evil.com") == "domain"
    assert ioc_kind("http://evil.com/x") == "url"
    assert ioc_kind("a" * 32) == "hash"
    assert ioc_kind("a" * 64) == "hash"
    assert ioc_kind("notanioc") == "other"


def test_normalize_ioc_defang():
    assert normalize_ioc("evil[.]com") == "evil.com"
    assert normalize_ioc("evil[dot]com") == "evil.com"
    assert normalize_ioc("hxxp://evil.com") == "http://evil.com"
    assert normalize_ioc("  EVIL.com ") == "evil.com"


def test_collect_iocs_dedups_by_feed():
    summaries = [
        _summary(1, "FeedA", ["1.2.3.4", "evil[.]com"]),
        _summary(2, "FeedB", ["1.2.3.4"]),
        _summary(3, "FeedA", ["1.2.3.4"]),  # mismo feed -> no duplica
    ]
    iocs = collect_iocs(summaries)
    assert iocs["1.2.3.4"] == ["FeedA", "FeedB"]
    assert "evil.com" in iocs           # normalizado
    # IOCs triviales (<=4 chars) se descartan
    assert all(len(k) > 4 for k in iocs)


def test_context_prompt_and_export():
    ctx = EnrichmentContext()
    ctx.add(IocVerdict(ioc="1.2.3.4", kind="ip", source="IPsum",
                       label="IP maliciosa", detail="9 listas"))
    block = ctx.format_for_prompt()
    assert "ENRICHMENT EXTERNO" in block and "1.2.3.4" in block and "IPsum" in block
    rows = ctx.export_rows()
    assert rows[0]["ioc"] == "1.2.3.4" and rows[0]["source"] == "IPsum"


def test_run_enrichment_isolates_failures():
    class GoodEnricher(Enricher):
        name = "good"
        def enrich(self, iocs, ctx):
            ctx.add(IocVerdict(ioc="1.2.3.4", kind="ip", source="good", label="x"))

    class BoomEnricher(Enricher):
        name = "boom"
        def enrich(self, iocs, ctx):
            raise RuntimeError("falla simulada")

    summaries = [_summary(1, "FeedA", ["1.2.3.4"])]
    ctx = run_enrichment(summaries, [GoodEnricher(), BoomEnricher()])
    assert "good" in ctx.sources_ok
    assert "boom" in ctx.sources_failed
    assert len(ctx.verdicts) == 1          # el fallo de boom no borró el de good


def test_run_enrichment_no_iocs():
    ctx = run_enrichment([_summary(1, "FeedA", [])], [])
    assert not ctx.has_signals()


# ── Notas de contexto (actividad externa no ligada a IOCs) ──

def test_notes_in_prompt_but_not_in_export():
    ctx = EnrichmentContext()
    ctx.add_note("Ransomware.live", "lockbit publicó víctima: ACME (US, Retail)")
    assert ctx.has_signals()
    block = ctx.format_for_prompt()
    assert "ACTIVIDAD EXTERNA" in block
    assert "Source: Ransomware.live" in block
    assert "ACME" in block
    assert ctx.export_rows() == []         # las notas no contaminan el CSV de IOCs


def test_notes_and_verdicts_coexist():
    ctx = EnrichmentContext()
    ctx.add(IocVerdict(ioc="1.2.3.4", kind="ip", source="IPsum", label="mala"))
    ctx.add_note("Ransomware.live", "akira publicó víctima: X (DE, Legal)")
    block = ctx.format_for_prompt()
    assert "ENRICHMENT EXTERNO" in block and "ACTIVIDAD EXTERNA" in block


# ── RansomwareLiveEnricher ──

def _victim(**over):
    base = {
        "victim": "ACME Corp", "group": "lockbit",
        "discovered": "2099-01-01T12:00:00+00:00",
        "attackdate": "2099-01-01T10:00:00+00:00",
        "country": "US", "activity": "Retail", "domain": "acme.com",
    }
    base.update(over)
    return base


def test_ransomware_live_notes_and_crossmatch(monkeypatch):
    from separatio.enrichers.ransomware import RansomwareLiveEnricher
    enr = RansomwareLiveEnricher(url="http://test.invalid", lookback_hours=26)
    monkeypatch.setattr(enr, "_fetch", lambda: [
        _victim(),
        _victim(victim="Vieja SA", domain="vieja.com",
                discovered="2000-01-01T00:00:00+00:00"),   # fuera de ventana
    ])
    ctx = EnrichmentContext()
    enr.enrich({"acme.com": ["FeedA"], "otro.com": ["FeedB"]}, ctx)
    # Nota solo de la víctima reciente
    notes = [t for _, t in ctx.notes]
    assert any("ACME Corp" in n for n in notes)
    assert not any("Vieja SA" in n for n in notes)
    # Cruce: acme.com estaba entre los IOCs del día (aunque la publicación sea
    # vieja, el dominio matchea contra todo el feed)
    assert any(v.ioc == "acme.com" and v.source == "Ransomware.live"
               for v in ctx.verdicts)
    assert not any(v.ioc == "otro.com" for v in ctx.verdicts)


def test_ransomware_live_discards_sensitive_fields(monkeypatch):
    """GDPR/ToS: screenshot, claim_url e infostealer no sobreviven al parseo."""
    from separatio.enrichers import ransomware as rw

    class FakeResp:
        status_code = 200
        def raise_for_status(self): pass
        def json(self):
            return [_victim(screenshot="https://x/cap.png",
                            claim_url="http://leak.onion/x",
                            infostealer={"employees": 3})]

    monkeypatch.setattr(rw.requests, "get", lambda *a, **k: FakeResp())
    enr = rw.RansomwareLiveEnricher(url="http://test.invalid")
    data = enr._fetch()
    assert "screenshot" not in data[0]
    assert "claim_url" not in data[0]
    assert "infostealer" not in data[0]
    assert data[0]["victim"] == "ACME Corp"


def test_ransomware_live_caps_notes(monkeypatch):
    from separatio.enrichers.ransomware import RansomwareLiveEnricher
    enr = RansomwareLiveEnricher(url="http://test.invalid", max_victims=3)
    monkeypatch.setattr(enr, "_fetch", lambda: [
        _victim(victim=f"V{i}", domain=f"v{i}.com") for i in range(10)
    ])
    ctx = EnrichmentContext()
    enr.enrich({}, ctx)
    assert len(ctx.notes) == 4             # 3 víctimas + línea "(+7 más…)"
    assert "+7" in ctx.notes[-1][1]


# ── OnionLookupEnricher ──

def test_onion_lookup_only_queries_onions(monkeypatch):
    from separatio.enrichers import onionlookup as ol
    calls = []

    class FakeResp:
        status_code = 200
        def json(self):
            return {"id": "abc.onion", "first_seen": "2026-01-01",
                    "last_seen": "2026-07-01", "titles": ["Evil Blog"]}

    monkeypatch.setattr(ol, "get_with_retry",
                        lambda url, **k: calls.append(url) or FakeResp())
    enr = ol.OnionLookupEnricher(base_url="http://test.invalid/api/lookup")
    ctx = EnrichmentContext()
    enr.enrich({"abc.onion": ["FeedA"], "normal.com": ["FeedB"]}, ctx)
    assert calls == ["http://test.invalid/api/lookup/abc.onion"]
    assert len(ctx.verdicts) == 1
    v = ctx.verdicts[0]
    assert v.ioc == "abc.onion" and "Evil Blog" in v.detail


def test_onion_lookup_no_onions_no_calls(monkeypatch):
    from separatio.enrichers import onionlookup as ol
    monkeypatch.setattr(ol, "get_with_retry",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no debía llamar")))
    enr = ol.OnionLookupEnricher(base_url="http://test.invalid")
    ctx = EnrichmentContext()
    enr.enrich({"normal.com": ["FeedA"]}, ctx)
    assert not ctx.has_signals()


# ── HoneypotEnricher (dato propio, capa 4) ──

def _honeypot_file(tmp_path, attackers):
    import json
    p = tmp_path / "attackers.json"
    p.write_text(json.dumps({"generated": "2026-08-08T09:00:00+00:00",
                             "window_hours": 24, "attackers": attackers}))
    return str(p)


def test_honeypot_notes_and_strong_signal(tmp_path):
    from separatio.enrichers.honeypot import HoneypotEnricher
    path = _honeypot_file(tmp_path, [
        {"ip": "45.134.26.10", "hits": 88, "kinds": ["web", "cowrie"],
         "last_seen": "2026-08-08T08:55:00+00:00", "sample_uris": ["/.env"]},
    ])
    ctx = EnrichmentContext()
    # 45.x es IOC del día → señal fuerte; 8.8.8.8 no atacó → sin verdict
    HoneypotEnricher(data_path=path).enrich(
        {"45.134.26.10": ["FeedX"], "8.8.8.8": ["FeedY"]}, ctx)
    assert any("atacaron el honeypot" in t for _, t in ctx.notes)
    strong = [v for v in ctx.verdicts if v.ioc == "45.134.26.10"]
    assert strong and strong[0].source == "Honeypot"
    assert not any(v.ioc == "8.8.8.8" for v in ctx.verdicts)


def test_honeypot_missing_file_is_safe(tmp_path):
    from separatio.enrichers.honeypot import HoneypotEnricher
    ctx = EnrichmentContext()
    HoneypotEnricher(data_path=str(tmp_path / "nope.json")).enrich({"1.2.3.4": ["F"]}, ctx)
    assert not ctx.has_signals()


# ── MalwareBazaarEnricher (punto-5: cruce de hashes) ──

def _corpus(tmp_path, shas):
    p = tmp_path / "hashes.log"
    p.write_text("".join(f"{s}\t2026-08-08\tvm2-services\tredis\t42\t1.2.3.4\n" for s in shas))
    return str(p)


def test_malwarebazaar_no_key_is_noop(tmp_path):
    from separatio.enrichers.malwarebazaar import MalwareBazaarEnricher
    ctx = EnrichmentContext()
    MalwareBazaarEnricher(auth_keys=[], corpus_path=_corpus(tmp_path, [])).enrich(
        {"a" * 64: ["F"]}, ctx)
    assert not ctx.has_signals()


def test_malwarebazaar_hit_in_honeypot_is_strong(tmp_path, monkeypatch):
    from separatio.enrichers import malwarebazaar as mb
    h = "b" * 64
    enr = mb.MalwareBazaarEnricher(auth_keys=["k"], corpus_path=_corpus(tmp_path, [h]))
    monkeypatch.setattr(enr, "_lookup", lambda x: {
        "signature": "Mirai", "file_type": "elf",
        "first_seen": "2026-08-01 10:00:00", "tags": ["mirai", "elf"]})
    ctx = EnrichmentContext()
    enr.enrich({h: ["FeedX"], "1.2.3.4": ["F"]}, ctx)   # 1.2.3.4 no es hash → ignorado
    assert any("malware conocido" in t for _, t in ctx.notes)
    strong = [v for v in ctx.verdicts if v.ioc == h]
    assert strong and strong[0].source == "MalwareBazaar" and "Mirai" in strong[0].label


def test_malwarebazaar_known_but_not_in_honeypot_no_verdict(tmp_path, monkeypatch):
    from separatio.enrichers import malwarebazaar as mb
    h = "c" * 64
    enr = mb.MalwareBazaarEnricher(auth_keys=["k"], corpus_path=_corpus(tmp_path, []))
    monkeypatch.setattr(enr, "_lookup", lambda x: {"signature": "CobaltStrike", "file_type": "exe"})
    ctx = EnrichmentContext()
    enr.enrich({h: ["FeedX"]}, ctx)
    assert any("malware conocido" in t for _, t in ctx.notes)
    assert not ctx.verdicts     # conocido pero NO pegó a tu honeypot → sin señal fuerte


def test_malwarebazaar_unknown_hash_is_noop(tmp_path, monkeypatch):
    from separatio.enrichers import malwarebazaar as mb
    enr = mb.MalwareBazaarEnricher(auth_keys=["k"], corpus_path=_corpus(tmp_path, []))
    monkeypatch.setattr(enr, "_lookup", lambda x: None)
    ctx = EnrichmentContext()
    enr.enrich({"d" * 64: ["F"]}, ctx)
    assert not ctx.has_signals()


def test_malwarebazaar_failover_to_secondary(tmp_path, monkeypatch):
    """La primaria da 403 → usa la secundaria y resuelve."""
    from separatio.enrichers import malwarebazaar as mb
    h = "e" * 64
    calls = []

    class _Resp:
        def __init__(self, code, payload):
            self.status_code, self._p = code, payload
        def json(self):
            return self._p

    def fake_post(url, data=None, headers=None, timeout=None):
        calls.append(headers["Auth-Key"])
        if headers["Auth-Key"] == "bad":
            return _Resp(403, {})
        return _Resp(200, {"query_status": "ok",
                           "data": [{"signature": "Gafgyt", "file_type": "elf"}]})

    monkeypatch.setattr(mb.requests, "post", fake_post)
    enr = mb.MalwareBazaarEnricher(auth_keys=["bad", "good"], corpus_path=_corpus(tmp_path, [h]))
    ctx = EnrichmentContext()
    enr.enrich({h: ["F"]}, ctx)
    assert calls == ["bad", "good"]         # probó la primaria, cayó a la secundaria
    assert any(v.ioc == h for v in ctx.verdicts)
