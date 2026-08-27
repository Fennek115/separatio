"""Tests del cliente y del enricher de ANCI/CSIRT Chile — sin red.

Las fixtures son recortes de respuestas **reales** de `csirt.gob.cl/api/v1/`
capturadas el 2026-08-19, no inventadas: los casos raros que fijan (el listado
que no viene en orden de publicación, el IOC de phishing alojado en un
redirector de google.com, el `error code: 1015` de Cloudflare en texto plano) son
los que se midieron contra la API.
"""

from datetime import datetime, timedelta, timezone

import pytest

from separatio import anci_client
from separatio.analyzer import ArticleSummary
from separatio.anci_client import (Alert, AnciClient, AnciError, Document,
                                   export_iocs, parse_epss, parse_ts)
from separatio.enrichers.anci import AnciEnricher
from separatio.enrichment import EnrichmentContext, run_enrichment

AHORA = datetime(2026, 8, 19, 12, 0, tzinfo=timezone.utc)


def _fecha(dias_atras: float) -> str:
    return (AHORA - timedelta(days=dias_atras)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _alerta_api(code="ACF26-01150", dias=0.5, revision=None, **extra) -> dict:
    """Una alerta como la manda la API (campos recortados de una real)."""
    base = {
        "category": "alertas",
        "tags": ["phishing", "fraude"],
        "title": "Banco X - Campaña Fraudulenta",
        "code": code,
        "alert_class": "Alerta",
        "incident_type": "Campaña Fraudulenta",
        "tlp": "TLP:CLEAR",
        "general_description": "Campaña de fraude observada recientemente.",
        "specific_description": "Página web fraudulenta que suplanta al Banco X.",
        "date": _fecha(dias),
        "latest_revision_created_at": revision if revision else _fecha(dias),
        "affected_entities": [],
        "iocs": [{"ioc_type": "url", "value": "https://malo.example.cl/login",
                  "comment": None}],
        "evidences": [],
        "vulnerable_products": [],
        "vulnerabilities": [],
        "mitigation": "",
        "updates": [],
    }
    base.update(extra)
    return base


class _Resp:
    def __init__(self, payload=None, text="", status=200):
        self._payload, self.text, self.status_code = payload, text, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        if self._payload is None:
            raise ValueError("no es JSON")
        return self._payload


class _Api:
    """Falso transporte: devuelve páginas fijas y anota lo que se le pidió."""

    def __init__(self, pages_por_endpoint):
        self.pages = pages_por_endpoint
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, method, url, params=None, **kwargs):
        endpoint = url.rstrip("/").rsplit("/", 1)[-1]
        self.calls.append((endpoint, dict(params or {})))
        paginas = self.pages.get(endpoint, [])
        idx = int((params or {}).get("page", 1)) - 1
        if isinstance(paginas, _Resp):
            return paginas
        if idx >= len(paginas):
            return _Resp({"items": [], "count": 0})
        items = paginas[idx]
        total = sum(len(p) for p in paginas)
        size = int((params or {}).get("page_size", 100))
        return _Resp({"items": items[:size], "count": total})


@pytest.fixture
def api(monkeypatch):
    def _instalar(pages):
        fake = _Api(pages)
        monkeypatch.setattr(anci_client.net, "request_with_retry", fake)
        return fake
    return _instalar


# ─────────────────────────────────────────────────────────
# MODELOS
# ─────────────────────────────────────────────────────────

def test_from_api_tolera_campos_que_faltan_y_campos_nuevos():
    a = Alert.from_api({"code": "AVC26-1", "campo_nuevo_de_anci": 42})
    assert a.code == "AVC26-1"
    assert a.title == "" and a.iocs == () and a.vulnerabilities == ()
    assert a.published_at is None


def test_from_api_descarta_ioc_y_vuln_malformados():
    a = Alert.from_api({
        "code": "X", "iocs": ["no soy un objeto", {"ioc_type": "IPv4", "value": "1.2.3.4"}],
        "vulnerabilities": [{"source": "CVE"}, {"code": "cve-2026-1", "cvss": "9.8"}],
    })
    assert [i.value for i in a.iocs] == ["1.2.3.4"]
    assert a.iocs[0].ioc_type == "ipv4"          # normalizado a minúsculas
    assert list(a.cve_map()) == ["CVE-2026-1"]   # y el CVE a mayúsculas


def test_epss_y_timestamps():
    assert parse_epss("87.4480%") == pytest.approx(87.448)
    assert parse_epss(None) is None and parse_epss("") is None
    assert parse_epss("no-es-un-numero") is None
    # La API mezcla ambos formatos: con y sin fracción de segundo.
    assert parse_ts("2026-08-18T20:08:12.429Z").year == 2026
    assert parse_ts("2026-08-13T16:48:00Z").tzinfo is not None
    assert parse_ts("") is None and parse_ts("ayer") is None


def test_crossable_iocs_deja_fuera_lo_que_no_es_indicador():
    a = Alert.from_api({"code": "X", "iocs": [
        {"ioc_type": "url", "value": "http://malo.cl"},
        {"ioc_type": "mitre-attck", "value": "T1566.001"},
        {"ioc_type": "comando", "value": "powershell -enc ..."},
        {"ioc_type": "asunto-email", "value": "Su factura"},
    ]})
    assert [i.value for i in a.crossable_iocs()] == ["http://malo.cl"]


# ─────────────────────────────────────────────────────────
# CLIENTE
# ─────────────────────────────────────────────────────────

def test_paginado_corta_por_revision_no_por_publicacion(api):
    """El listado viene ordenado por revisión (medido). El corte tiene que mirar
    la revisión; si mirara `date` cortaría en la primera alerta vieja revisada
    ayer y se perdería lo publicado hoy que viene detrás."""
    pagina1 = [
        _alerta_api("VIEJA", dias=200, revision=_fecha(0.2)),   # revisada ayer
        _alerta_api("NUEVA", dias=0.5),                          # publicada hoy
    ]
    pagina2 = [_alerta_api("ANTIGUA", dias=400, revision=_fecha(400))]
    fake = api({"alerts": [pagina1, pagina2]})
    cli = AnciClient(page_size=2, pause=0)

    alerts = cli.alerts(since=AHORA - timedelta(days=90))
    assert [a.code for a in alerts] == ["NUEVA"]      # VIEJA se filtra por `date`
    assert len(fake.calls) == 2                        # pidió la 2ª y ahí cortó


def test_paginado_no_pide_de_mas_si_la_pagina_ya_es_vieja(api):
    fake = api({"alerts": [[_alerta_api("A", dias=200, revision=_fecha(200))]]})
    cli = AnciClient(page_size=100, pause=0)
    assert cli.alerts(since=AHORA - timedelta(days=90)) == []
    assert len(fake.calls) == 1


def test_page_size_topea_en_100(api):
    fake = api({"alerts": [[_alerta_api()]]})
    AnciClient(page_size=500, pause=0).alerts()
    assert fake.calls[0][1]["page_size"] == 100


def test_cuerpo_no_json_levanta_error_legible(monkeypatch):
    # Cloudflare responde así cuando se dispara el rate limit no documentado.
    monkeypatch.setattr(anci_client.net, "request_with_retry",
                        lambda *a, **k: _Resp(None, text="error code: 1015"))
    with pytest.raises(AnciError) as exc:
        AnciClient(pause=0).alerts()
    assert "1015" in str(exc.value) and "no-JSON" in str(exc.value)


def test_respuesta_que_no_es_objeto_levanta_error(monkeypatch):
    class _Lista(_Resp):
        def json(self): return ["no", "es", "un", "objeto"]
    monkeypatch.setattr(anci_client.net, "request_with_retry",
                        lambda *a, **k: _Lista({}))
    with pytest.raises(AnciError):
        AnciClient(pause=0).alerts()


def test_cache_fresca_evita_la_segunda_peticion(api, tmp_path):
    fake = api({"alerts": [[_alerta_api()]]})
    cli = AnciClient(pause=0, cache_dir=tmp_path, ttl={"alerts": 3600})
    assert len(cli.alerts()) == 1
    assert len(cli.alerts()) == 1
    assert len(fake.calls) == 1


def test_cache_vencida_se_vuelve_a_pedir(api, tmp_path):
    fake = api({"alerts": [[_alerta_api()]]})
    cli = AnciClient(pause=0, cache_dir=tmp_path, ttl={"alerts": 0})
    cli.alerts()
    cli.alerts()
    assert len(fake.calls) == 2


def test_cache_fail_open_a_copia_vencida(api, tmp_path, monkeypatch):
    """Si la API se cae, vale más la copia vieja que quedarse sin dato (mismo
    criterio que `LocalLists`)."""
    api({"alerts": [[_alerta_api("GUARDADA")]]})
    cli = AnciClient(pause=0, cache_dir=tmp_path, ttl={"alerts": 0})
    cli.alerts()

    def _cae(*a, **k):
        raise RuntimeError("502 Bad Gateway")
    monkeypatch.setattr(anci_client.net, "request_with_retry", _cae)
    assert [a.code for a in cli.alerts()] == ["GUARDADA"]


def test_sin_cache_previa_el_fallo_se_propaga(monkeypatch, tmp_path):
    monkeypatch.setattr(anci_client.net, "request_with_retry",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        AnciClient(pause=0, cache_dir=tmp_path).alerts()


def test_news_pagina_entero_porque_no_viene_ordenado(api):
    """La noticia más nueva estaba en la última página (medido): no se puede
    cortar antes de tiempo."""
    vieja = {"title": "vieja", "date": _fecha(300)}
    nueva = {"title": "nueva", "date": _fecha(0.5)}
    fake = api({"news": [[vieja] * 2, [nueva]]})
    cli = AnciClient(page_size=2, pause=0)
    news = cli.news(since=AHORA - timedelta(days=2))
    assert [n.title for n in news] == ["nueva"]
    assert len(fake.calls) == 2


def test_documents_filtra_por_categoria_raiz(api):
    api({"documents": [[
        {"title": "Boletín 40", "file": "/d/40.pdf", "category": "boletines/ediciones-anteriores"},
        {"title": "Guía de contraseñas", "file": "/d/g.pdf", "category": "guias/basico"},
    ]]})
    docs = AnciClient(pause=0).documents(categories=("boletines",))
    assert [d.title for d in docs] == ["Boletín 40"]
    assert Document.from_api({"category": "boletines/x"}).root_category == "boletines"


def test_events_upcoming_only(api):
    api({"events": [[
        {"title": "pasado", "starts": _fecha(100)},
        {"title": "futuro", "starts": _fecha(-30)},
    ]]})
    assert [e.title for e in AnciClient(pause=0).events(upcoming_only=True)] == ["futuro"]


def test_galleries_se_parsea(api):
    api({"galleries": [[{"title": "Fake News",
                         "gallery_images": [{"image": "http://x/1.png", "caption": "c"}]}]]})
    g = AnciClient(pause=0).galleries()[0]
    assert g.images == (("http://x/1.png", "c"),)


def test_throttle_espacia_las_peticiones(api, monkeypatch):
    """El rate limit de Cloudflare cuenta peticiones, no páginas: el throttle
    tiene que aplicar también al saltar de un endpoint a otro."""
    dormido = []
    monkeypatch.setattr(anci_client.time, "sleep", dormido.append)
    # `_get` mira el reloj dos veces: antes de pedir y al anotar la petición.
    reloj = iter([1000.0, 1000.0, 1000.5, 1000.5, 1001.0, 1001.0])
    monkeypatch.setattr(anci_client.time, "monotonic", lambda: next(reloj))

    api({"alerts": [[_alerta_api("A")], [_alerta_api("B")]],
         "news": [[{"title": "n", "date": _fecha(0.1)}]]})
    cli = AnciClient(page_size=1, pause=2.0, max_pages=2)
    cli.alerts()
    cli.news()
    assert cli.requests_made == 3
    # La primera no espera (nadie pidió antes); las otras dos completan los 2 s
    # desde la anterior, incluida la que cambia de endpoint.
    assert dormido == [1.5, 1.5]


def test_tope_de_paginas(api):
    fake = api({"alerts": [[_alerta_api(f"A{i}")] for i in range(10)]})
    AnciClient(page_size=1, pause=0, max_pages=3).alerts()
    assert len(fake.calls) == 3


# ─────────────────────────────────────────────────────────
# VOLCADO LOCAL
# ─────────────────────────────────────────────────────────

def test_export_dedup_por_code_y_value(tmp_path):
    repetida = {"ioc_type": "ipv4", "value": "1.2.3.4"}
    alerts = [
        Alert.from_api(_alerta_api("A", iocs=[repetida, dict(repetida), {"ioc_type": "dominio", "value": "malo.cl"}])),
        Alert.from_api(_alerta_api("B", iocs=[repetida])),   # otra alerta: sí cuenta
    ]
    paths = export_iocs(alerts, tmp_path)
    filas = open(paths["csv"], encoding="utf-8").read().strip().splitlines()
    assert len(filas) == 4                       # cabecera + 3 filas
    assert open(paths["ips"], encoding="utf-8").read() == "1.2.3.4\n"
    assert open(paths["domains"], encoding="utf-8").read() == "malo.cl\n"
    assert open(paths["urls"], encoding="utf-8").read() == ""


# ─────────────────────────────────────────────────────────
# ENRICHER
# ─────────────────────────────────────────────────────────

class _Cliente:
    """Cliente falso: devuelve alertas ya parseadas."""

    def __init__(self, alerts=(), news=(), documents=(), falla_news=False):
        self._alerts = [Alert.from_api(a) if isinstance(a, dict) else a for a in alerts]
        self._news, self._documents = list(news), list(documents)
        self.falla_news = falla_news

    def alerts(self, since=None):
        return sorted(self._alerts, key=lambda a: a.date, reverse=True)

    def news(self, since=None):
        if self.falla_news:
            raise RuntimeError("429 Too Many Requests")
        return self._news

    def documents(self, categories=None):
        return [Document.from_api(d) if isinstance(d, dict) else d
                for d in self._documents]


def _enricher(cliente, tmp_path, **kw):
    kw.setdefault("export", False)
    kw.setdefault("max_news", 0)
    kw.setdefault("doc_categories", ())
    return AnciEnricher(cliente, state_dir=str(tmp_path), **kw)


def _notas(ctx):
    return [t for _, t in ctx.notes]


def test_notas_solo_de_la_ventana(tmp_path):
    cli = _Cliente([_alerta_api("HOY", dias=0.2),
                    _alerta_api("SEMANA-PASADA", dias=6)])
    ctx = EnrichmentContext()
    _enricher(cli, tmp_path).enrich({}, ctx)
    texto = "\n".join(_notas(ctx))
    assert "HOY" in texto and "SEMANA-PASADA" not in texto
    assert "CC BY-SA 4.0" in texto        # la atribución que exige la licencia


def test_ventana_semanal_alcanza_la_alerta_de_hace_seis_dias(tmp_path):
    cli = _Cliente([_alerta_api("SEMANA-PASADA", dias=6)])
    ctx = EnrichmentContext()
    _enricher(cli, tmp_path, lookback_hours=24 * 7).enrich({}, ctx)
    assert "SEMANA-PASADA" in "\n".join(_notas(ctx))


def test_veredicto_por_valor_exacto(tmp_path):
    cli = _Cliente([_alerta_api("ACF26-1", iocs=[
        {"ioc_type": "ipv4", "value": "45.148.10.152"}])])
    ctx = EnrichmentContext()
    _enricher(cli, tmp_path).enrich({"45.148.10.152": ["FeedA"]}, ctx)
    assert len(ctx.verdicts) == 1
    v = ctx.verdicts[0]
    assert v.kind == "ip" and v.source == "CSIRT Chile (ANCI)"
    assert "ACF26-1" in v.detail and "Campaña Fraudulenta" in v.label


def test_ip_que_cruza_arrastra_la_nota_de_cautela(tmp_path):
    """Medido sobre el volcado real: 17 de 42 IPs de ANCI son de Cloudflare —
    son la IP del alojamiento del phishing, no la del atacante."""
    cli = _Cliente([_alerta_api("A", iocs=[{"ioc_type": "ipv4", "value": "104.21.76.34"}])])
    ctx = EnrichmentContext()
    _enricher(cli, tmp_path).enrich({"104.21.76.34": ["FeedA"]}, ctx)
    assert ctx.verdicts[0].label.startswith("figura en alerta")
    assert any("ALOJAMIENTO" in t for t in _notas(ctx))


def test_sin_ips_que_crucen_no_hay_nota_de_cautela(tmp_path):
    cli = _Cliente([_alerta_api("A", iocs=[{"ioc_type": "dominio", "value": "malo.cl"}])])
    ctx = EnrichmentContext()
    _enricher(cli, tmp_path).enrich({"malo.cl": ["FeedA"]}, ctx)
    assert len(ctx.verdicts) == 1
    assert not any("ALOJAMIENTO" in t for t in _notas(ctx))


def test_no_cruza_por_host_de_la_url(tmp_path):
    """Caso real (ACF26-01147): el IOC de una campaña de phishing es un
    redirector de google.com. Indexar el host diría "google.com está en una
    alerta del CSIRT", que es falso."""
    cli = _Cliente([_alerta_api("ACF26-01147", iocs=[
        {"ioc_type": "url",
         "value": "https://www.google.com/share.google?q=WLtCl3x3ywT1O5yOs"}])])
    ctx = EnrichmentContext()
    _enricher(cli, tmp_path).enrich(
        {"google.com": ["FeedA"], "www.google.com": ["FeedB"]}, ctx)
    assert ctx.verdicts == []


def test_ioc_defangeado_del_articulo_cruza_igual(tmp_path):
    cli = _Cliente([_alerta_api("A", iocs=[{"ioc_type": "dominio", "value": "Malo.CL"}])])
    ctx = EnrichmentContext()
    # `collect_iocs` ya normaliza: `malo[.]cl` llega como `malo.cl`.
    _enricher(cli, tmp_path).enrich({"malo.cl": ["FeedA"]}, ctx)
    assert len(ctx.verdicts) == 1


def test_tipos_no_cruzables_no_generan_veredicto(tmp_path):
    cli = _Cliente([_alerta_api("A", iocs=[
        {"ioc_type": "mitre-attck", "value": "T1566.001"}])])
    ctx = EnrichmentContext()
    _enricher(cli, tmp_path).enrich({"T1566.001": ["FeedA"]}, ctx)
    assert ctx.verdicts == []


def test_cruce_de_cves_ordena_por_epss_y_recorta(tmp_path):
    vulns = [
        {"code": "CVE-2026-1", "source": "CVE", "cvss": "5.5", "epss": None},
        {"code": "CVE-2026-2", "source": "CVE", "cvss": "9.8", "epss": "87.4480%"},
        {"code": "CVE-2026-3", "source": "CVE", "cvss": "7.8", "epss": "1.1000%"},
    ]
    cli = _Cliente([_alerta_api("AVC26-00728", dias=7,
                                title="Microsoft Patch Tuesday 2026 Agosto",
                                incident_type="Vulnerabilidad Crítica",
                                vulnerabilities=vulns)])
    ctx = EnrichmentContext()
    ctx.cves = {"CVE-2026-1", "CVE-2026-2", "CVE-2026-3", "CVE-2099-9"}
    _enricher(cli, tmp_path, max_cves_per_alert=2).enrich({}, ctx)

    nota = [t for t in _notas(ctx) if "AVC26-00728" in t][0]
    assert "cubre 3 CVE(s)" in nota
    assert nota.index("CVE-2026-2") < nota.index("CVE-2026-3")   # por EPSS desc
    assert "EPSS 87.4%" in nota and "CVSS 9.8" in nota
    assert "CVE-2026-1" not in nota and "(+1 más)" in nota
    assert "CVE-2099-9" not in nota                              # no es de ANCI


def test_sin_cves_del_dia_no_hay_nota_de_cves(tmp_path):
    cli = _Cliente([_alerta_api("AVC", dias=7, vulnerabilities=[
        {"code": "CVE-2026-2", "source": "CVE"}])])
    ctx = EnrichmentContext()          # ctx.cves vacío
    _enricher(cli, tmp_path).enrich({}, ctx)
    assert not any("cubre" in t for t in _notas(ctx))


def test_documentos_primera_corrida_fija_linea_base(tmp_path):
    docs = [{"title": "Boletín 39", "file": "/d/39.pdf", "category": "boletines/x"}]
    cli = _Cliente([], documents=docs)
    ctx = EnrichmentContext()
    _enricher(cli, tmp_path, doc_categories=("boletines",)).enrich({}, ctx)
    assert _notas(ctx) == []           # no vomita los 300 históricos

    cli._documents.append({"title": "Boletín 40", "file": "/d/40.pdf",
                           "category": "boletines/x"})
    ctx2 = EnrichmentContext()
    _enricher(cli, tmp_path, doc_categories=("boletines",)).enrich({}, ctx2)
    assert len(_notas(ctx2)) == 1 and "Boletín 40" in _notas(ctx2)[0]


def test_noticias_caidas_no_tiran_las_alertas(tmp_path):
    cli = _Cliente([_alerta_api("HOY", dias=0.2)], falla_news=True)
    ctx = EnrichmentContext()
    _enricher(cli, tmp_path, max_news=5).enrich({}, ctx)
    assert any("HOY" in t for t in _notas(ctx))


def test_corpus_vacio_no_hace_nada(tmp_path):
    ctx = EnrichmentContext()
    _enricher(_Cliente([]), tmp_path).enrich({"1.2.3.4": ["FeedA"]}, ctx)
    assert not ctx.has_signals()


def test_export_escribe_el_volcado_local(tmp_path):
    cli = _Cliente([_alerta_api("A", iocs=[{"ioc_type": "ipv4", "value": "1.2.3.4"}])])
    ctx = EnrichmentContext()
    AnciEnricher(cli, state_dir=str(tmp_path), export=True,
                 export_dir=str(tmp_path), max_news=0,
                 doc_categories=()).enrich({}, ctx)
    assert (tmp_path / "anci-iocs.csv").exists()
    assert (tmp_path / "anci-ips.txt").read_text(encoding="utf-8") == "1.2.3.4\n"


# ─────────────────────────────────────────────────────────
# ctx.cves (el cambio aditivo en enrichment.py)
# ─────────────────────────────────────────────────────────

def test_run_enrichment_puebla_las_cves_del_dia():
    summaries = [
        ArticleSummary(article_id=1, title="t", url="u", feed_title="F",
                       feed_category="Vulnerability", published_at="",
                       iocs=["1.2.3.4"], cves=["cve-2026-1", " CVE-2026-2 "]),
        ArticleSummary(article_id=2, title="t", url="u", feed_title="F",
                       feed_category="Vulnerability", published_at="",
                       iocs=["5.6.7.8"], cves=[]),
    ]
    ctx = run_enrichment(summaries, [])
    assert ctx.cves == {"CVE-2026-1", "CVE-2026-2"}


def test_contexto_nuevo_nace_sin_cves():
    assert EnrichmentContext().cves == set()
