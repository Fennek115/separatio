"""Tests del manifiesto de la corrida (F-H del rework) — deterministas, sin red.

Los dos últimos son los que importan: verifican que el recorte REAL del pipeline
—el de enrichment y el de IOCs por artículo— queda registrado con sus números.
Un manifiesto que sólo funciona cuando lo llaman los tests no sirve de nada.
"""

import json

import pytest

from separatio import runlog
from separatio.analyzer import ArticleSummary, _format_phase_items
from separatio.enrichment import EnrichmentContext, IocVerdict


@pytest.fixture(autouse=True)
def sin_corrida_previa():
    """Cada test arranca sin manifiesto activo y no le deja uno al siguiente."""
    runlog.reset()
    yield
    runlog.reset()


def _verdict(ioc: str, source: str = "IPsum") -> IocVerdict:
    return IocVerdict(ioc=ioc, kind="ip", source=source, label="blocklist")


def _summary(**kw) -> ArticleSummary:
    base = dict(article_id=1, title="t", url="u", feed_title="f",
                feed_category="c", published_at="2026-08-09")
    base.update(kw)
    return ArticleSummary(**base)


# ── el no-op ────────────────────────────────────────────────

def test_sin_start_run_las_llamadas_son_noop():
    runlog.record_drop("donde", 1, 10, detail="x")
    runlog.record_llm("stage3", "m", 10, 20, "end_turn", 100, 1.0)
    runlog.record_failure("enricher:X", ValueError("boom"))
    runlog.record_stage("stage1", True, 1.0)
    runlog.record_count("articulos_tomados", 5)
    runlog.record_source("IPsum", "ok")
    runlog.record_report({"md": "/tmp/x.md"})

    m = runlog.current()
    assert not m                      # el no-op es falsy
    assert m.totals()["datos_omitidos"] == 0
    assert m.exit_code() == 0
    # y al arrancar una corrida de verdad no arrastra nada
    real = runlog.start_run("2026-08-09", "full")
    assert real.drops == [] and real.llm_calls == []


# ── acumulación ─────────────────────────────────────────────

def test_record_drop_acumula():
    runlog.start_run("2026-08-09", "full")
    runlog.record_drop("enrichment.format_for_prompt", 25, 63, detail="IPsum")
    runlog.record_drop("enrichment.format_for_prompt", 25, 30, detail="ipcheck")
    runlog.record_drop("enrichment.format_for_prompt", 25, 40, detail="OpenPhish")

    m = runlog.current()
    assert len(m.drops) == 3
    assert {d.detail for d in m.drops} == {"IPsum", "ipcheck", "OpenPhish"}
    assert m.totals()["datos_omitidos"] == 38 + 5 + 15


def test_drop_registra_shown_y_total():
    runlog.start_run("2026-08-09", "full")
    runlog.record_drop("enrichment.format_for_prompt", 25, 68, detail="IPsum")
    d = runlog.current().drops[0]
    assert (d.shown, d.total, d.omitted) == (25, 68, 43)


def test_drop_sin_recorte_no_se_registra():
    runlog.start_run("2026-08-09", "full")
    runlog.record_drop("enrichment.format_for_prompt", 25, 25, detail="IPsum")
    runlog.record_drop("enrichment.format_for_prompt", 25, 3, detail="ipcheck")
    assert runlog.current().drops == []


def test_totales_de_tokens():
    runlog.start_run("2026-08-09", "full")
    runlog.record_llm("stage2", "haiku", 1000, 200, "end_turn", 900, 1.2)
    runlog.record_llm("phase:vulnerability", "sonnet", 20000, 16000, "max_tokens", 16000, 40.0)
    runlog.record_llm("synthesis", "opus", 5000, 900, "end_turn", 4000, 12.0)

    t = runlog.current().totals()
    assert t["in_tokens"] == 26000
    assert t["out_tokens"] == 17100
    assert t["llamadas"] == 3
    assert t["truncadas"] == 1


# ── status y exit code ──────────────────────────────────────

def test_status_ok_sin_fallos(tmp_path):
    runlog.start_run("2026-08-09", "full")
    runlog.record_stage("stage3_phases", True, 10.0)
    runlog.record_source("IPsum", "ok")
    runlog.record_report({"md": str(tmp_path / "r.md")})
    m = runlog.finish_run(tmp_path / "run-manifest.json")
    assert m.status == "ok"
    assert m.exit_code() == 0


def test_status_degraded_con_fuente_caida(tmp_path):
    runlog.start_run("2026-08-09", "full")
    runlog.record_stage("stage3_phases", True, 10.0)
    runlog.record_source("IPsum", "ok")
    runlog.record_source("OpenPhish", "failed: InvalidURL: Invalid IPv6 URL")
    runlog.record_failure("enricher:OpenPhish", ValueError("Invalid IPv6 URL"))
    runlog.record_report({"md": str(tmp_path / "r.md")})
    m = runlog.finish_run(tmp_path / "run-manifest.json")
    assert m.status == "degraded"
    assert m.exit_code() == 0          # a propósito: el timer no debe ponerse rojo
    assert m.failures[0].error_type == "ValueError"


def test_status_failed_sin_informe(tmp_path):
    runlog.start_run("2026-08-09", "full")
    runlog.record_stage("stage1", True, 5.0)
    runlog.record_stage("stage3_phases", False, 2.0, error="RuntimeError: boom")
    m = runlog.finish_run(tmp_path / "run-manifest.json")
    assert m.status == "failed"
    assert m.exit_code() == 1


def test_sin_articulos_es_degraded_no_failed(tmp_path):
    """Un día sin artículos nuevos no generó informe, pero no es un fallo."""
    runlog.start_run("2026-08-09", "full")
    runlog.record_stage("stage1", True, 3.0)
    runlog.expect_no_report("sin artículos nuevos en Miniflux")
    m = runlog.finish_run(tmp_path / "run-manifest.json")
    assert m.status == "degraded"
    assert m.exit_code() == 0


def test_fuente_omitida_por_falta_de_key_degrada(tmp_path):
    """Una fuente habilitada que no consulta nada (sin key) no puede pasar por
    'ok': el informe saldría como si esa fuente hubiera dicho 'nada que ver'."""
    runlog.start_run("2026-08-09", "full")
    runlog.record_source("MalwareBazaar", "skipped: sin ABUSECH_API_KEY")
    runlog.record_source("MalwareBazaar", "ok")        # run_enrichment no lo pisa
    runlog.record_stage("stage3_phases", True, 10.0)
    runlog.record_report({"md": str(tmp_path / "r.md")})
    m = runlog.finish_run(tmp_path / "run-manifest.json")

    assert m.sources["MalwareBazaar"] == "skipped: sin ABUSECH_API_KEY"
    assert m.status == "degraded"
    assert "OMITIDA: MalwareBazaar — sin ABUSECH_API_KEY" in m.summary_text()


def test_salida_truncada_degrada_la_corrida(tmp_path):
    runlog.start_run("2026-08-09", "full")
    runlog.record_stage("stage3_phases", True, 10.0)
    runlog.record_llm("phase:vulnerability", "sonnet", 100, 16000, "max_tokens", 16000, 9.0)
    runlog.record_report({"md": str(tmp_path / "r.md")})
    m = runlog.finish_run(tmp_path / "run-manifest.json")
    assert m.status == "degraded"


# ── persistencia ────────────────────────────────────────────

def test_manifiesto_se_escribe_atomico(tmp_path):
    path = tmp_path / "run-manifest.json"
    runlog.start_run("2026-08-09", "full")
    runlog.record_drop("enrichment.format_for_prompt", 25, 63, detail="IPsum")
    runlog.finish_run(path)

    assert path.exists()
    assert list(tmp_path.glob("*.tmp")) == []      # no quedan temporales
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["drops"][0]["total"] == 63
    assert data["totals"]["datos_omitidos"] == 38
    assert data["finished_at"]


def test_manifiesto_es_json_valido_con_acentos(tmp_path):
    path = tmp_path / "run-manifest.json"
    runlog.start_run("2026-08-09", "full")
    runlog.record_failure("enricher:Ransomware.live", RuntimeError("límite de cuota excedido"))
    runlog.finish_run(path)

    crudo = path.read_text(encoding="utf-8")
    assert "límite de cuota excedido" in crudo     # ensure_ascii=False
    recargado = runlog.load_manifest(path)
    assert recargado.failures[0].message == "límite de cuota excedido"
    assert recargado.status == "degraded"


def test_resumen_lista_los_drops(tmp_path):
    runlog.start_run("2026-08-09", "full")
    runlog.record_count("articulos_pool", 600)
    runlog.record_count("articulos_tomados", 120)
    runlog.record_count("articulos_resumidos", 116)
    runlog.record_count("articulos_fallidos", 4)
    runlog.record_drop("enrichment.format_for_prompt", 25, 63, detail="IPsum")
    runlog.record_drop("analyzer._format_phase_items.iocs", 8, 12, detail="art 42")
    runlog.record_source("OpenPhish", "failed: InvalidURL: Invalid IPv6 URL")
    runlog.record_llm("synthesis", "opus", 5000, 900, "end_turn", 4000, 12.0)
    runlog.record_report({"md": str(tmp_path / "r.md")})
    m = runlog.finish_run(tmp_path / "run-manifest.json")

    texto = m.summary_text()
    assert "RESUMEN DE LA CORRIDA — 2026-08-09  [degraded]" in texto
    assert "600 en el pool → 120 tomados → 116 resumidos, 4 fallidos" in texto
    assert "38 veredictos de enrichment recortados (IPsum 25/63)" in texto
    assert "4 IOCs recortados" in texto
    assert "FALLIDA: OpenPhish — InvalidURL: Invalid IPv6 URL" in texto


def test_last_run_lee_el_mas_reciente(tmp_path):
    for date, mode in (("2026-08-07", "full"), ("2026-08-09", "report-only")):
        d = tmp_path / date
        d.mkdir()
        runlog.start_run(date, mode)
        runlog.finish_run(d / runlog.MANIFEST_NAME)
        # started_at se toma del reloj: para desempatar, se fija a mano.
        raw = json.loads((d / runlog.MANIFEST_NAME).read_text())
        raw["started_at"] = f"{date}T07:00:00"
        (d / runlog.MANIFEST_NAME).write_text(json.dumps(raw), encoding="utf-8")

    ultimo = runlog.find_latest_manifest(tmp_path)
    assert ultimo.parent.name == "2026-08-09"
    assert runlog.load_manifest(ultimo).mode == "report-only"


def test_find_latest_sin_manifiestos(tmp_path):
    assert runlog.find_latest_manifest(tmp_path) is None


# ── integración con el recorte real ─────────────────────────

def test_format_for_prompt_registra_el_recorte():
    """30 veredictos de una fuente ⇒ un Drop(shown=25, total=30)."""
    runlog.start_run("2026-08-09", "full")
    ctx = EnrichmentContext()
    for i in range(30):
        ctx.add(_verdict(f"10.0.0.{i}"))
    bloque = ctx.format_for_prompt()

    drops = [d for d in runlog.current().drops
             if d.where == "enrichment.format_for_prompt"]
    assert len(drops) == 1
    assert (drops[0].shown, drops[0].total, drops[0].detail) == (25, 30, "IPsum")
    assert bloque.count("10.0.0.") == 25      # y el prompt efectivamente lleva 25


def test_format_phase_items_registra_iocs_recortados():
    """Un artículo con 12 IOCs ⇒ un Drop(shown=8, total=12)."""
    runlog.start_run("2026-08-09", "full")
    art = _summary(iocs=[f"10.0.0.{i}" for i in range(12)])
    _top, items = _format_phase_items([art], article_limit=50, phase="vulnerability")

    drops = [d for d in runlog.current().drops
             if d.where == "analyzer._format_phase_items.iocs"]
    assert len(drops) == 1
    assert (drops[0].shown, drops[0].total) == (8, 12)
    assert items[0].count("10.0.0.") == 8


def test_format_phase_items_registra_articulos_recortados():
    runlog.start_run("2026-08-09", "full")
    arts = [_summary(article_id=i) for i in range(30)]
    _format_phase_items(arts, article_limit=20, phase="threat_intel")

    drops = [d for d in runlog.current().drops
             if d.where == "analyzer._format_phase_items"]
    assert (drops[0].shown, drops[0].total, drops[0].detail) == (20, 30, "threat_intel")


def test_truncate_text_registra_el_truncado():
    from separatio.extractor import truncate_text

    runlog.start_run("2026-08-09", "full")
    texto = "x" * 5000
    assert truncate_text(texto, max_tokens_approx=100) != texto

    drops = [d for d in runlog.current().drops if d.where == "extractor.truncate_text"]
    assert (drops[0].shown, drops[0].total, drops[0].kind) == (400, 5000, "truncate")


def test_trending_registra_recorte_de_actores():
    from separatio.history import TrendingContext

    runlog.start_run("2026-08-09", "full")
    ctx = TrendingContext(window_days=14, days_with_data=10,
                          returning_actors={f"APT{i}": 3 for i in range(12)})
    ctx.format_for_prompt()

    drops = [d for d in runlog.current().drops if d.where == "history.format_for_prompt"]
    assert (drops[0].shown, drops[0].total) == (8, 12)
