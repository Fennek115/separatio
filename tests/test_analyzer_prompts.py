"""Tests de los prompts (F-I del rework) — deterministas, sin red ni LLM.

Lo que fijan, en orden de importancia:

1. Que el informe **sepa lo que no tiene**: el bloque de cobertura sale del
   manifiesto de F-H y nombra las fuentes caídas y los recortes reales.
2. Que una corrida limpia NO inyecte el bloque — declarar faltantes que no
   existen es tan malo como callar los que sí.
3. Que los topes salgan de `config.PROMPT_CAPS` y no de constantes de módulo.
4. Que el enrichment llegue a las cuatro fases y la correlación no se filtre
   donde no sirve (la regresión concreta del cambio 3).
"""

import json

import pytest

from separatio import config, runlog
from separatio.analyzer import (
    ARTICLE_SUMMARY_SCHEMA,
    ArticleSummary,
    build_general_prompt,
    build_latam_prompt,
    build_threat_prompt,
    build_vuln_prompt,
)
from separatio.correlator import CorrelationContext, build_correlation_context
from separatio.enrichment import EnrichmentContext, IocVerdict


@pytest.fixture(autouse=True)
def sin_corrida_previa():
    runlog.reset()
    yield
    runlog.reset()


def _summary(**kw) -> ArticleSummary:
    base = dict(article_id=1, title="t", url="u", feed_title="f",
                feed_category="c", published_at="2026-08-09",
                severity="Alta", severity_score=4, summary="s")
    base.update(kw)
    return ArticleSummary(**base)


def _enrichment(n: int = 1) -> EnrichmentContext:
    ctx = EnrichmentContext()
    for i in range(n):
        ctx.add(IocVerdict(ioc=f"10.9.9.{i}", kind="ip",
                           source="IPsum", label="blocklist"))
    return ctx


def _correlation() -> CorrelationContext:
    return CorrelationContext(kev_active_cves=["CVE-2026-1111"])


# ── 1. El bloque de cobertura ───────────────────────────────

def test_bloque_de_cobertura_lista_las_fuentes_caidas():
    runlog.start_run("2026-08-09", "full")
    runlog.record_source("IPsum", "ok")
    runlog.record_source("OpenPhish", "failed: Timeout: feed no responde")

    bloque = runlog.coverage_block("vulnerability")

    assert "OpenPhish" in bloque
    assert "FALLÓ" in bloque
    # Lo que hace útil el bloque: nombra QUÉ deja de estar cubierto.
    assert "phishing" in bloque
    assert "PARCIAL" in bloque
    assert "no se pudo verificar" in bloque


def test_bloque_de_cobertura_distingue_omitida_de_caida():
    """Una fuente sin key no falló: no se consultó. Son problemas distintos y
    el informe no puede tratarlos igual."""
    runlog.start_run("2026-08-09", "full")
    runlog.record_source("MalwareBazaar", "skipped: sin ABUSECH_API_KEY")

    bloque = runlog.coverage_block()

    assert "OMITIDA MalwareBazaar" in bloque
    assert "familias de malware por hash" in bloque


def test_bloque_de_cobertura_lista_los_recortes():
    runlog.start_run("2026-08-09", "full")
    runlog.record_drop("analyzer._format_phase_items", shown=35, total=78,
                       detail="vulnerability")
    runlog.record_drop("enrichment.format_for_prompt", shown=60, total=103,
                       detail="IPsum")

    bloque = runlog.coverage_block("vulnerability")

    assert "35 de 78 artículos" in bloque
    assert "43 veredictos de reputación" in bloque


def test_el_bloque_de_una_fase_no_declara_recortes_de_otra():
    """Decirle al analista de LATAM que la fase de vulnerabilidades recortó 43
    artículos es ruido: no cambia nada de lo que tiene que escribir."""
    runlog.start_run("2026-08-09", "full")
    runlog.record_drop("analyzer._format_phase_items", shown=35, total=78,
                       detail="vulnerability")

    assert "78" in runlog.coverage_block("vulnerability")
    assert runlog.coverage_block("latam") == ""
    assert "78" in runlog.coverage_block()          # la síntesis ve todo


def test_sin_faltantes_no_se_inyecta_el_bloque():
    runlog.start_run("2026-08-09", "full")
    runlog.record_source("IPsum", "ok")
    runlog.record_source("OpenPhish", "ok")

    bloque = runlog.coverage_block("vulnerability")

    # Con todas las fuentes OK el bloque informa cobertura pero NO regla ni
    # faltantes; sin fuentes ni recortes de ningún tipo, no hay bloque.
    assert "2 fuentes OK" in bloque
    runlog.reset()
    runlog.start_run("2026-08-09", "full")
    assert runlog.coverage_block("vulnerability") == ""


def test_sin_corrida_activa_el_bloque_es_vacio():
    """El no-op de F-H: los prompts se pueden construir fuera de una corrida."""
    assert runlog.coverage_block() == ""
    # La REGLA sobre el bloque está siempre en el prompt (y contempla el caso
    # "sin faltantes"); lo que no puede aparecer es el bloque en sí.
    assert "lo que este análisis SÍ y NO tiene" not in \
        build_latam_prompt([_summary()], "2026-08-09")


def test_el_bloque_llega_al_prompt_de_la_fase():
    runlog.start_run("2026-08-09", "full")
    runlog.record_source("OpenPhish", "failed: Timeout")

    prompt = build_vuln_prompt([_summary()], "2026-08-09")

    assert "COBERTURA DE ESTA CORRIDA" in prompt
    assert "OpenPhish" in prompt
    # Y el informe tiene que declararlo, no sólo saberlo.
    assert "Limitaciones de esta corrida" in prompt


# ── 2. Los topes ────────────────────────────────────────────

def test_los_topes_salen_de_config(monkeypatch):
    art = _summary(iocs=[f"10.0.0.{i}" for i in range(30)])

    monkeypatch.setitem(config.PROMPT_CAPS, "iocs_per_article", 3)
    assert build_latam_prompt([art], "2026-08-09").count("10.0.0.") == 3

    monkeypatch.setitem(config.PROMPT_CAPS, "iocs_per_article", 25)
    assert build_latam_prompt([art], "2026-08-09").count("10.0.0.") == 25


def test_el_tope_de_veredictos_sale_de_config(monkeypatch):
    monkeypatch.setitem(config.PROMPT_CAPS, "verdicts_per_source", 4)
    prompt = build_latam_prompt([_summary()], "2026-08-09",
                                enrichment=_enrichment(10))
    assert prompt.count("10.9.9.") == 4


# ── 3. Enrichment a las cuatro fases (cambio 3) ─────────────

@pytest.mark.parametrize("builder", [
    lambda e: build_vuln_prompt([_summary()], "2026-08-09", enrichment=e),
    lambda e: build_threat_prompt([_summary()], "2026-08-09", enrichment=e),
    lambda e: build_latam_prompt([_summary()], "2026-08-09", enrichment=e),
    lambda e: build_general_prompt([_summary()], "2026-08-09", enrichment=e),
])
def test_enrichment_llega_a_las_cuatro_fases(builder):
    assert "10.9.9.0" in builder(_enrichment())


def test_correlacion_no_llega_a_latam():
    """La contraparte: KEV/EPSS en el prompt de LATAM es ruido. `build_latam_prompt`
    no acepta correlación siquiera — esto fija que siga siendo así."""
    corr = _correlation()
    assert "CVE-2026-1111" in build_vuln_prompt([_summary()], "2026-08-09", corr)
    assert "CVE-2026-1111" not in build_latam_prompt([_summary()], "2026-08-09")
    assert "CVE-2026-1111" not in build_general_prompt([_summary()], "2026-08-09")


# ── 4. Campos estructurados nuevos (cambio 4) ───────────────

def test_cache_viejo_sin_campos_nuevos_carga():
    """`--report-only` sobre el caché de ayer no puede explotar."""
    viejo = {
        "article_id": 1, "title": "t", "url": "u", "feed_title": "f",
        "feed_category": "c", "published_at": "2026-08-08",
        "threat_type": "CVE", "severity": "Alta", "severity_score": 4,
        "actors": [], "cves": [], "affected_systems": [], "summary": "s",
        "iocs": [], "error": None,
    }
    known = ArticleSummary.__dataclass_fields__
    s = ArticleSummary(**{k: v for k, v in viejo.items() if k in known})

    assert s.attack_techniques == []
    assert s.exploitation_status == "unknown"
    assert s.confidence == "media"
    # Y un prompt construido con él no revienta ni imprime basura.
    assert "ATT&CK" not in build_latam_prompt([s], "2026-08-08")


def test_tecnicas_corroboradas_entre_fuentes(monkeypatch):
    monkeypatch.setattr("separatio.correlator.get_with_retry",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("sin red")))
    arts = [
        _summary(feed_title="Medio A", attack_techniques=["T1566.001", "T1059"]),
        _summary(feed_title="Medio B", attack_techniques=["t1566.001 — Phishing"]),
        _summary(feed_title="Medio C", attack_techniques=["Phishing"]),
    ]
    ctx = build_correlation_context(arts)

    assert "T1566.001" in ctx.corroborated_techniques        # 2 fuentes
    assert "T1059" not in ctx.corroborated_techniques        # 1 sola fuente
    assert "PHISHING" not in ctx.corroborated_techniques     # no es un ID
    assert "T1566.001" in ctx.format_for_prompt()


def test_campos_nuevos_llegan_al_prompt():
    art = _summary(attack_techniques=["T1486"], exploitation_status="active")
    prompt = build_threat_prompt([art], "2026-08-09")
    assert "T1486" in prompt
    assert "explotación activa" in prompt


def test_confianza_baja_se_marca_y_la_normal_no():
    normal = build_threat_prompt([_summary(confidence="alta")], "2026-08-09")
    baja   = build_threat_prompt([_summary(confidence="baja")], "2026-08-09")
    assert "Confianza" not in normal
    assert "BAJA" in baja


# ── 5. El esquema de salida estructurada (cambio 5) ─────────

def test_esquema_json_es_valido():
    """Los dos requisitos que la API impone y que es fácil olvidar."""
    assert ARTICLE_SUMMARY_SCHEMA["additionalProperties"] is False
    props = set(ARTICLE_SUMMARY_SCHEMA["properties"])
    assert set(ARTICLE_SUMMARY_SCHEMA["required"]) == props
    # Serializable tal cual va al cuerpo de la petición.
    json.dumps(ARTICLE_SUMMARY_SCHEMA)


def test_el_esquema_cubre_los_campos_del_dataclass():
    """Si mañana alguien agrega un campo al prompt y no al esquema, la salida
    estructurada lo deja fuera en silencio."""
    campos = set(ARTICLE_SUMMARY_SCHEMA["properties"])
    del_dataclass = set(ArticleSummary.__dataclass_fields__)
    assert campos <= del_dataclass
    for nuevo in ("attack_techniques", "exploitation_status", "confidence"):
        assert nuevo in campos


# ── 6. Effort (cambio 6) ────────────────────────────────────

def test_haiku_nunca_recibe_effort():
    """Haiku 4.5 devuelve 400 si se le pasa `effort`; Sonnet/Opus lo aceptan."""
    from separatio.analyzer import _effort_for

    assert _effort_for("latam", "claude-haiku-4-5-20251001") is None
    assert _effort_for("vulnerability", "claude-haiku-4-5-20251001") is None
    assert _effort_for("vulnerability", "claude-sonnet-5") == \
        config.PHASE_EFFORT["vulnerability"]
    assert _effort_for("synthesis", "claude-opus-5") == config.PHASE_EFFORT["synthesis"]
    assert _effort_for("latam", "claude-sonnet-5") is None   # no está en PHASE_EFFORT
