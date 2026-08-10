"""Fija el comportamiento de las funciones que llaman al LLM en `analyzer.py`
tras el refactor de proveedores (F-G/G-5) — antes de esta fase ninguna estaba
cubierta (ni `_llm_chat`, ni el streaming de Ollama, ni el dispatch por
proveedor).

Usa un `FakeProvider` en vez de los SDKs reales: lo que se fija acá es que
`analyzer.py` sigue llamando al proveedor con los mismos parámetros, logueando
los mismos mensajes y —el punto más importante del refactor— **preservando el
quirk existente**: `generate_report` nunca llamó `_log_usage` en la rama
Ollama (no hay `runlog.record_llm` para esa llamada) mientras que
`generate_phase_report` sí. Ese quirk está documentado como deuda en
`docs/fases/F-G.md` — el refactor no lo podía tocar sin cambiar la salida."""

import pytest

from separatio import analyzer, runlog
from separatio.providers import ChatResult


class FakeProvider:
    """Devuelve un `ChatResult` fijo (o levanta) y registra cómo lo llamaron."""

    def __init__(self, result=None, raises=None, stream_chunks=None):
        self._result = result or ChatResult(text="  # Informe\n\ntexto  ",
                                            in_tok=100, out_tok=50, finish="stop")
        self._raises = raises
        self.chat_calls: list[dict] = []
        self.chat_stream_calls: list[dict] = []
        self._stream_chunks = stream_chunks or [1, 2, 3]

    def chat(self, **kwargs):
        self.chat_calls.append(kwargs)
        if self._raises:
            raise self._raises
        return self._result

    def chat_stream(self, **kwargs):
        self.chat_stream_calls.append(kwargs)
        if self._raises:
            raise self._raises
        on_token = kwargs.get("on_token")
        if on_token:
            for i in self._stream_chunks:
                on_token(i)
        return self._result


@pytest.fixture(autouse=True)
def sin_corrida_previa():
    runlog.reset()
    yield
    runlog.reset()


@pytest.fixture
def fake_provider(monkeypatch):
    provider = FakeProvider()
    monkeypatch.setattr(analyzer, "get_provider", lambda name, host="": provider)
    return provider


# ── _llm_chat ────────────────────────────────────────────────

def test_llm_chat_pide_el_proveedor_correcto_y_devuelve_texto_limpio(fake_provider):
    text = analyzer._llm_chat(
        system="sys", user="usr", provider="claude", model="m",
        max_tokens=100, stage="stage2",
    )
    assert text == "# Informe\n\ntexto"  # _strip_llm_output recorta bordes
    assert fake_provider.chat_calls[0]["system"] == "sys"
    assert fake_provider.chat_calls[0]["user"] == "usr"


def test_llm_chat_registra_el_consumo_en_el_manifiesto(fake_provider):
    runlog.start_run(date="2026-08-09", mode="full")
    analyzer._llm_chat(
        system="s", user="u", provider="claude", model="claude-sonnet-5",
        max_tokens=100, stage="stage2",
    )
    calls = runlog.current().llm_calls
    assert len(calls) == 1
    assert calls[0].stage == "stage2"
    assert calls[0].in_tokens == 100
    assert calls[0].out_tokens == 50


def test_llm_chat_propaga_output_schema_y_effort(fake_provider):
    schema = {"type": "object"}
    analyzer._llm_chat(
        system="s", user="u", provider="claude", model="m", max_tokens=100,
        output_schema=schema, effort="high",
    )
    kwargs = fake_provider.chat_calls[0]
    assert kwargs["output_schema"] is schema
    assert kwargs["effort"] == "high"


# ── _llm_chat_stream ─────────────────────────────────────────

def test_llm_chat_stream_no_registra_nada_en_el_manifiesto_por_si_solo(fake_provider):
    """A diferencia de `_llm_chat`, esta función no loguea consumo — cada
    llamador decide (ver el quirk de `generate_report` más abajo)."""
    runlog.start_run(date="2026-08-09", mode="full")
    result = analyzer._llm_chat_stream(
        system="s", user="u", provider="ollama", model="m", max_tokens=100,
    )
    assert result.text == "# Informe\n\ntexto"
    assert runlog.current().llm_calls == []


def test_llm_chat_stream_pasa_on_token(fake_provider):
    seen = []

    def _cb(total):
        seen.append(total)

    analyzer._llm_chat_stream(
        system="s", user="u", provider="ollama", model="m", max_tokens=100,
        on_token=_cb,
    )
    assert fake_provider.chat_stream_calls[0]["on_token"] is _cb
    assert seen == [1, 2, 3]  # FakeProvider.chat_stream invoca on_token(i) por cada chunk


# ── generate_report ──────────────────────────────────────────

def _summary(**kw):
    base = dict(article_id=1, title="t", url="u", feed_title="f",
                feed_category="c", published_at="2026-08-09",
                severity="Alta", severity_score=4, summary="s")
    base.update(kw)
    return analyzer.ArticleSummary(**base)


def test_generate_report_ollama_no_llama_log_usage(fake_provider, caplog):
    """El quirk: la rama Ollama de `generate_report` nunca llamó a
    `_log_usage` (bug preexistente, F-G lo documenta y lo preserva)."""
    runlog.start_run(date="2026-08-09", mode="full")
    with caplog.at_level("INFO"):
        text = analyzer.generate_report(
            summaries=[_summary()], date_str="2026-08-09", model="m",
            ollama_host="http://x", provider="ollama", max_tokens=500,
        )
    assert text == "# Informe\n\ntexto"
    assert runlog.current().llm_calls == []
    assert "Informe generado: 50 tokens" in caplog.text


def test_generate_report_claude_si_llama_log_usage(fake_provider):
    runlog.start_run(date="2026-08-09", mode="full")
    analyzer.generate_report(
        summaries=[_summary()], date_str="2026-08-09", model="m",
        ollama_host="", provider="claude", max_tokens=500,
    )
    calls = runlog.current().llm_calls
    assert len(calls) == 1
    assert calls[0].stage == "stage3"


def test_generate_report_ollama_usa_chat_stream_no_chat(fake_provider):
    analyzer.generate_report(
        summaries=[_summary()], date_str="2026-08-09", model="m",
        ollama_host="", provider="ollama", max_tokens=500,
    )
    assert len(fake_provider.chat_stream_calls) == 1
    assert fake_provider.chat_calls == []


def test_generate_report_error_no_rompe(fake_provider):
    fake_provider._raises = RuntimeError("boom")
    text = analyzer.generate_report(
        summaries=[_summary()], date_str="2026-08-09", model="m",
        ollama_host="", provider="claude", max_tokens=500,
    )
    assert "Error al generar el informe" in text
    assert "boom" in text


# ── generate_phase_report ────────────────────────────────────

def test_generate_phase_report_ollama_si_llama_log_usage(fake_provider):
    """A diferencia de `generate_report`, esta sí siempre llamó `_log_usage`
    para Ollama — el otro lado del quirk."""
    runlog.start_run(date="2026-08-09", mode="full")
    analyzer.generate_phase_report(
        phase="vulnerability", summaries=[_summary()], date_str="2026-08-09",
        model="m", ollama_host="", provider="ollama", max_tokens=500,
    )
    calls = runlog.current().llm_calls
    assert len(calls) == 1
    assert calls[0].stage == "phase:vulnerability"


def test_generate_phase_report_claude_pasa_effort_de_haiku_es_none(fake_provider, monkeypatch):
    from separatio import config
    monkeypatch.setattr(config, "PHASE_EFFORT", {"vulnerability": "high"}, raising=False)
    analyzer.generate_phase_report(
        phase="vulnerability", summaries=[_summary()], date_str="2026-08-09",
        model="claude-haiku-4-5-20251001", ollama_host="", provider="claude", max_tokens=500,
    )
    assert fake_provider.chat_calls[0]["effort"] is None


def test_generate_phase_report_claude_pasa_effort_de_sonnet(fake_provider, monkeypatch):
    from separatio import config
    monkeypatch.setattr(config, "PHASE_EFFORT", {"vulnerability": "high"}, raising=False)
    analyzer.generate_phase_report(
        phase="vulnerability", summaries=[_summary()], date_str="2026-08-09",
        model="claude-sonnet-5", ollama_host="", provider="claude", max_tokens=500,
    )
    assert fake_provider.chat_calls[0]["effort"] == "high"


def test_generate_phase_report_error_no_rompe(fake_provider):
    fake_provider._raises = ValueError("mal")
    text = analyzer.generate_phase_report(
        phase="latam", summaries=[_summary()], date_str="2026-08-09",
        model="m", ollama_host="", provider="claude", max_tokens=500,
    )
    assert "Error en fase latam" in text


# ── generate_synthesis_report / generate_weekly_report ───────

def test_generate_synthesis_report(fake_provider):
    text = analyzer.generate_synthesis_report(
        phase_outputs={"vulnerability": "x"}, date_str="2026-08-09",
        total_articles=1, model="m", ollama_host="", provider="claude",
    )
    assert text == "# Informe\n\ntexto"


def test_generate_synthesis_report_error_no_rompe(fake_provider):
    fake_provider._raises = RuntimeError("boom")
    text = analyzer.generate_synthesis_report(
        phase_outputs={}, date_str="2026-08-09", total_articles=0,
        model="m", ollama_host="", provider="claude",
    )
    assert "Error en síntesis" in text


def test_generate_weekly_report(fake_provider):
    text = analyzer.generate_weekly_report(
        summaries=[_summary()], dates=["2026-08-09"], week_label="semana 32",
        model="m", ollama_host="", provider="claude",
    )
    assert text == "# Informe\n\ntexto"


# ── summarize_article ────────────────────────────────────────

def test_summarize_article_parsea_el_json(monkeypatch):
    import json
    provider = FakeProvider(result=ChatResult(
        text=json.dumps({"threat_type": "Ransomware", "severity": "Alta"}),
        in_tok=10, out_tok=5, finish="stop",
    ))
    monkeypatch.setattr(analyzer, "get_provider", lambda name, host="": provider)
    summary = analyzer.summarize_article(
        article_id=1, title="t", content="c", feed_title="f",
        feed_category="cat", url="u", published_at="2026-08-09",
        model="m", ollama_host="", provider="claude",
    )
    assert summary.threat_type == "Ransomware"
    assert summary.severity == "Alta"


def test_summarize_article_json_invalido_reintenta_y_despues_marca_error(monkeypatch):
    provider = FakeProvider(result=ChatResult(text="no es json", in_tok=1, out_tok=1))
    monkeypatch.setattr(analyzer, "get_provider", lambda name, host="": provider)
    summary = analyzer.summarize_article(
        article_id=1, title="t", content="c", feed_title="f",
        feed_category="cat", url="u", published_at="2026-08-09",
        model="m", ollama_host="", provider="claude", max_retries=1,
    )
    assert summary.error is not None
    assert len(provider.chat_calls) == 2  # intento inicial + 1 reintento
