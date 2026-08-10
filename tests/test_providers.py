"""Tests de `separatio/providers/` (F-G/G-5 — abstracción de proveedores LLM).

Antes de esta fase no había un solo test que ejercitara el dispatch de
proveedor ni el streaming de Ollama: `_llm_chat` mezclaba las cuatro APIs con
`if provider == ...` y nadie lo importaba desde `tests/`. Estos tests fijan,
por primera vez, el contrato de cada proveedor — con los SDKs (`ollama`,
`anthropic`, `openai`, `google.generativeai`) reemplazados por dobles en
`sys.modules`, así que corren sin red y sin que el SDK real esté instalado
(`openai`/`google-generativeai` no son dependencias del proyecto)."""

import sys
import types

import pytest

from separatio.providers import (
    AnthropicProvider,
    ChatResult,
    GeminiProvider,
    LLMProvider,
    OllamaProvider,
    OpenAIProvider,
    get_api_key,
    get_provider,
)


# ── get_provider (la fábrica) ───────────────────────────────

def test_get_provider_devuelve_la_clase_correcta():
    assert isinstance(get_provider("ollama"), OllamaProvider)
    assert isinstance(get_provider("claude"), AnthropicProvider)
    assert isinstance(get_provider("openai"), OpenAIProvider)
    assert isinstance(get_provider("gemini"), GeminiProvider)


def test_get_provider_desconocido_levanta_con_el_mismo_mensaje_de_siempre():
    with pytest.raises(ValueError) as exc:
        get_provider("bogus")
    assert str(exc.value) == (
        "Provider desconocido: 'bogus'. Opciones: ollama, claude, openai, gemini"
    )


def test_get_provider_pasa_el_host_solo_a_ollama():
    p = get_provider("ollama", ollama_host="http://x:11434")
    assert p._ollama_host == "http://x:11434"
    assert get_provider("claude")._ollama_host == ""


# ── get_api_key ─────────────────────────────────────────────

def test_get_api_key_lee_de_config(monkeypatch):
    from separatio import config
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "sk-test", raising=False)
    assert get_api_key("claude") == "sk-test"


def test_get_api_key_sin_key_levanta(monkeypatch):
    from separatio import config
    monkeypatch.setattr(config, "OPENAI_API_KEY", "", raising=False)
    with pytest.raises(ValueError, match="API key para 'openai' no configurada"):
        get_api_key("openai")


# ── OllamaProvider ───────────────────────────────────────────

class _FakeOllamaClient:
    def __init__(self, host="", timeout=120):
        self.host = host
        self.timeout = timeout

    def chat(self, model, messages, think, options, stream=False):
        if not stream:
            return {
                "message": {"content": "  hola  "},
                "prompt_eval_count": 10,
                "eval_count": 5,
                "done_reason": "stop",
            }
        return iter([
            {"message": {"content": "ho"}},
            {"message": {"content": "la"}},
            {"message": {"content": ""}, "done_reason": "stop", "prompt_eval_count": 10},
        ])


@pytest.fixture
def fake_ollama(monkeypatch):
    mod = types.ModuleType("ollama")
    mod.Client = _FakeOllamaClient
    monkeypatch.setitem(sys.modules, "ollama", mod)
    return mod


def test_ollama_chat_no_streaming(fake_ollama):
    result = OllamaProvider().chat(
        system="s", user="u", model="m", max_tokens=100,
    )
    assert isinstance(result, ChatResult)
    assert result.text == "  hola  "  # el strip lo hace analyzer, no el provider
    assert result.in_tok == 10
    assert result.out_tok == 5
    assert result.finish == "stop"


def test_ollama_chat_stream_junta_los_chunks_y_llama_on_token(fake_ollama):
    seen = []
    result = OllamaProvider().chat_stream(
        system="s", user="u", model="m", max_tokens=100, on_token=seen.append,
    )
    assert result.text == "hola"
    assert result.out_tok == 2          # dos chunks con contenido no vacío
    assert result.finish == "stop"
    assert result.in_tok == 10          # viene del último chunk (done)
    assert seen == [1, 2]               # on_token(total) por cada token no vacío


def test_ollama_chat_stream_sin_on_token_no_explota(fake_ollama):
    result = OllamaProvider().chat_stream(
        system="s", user="u", model="m", max_tokens=100,
    )
    assert result.text == "hola"


def test_ollama_usa_el_host_del_constructor(fake_ollama, monkeypatch):
    captured = {}
    real_init = _FakeOllamaClient.__init__

    def _spy_init(self, host="", timeout=120):
        captured["host"] = host
        real_init(self, host, timeout)

    monkeypatch.setattr(_FakeOllamaClient, "__init__", _spy_init)
    OllamaProvider(ollama_host="http://donde-sea:11434").chat(
        system="s", user="u", model="m", max_tokens=10,
    )
    assert captured["host"] == "http://donde-sea:11434"


# ── AnthropicProvider ────────────────────────────────────────

class _FakeBlock:
    def __init__(self, type_, text=""):
        self.type = type_
        self.text = text


class _FakeUsage:
    def __init__(self, in_tok, out_tok):
        self.input_tokens = in_tok
        self.output_tokens = out_tok


class _FakeAnthropicResponse:
    def __init__(self, content, stop_reason="end_turn", in_tok=20, out_tok=8):
        self.content = content
        self.stop_reason = stop_reason
        self.usage = _FakeUsage(in_tok, out_tok)


class _FakeAnthropicMessages:
    def __init__(self, response, capture):
        self._response = response
        self._capture = capture

    def create(self, **kwargs):
        self._capture.update(kwargs)
        return self._response


class _FakeAnthropicClient:
    last_capture = None

    def __init__(self, api_key=""):
        self.api_key = api_key
        _FakeAnthropicClient.last_capture = {}
        self.messages = _FakeAnthropicMessages(
            _FakeAnthropicClient.next_response, _FakeAnthropicClient.last_capture
        )


@pytest.fixture
def fake_anthropic(monkeypatch):
    mod = types.ModuleType("anthropic")
    mod.Anthropic = _FakeAnthropicClient
    monkeypatch.setitem(sys.modules, "anthropic", mod)
    from separatio import config
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "sk-test", raising=False)
    return mod


def test_claude_filtra_bloques_de_thinking_y_se_queda_con_el_texto(fake_anthropic):
    _FakeAnthropicClient.next_response = _FakeAnthropicResponse(
        content=[_FakeBlock("thinking", "razonando..."), _FakeBlock("text", "resultado")],
    )
    result = AnthropicProvider().chat(system="s", user="u", model="m", max_tokens=50)
    assert result.text == "resultado"
    assert result.in_tok == 20
    assert result.out_tok == 8
    assert result.finish == "end_turn"


def test_claude_no_manda_output_config_sin_schema_ni_effort(fake_anthropic):
    _FakeAnthropicClient.next_response = _FakeAnthropicResponse(content=[_FakeBlock("text", "x")])
    AnthropicProvider().chat(system="s", user="u", model="m", max_tokens=50)
    assert "output_config" not in _FakeAnthropicClient.last_capture


def test_claude_manda_schema_y_effort_cuando_se_pasan(fake_anthropic):
    _FakeAnthropicClient.next_response = _FakeAnthropicResponse(content=[_FakeBlock("text", "x")])
    schema = {"type": "object"}
    AnthropicProvider().chat(
        system="s", user="u", model="m", max_tokens=50,
        output_schema=schema, effort="high",
    )
    oc = _FakeAnthropicClient.last_capture["output_config"]
    assert oc["format"] == {"type": "json_schema", "schema": schema}
    assert oc["effort"] == "high"


def test_claude_no_manda_temperature_ni_top_p(fake_anthropic):
    """Sonnet 5 / Opus 5 rechazan sampling params con 400 — no deben mandarse."""
    _FakeAnthropicClient.next_response = _FakeAnthropicResponse(content=[_FakeBlock("text", "x")])
    AnthropicProvider().chat(system="s", user="u", model="m", max_tokens=50, temperature=0.7)
    assert "temperature" not in _FakeAnthropicClient.last_capture


def test_claude_chat_stream_cae_a_chat_sin_invocar_on_token(fake_anthropic):
    """Cloud responde en segundos: no hay streaming real, la base cae a chat()."""
    _FakeAnthropicClient.next_response = _FakeAnthropicResponse(content=[_FakeBlock("text", "x")])
    seen = []
    result = AnthropicProvider().chat_stream(
        system="s", user="u", model="m", max_tokens=50, on_token=seen.append,
    )
    assert result.text == "x"
    assert seen == []


# ── OpenAIProvider (SDK no instalado — sólo vía el doble) ────

class _FakeOpenAIUsage:
    def __init__(self, p, c):
        self.prompt_tokens = p
        self.completion_tokens = c


class _FakeOpenAIChoice:
    def __init__(self, content, finish_reason="stop"):
        self.message = types.SimpleNamespace(content=content)
        self.finish_reason = finish_reason


class _FakeOpenAIResponse:
    def __init__(self, content, finish_reason="stop", p=12, c=6):
        self.choices = [_FakeOpenAIChoice(content, finish_reason)]
        self.usage = _FakeOpenAIUsage(p, c)


class _FakeOpenAICompletions:
    def create(self, **kwargs):
        _FakeOpenAIClient.last_capture = kwargs
        return _FakeOpenAIClient.next_response


class _FakeOpenAIChat:
    def __init__(self):
        self.completions = _FakeOpenAICompletions()


class _FakeOpenAIClient:
    last_capture = None
    next_response = None

    def __init__(self, api_key=""):
        self.api_key = api_key
        self.chat = _FakeOpenAIChat()


@pytest.fixture
def fake_openai(monkeypatch):
    mod = types.ModuleType("openai")
    mod.OpenAI = _FakeOpenAIClient
    monkeypatch.setitem(sys.modules, "openai", mod)
    from separatio import config
    monkeypatch.setattr(config, "OPENAI_API_KEY", "sk-test", raising=False)
    return mod


def test_openai_chat(fake_openai):
    _FakeOpenAIClient.next_response = _FakeOpenAIResponse("respuesta", "stop", 12, 6)
    result = OpenAIProvider().chat(system="s", user="u", model="m", max_tokens=50)
    assert result.text == "respuesta"
    assert result.in_tok == 12
    assert result.out_tok == 6
    assert result.finish == "stop"
    assert _FakeOpenAIClient.last_capture["temperature"] == 0.1


# ── GeminiProvider (SDK no instalado — sólo vía el doble) ────

class _FakeGeminiFinishReason:
    def __init__(self, name):
        self.name = name


class _FakeGeminiCandidate:
    def __init__(self, finish_reason):
        self.finish_reason = _FakeGeminiFinishReason(finish_reason)


class _FakeGeminiUsage:
    def __init__(self, p, c):
        self.prompt_token_count = p
        self.candidates_token_count = c


class _FakeGeminiResponse:
    def __init__(self, text, finish_reason="STOP", p=15, c=7):
        self.text = text
        self.candidates = [_FakeGeminiCandidate(finish_reason)]
        self.usage_metadata = _FakeGeminiUsage(p, c)


class _FakeGeminiModel:
    def __init__(self, model_name="", system_instruction=""):
        self.model_name = model_name
        self.system_instruction = system_instruction

    def generate_content(self, user, generation_config=None):
        _FakeGenAI.last_capture = {
            "user": user, "generation_config": generation_config,
        }
        return _FakeGenAI.next_response


class _FakeGenAI:
    last_capture = None
    next_response = None

    @staticmethod
    def configure(api_key=""):
        _FakeGenAI.last_api_key = api_key

    GenerativeModel = _FakeGeminiModel

    class types:
        class GenerationConfig:
            def __init__(self, max_output_tokens=0, temperature=0.0):
                self.max_output_tokens = max_output_tokens
                self.temperature = temperature


@pytest.fixture
def fake_gemini(monkeypatch):
    genai_mod = types.ModuleType("google.generativeai")
    genai_mod.configure = _FakeGenAI.configure
    genai_mod.GenerativeModel = _FakeGenAI.GenerativeModel
    genai_mod.types = _FakeGenAI.types
    google_mod = types.ModuleType("google")
    google_mod.generativeai = genai_mod
    monkeypatch.setitem(sys.modules, "google", google_mod)
    monkeypatch.setitem(sys.modules, "google.generativeai", genai_mod)
    from separatio import config
    monkeypatch.setattr(config, "GEMINI_API_KEY", "gk-test", raising=False)
    return genai_mod


def test_gemini_chat(fake_gemini):
    _FakeGenAI.next_response = _FakeGeminiResponse("respuesta gemini", "STOP", 15, 7)
    result = GeminiProvider().chat(system="s", user="u", model="m", max_tokens=50)
    assert result.text == "respuesta gemini"
    assert result.in_tok == 15
    assert result.out_tok == 7
    assert result.finish == "STOP"


def test_gemini_sin_candidatos_finish_unknown(fake_gemini):
    resp = _FakeGeminiResponse("x")
    resp.candidates = []
    _FakeGenAI.next_response = resp
    result = GeminiProvider().chat(system="s", user="u", model="m", max_tokens=50)
    assert result.finish == "UNKNOWN"


# ── El contrato de la base (chat_stream cae a chat) ──────────

class _StubProvider(LLMProvider):
    name = "stub"

    def chat(self, **kwargs):
        return ChatResult(text="fijo", in_tok=1, out_tok=1, finish="stop")


def test_llmprovider_chat_stream_por_defecto_delega_en_chat():
    seen = []
    result = _StubProvider().chat_stream(
        system="s", user="u", model="m", max_tokens=10, on_token=seen.append,
    )
    assert result.text == "fijo"
    assert seen == []
