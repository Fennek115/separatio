"""Interfaz común de proveedor LLM (F-G/G-5).

Reemplaza el dispatch `if provider == ...` que tenía `analyzer._llm_chat` por
una jerarquía de clases: cada proveedor implementa `chat()` (una respuesta
completa) y, sólo si necesita streaming de verdad, `chat_stream()` — la base
cae a `chat()`, que es exactamente lo que las ramas `else` de
`generate_report`/`generate_phase_report` ya hacían para los proveedores cloud
("responden en segundos, no necesitan streaming"). Sólo `OllamaProvider`
sobreescribe `chat_stream()`, y ahí queda el único lugar con el loop de
streaming — antes estaba duplicado en `generate_report` y
`generate_phase_report`.
"""

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class ChatResult:
    text: str
    in_tok: int = 0
    out_tok: int = 0
    finish: str = "stop"


class LLMProvider(ABC):
    name: str = "?"

    def __init__(self, ollama_host: str = ""):
        # Sólo lo usa OllamaProvider; el resto lo ignora — vive acá para que
        # `get_provider()` no necesite un caso especial por proveedor.
        self._ollama_host = ollama_host

    @abstractmethod
    def chat(
        self,
        *,
        system: str,
        user: str,
        model: str,
        max_tokens: int,
        temperature: float = 0.1,
        timeout: int = 120,
        thinking: bool = False,
        num_ctx: int = 4096,
        num_threads: int = 0,
        output_schema: dict | None = None,
        effort: str | None = None,
    ) -> ChatResult:
        """Una respuesta completa. `output_schema`/`effort` son de la API de
        Claude (F-I) — el resto de los proveedores los ignora."""
        raise NotImplementedError

    def chat_stream(
        self,
        *,
        system: str,
        user: str,
        model: str,
        max_tokens: int,
        temperature: float = 0.1,
        timeout: int = 120,
        thinking: bool = False,
        num_ctx: int = 4096,
        num_threads: int = 0,
        on_token: Callable[[int], None] | None = None,
    ) -> ChatResult:
        return self.chat(
            system=system, user=user, model=model, max_tokens=max_tokens,
            temperature=temperature, timeout=timeout, thinking=thinking,
            num_ctx=num_ctx, num_threads=num_threads,
        )


def get_api_key(provider: str, settings=None) -> str:
    """La key del proveedor, de un `Settings` (F-G/G-2) o del `config` global."""
    if settings is None:
        from separatio import config as settings
    keys = {
        "claude": getattr(settings, "ANTHROPIC_API_KEY", ""),
        "openai": getattr(settings, "OPENAI_API_KEY", ""),
        "gemini": getattr(settings, "GEMINI_API_KEY", ""),
    }
    key = keys.get(provider, "")
    if not key:
        raise ValueError(
            f"API key para '{provider}' no configurada. "
            f"Revisa config.py o la variable de entorno correspondiente."
        )
    return key
