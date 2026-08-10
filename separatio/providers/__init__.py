"""Fábrica de proveedores LLM (F-G/G-5). Ver `base.py` para el porqué.

`analyzer.py` sigue siendo el único que conoce `stage`/logging/manifiesto —
este paquete sólo sabe hablar con cada API y devolver un `ChatResult`.
"""

from .anthropic_provider import AnthropicProvider
from .base import ChatResult, LLMProvider, get_api_key
from .gemini_provider import GeminiProvider
from .ollama import OllamaProvider
from .openai_provider import OpenAIProvider

_REGISTRY = {
    "ollama": OllamaProvider,
    "claude": AnthropicProvider,
    "openai": OpenAIProvider,
    "gemini": GeminiProvider,
}


def get_provider(name: str, ollama_host: str = "") -> LLMProvider:
    cls = _REGISTRY.get(name)
    if cls is None:
        raise ValueError(
            f"Provider desconocido: {name!r}. Opciones: {', '.join(_REGISTRY)}"
        )
    return cls(ollama_host)


__all__ = [
    "ChatResult", "LLMProvider", "get_api_key", "get_provider",
    "OllamaProvider", "AnthropicProvider", "OpenAIProvider", "GeminiProvider",
]
