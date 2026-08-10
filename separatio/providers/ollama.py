"""Proveedor Ollama (legacy: CT 111 ya no existe, ver CLAUDE.md de la raíz).

Único proveedor con streaming real — CPU-only necesita ver tokens llegando
para no pegarse un timeout en generaciones largas. `chat_stream()` es el único
lugar del repo con este loop; antes estaba duplicado en
`analyzer.generate_report` y `analyzer.generate_phase_report`.
"""

from collections.abc import Callable

from .base import ChatResult, LLMProvider


def _build_options(num_ctx: int, num_predict: int,
                   temperature: float, num_threads: int) -> dict:
    options: dict = {
        "temperature": temperature,
        "num_predict": num_predict,
        "num_ctx": num_ctx,
    }
    if num_threads > 0:
        options["num_thread"] = num_threads
    return options


class OllamaProvider(LLMProvider):
    name = "ollama"

    def chat(
        self, *, system, user, model, max_tokens, temperature=0.1, timeout=120,
        thinking=False, num_ctx=4096, num_threads=0, output_schema=None, effort=None,
    ) -> ChatResult:
        import ollama
        client  = ollama.Client(host=self._ollama_host, timeout=timeout)
        options = _build_options(num_ctx, max_tokens, temperature, num_threads)
        response = client.chat(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            think=thinking,
            options=options,
        )
        return ChatResult(
            text=response["message"]["content"],
            in_tok=response.get("prompt_eval_count", 0),
            out_tok=response.get("eval_count", 0),
            finish=response.get("done_reason", "stop"),
        )

    def chat_stream(
        self, *, system, user, model, max_tokens, temperature=0.1, timeout=120,
        thinking=False, num_ctx=4096, num_threads=0,
        on_token: Callable[[int], None] | None = None,
    ) -> ChatResult:
        import ollama
        client  = ollama.Client(host=self._ollama_host, timeout=timeout)
        options = _build_options(num_ctx, max_tokens, temperature, num_threads)
        stream = client.chat(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            think=thinking,
            options=options,
            stream=True,
        )
        tokens: list[str] = []
        total = 0
        last_chunk: dict = {}
        for chunk in stream:
            last_chunk = chunk
            token = chunk["message"]["content"]
            if token:
                tokens.append(token)
                total += 1
                if on_token is not None:
                    on_token(total)
        return ChatResult(
            text="".join(tokens),
            in_tok=last_chunk.get("prompt_eval_count", 0),
            out_tok=total,
            finish=last_chunk.get("done_reason", "stop"),
        )
