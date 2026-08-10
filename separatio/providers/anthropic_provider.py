from .base import ChatResult, LLMProvider, get_api_key


class AnthropicProvider(LLMProvider):
    name = "claude"

    def chat(
        self, *, system, user, model, max_tokens, temperature=0.1, timeout=120,
        thinking=False, num_ctx=4096, num_threads=0, output_schema=None, effort=None,
    ) -> ChatResult:
        import anthropic
        client = anthropic.Anthropic(api_key=get_api_key("claude"))
        # Los modelos Claude actuales (Sonnet 5 / Opus 5 / 4.7+) rechazan los
        # parámetros de sampling (temperature/top_p/top_k) con 400 — se omiten.
        kwargs: dict = {}
        output_config: dict = {}
        if output_schema:
            output_config["format"] = {"type": "json_schema", "schema": output_schema}
        if effort:
            output_config["effort"] = effort
        if output_config:
            kwargs["output_config"] = output_config
        response = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
            **kwargs,
        )
        # Sonnet 5 / Opus 5 piensan por defecto: content puede empezar con
        # bloques "thinking" — quedarse solo con los bloques de texto.
        text = "".join(b.text for b in response.content if b.type == "text")
        return ChatResult(
            text=text,
            in_tok=response.usage.input_tokens,
            out_tok=response.usage.output_tokens,
            finish=response.stop_reason,
        )
