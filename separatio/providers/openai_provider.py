from .base import ChatResult, LLMProvider, get_api_key


class OpenAIProvider(LLMProvider):
    name = "openai"

    def chat(
        self, *, system, user, model, max_tokens, temperature=0.1, timeout=120,
        thinking=False, num_ctx=4096, num_threads=0, output_schema=None, effort=None,
    ) -> ChatResult:
        import openai
        client = openai.OpenAI(api_key=get_api_key("openai"))
        response = client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        )
        usage = response.usage
        return ChatResult(
            text=response.choices[0].message.content,
            in_tok=usage.prompt_tokens,
            out_tok=usage.completion_tokens,
            finish=response.choices[0].finish_reason,
        )
