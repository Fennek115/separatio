from .base import ChatResult, LLMProvider, get_api_key


class GeminiProvider(LLMProvider):
    name = "gemini"

    def chat(
        self, *, system, user, model, max_tokens, temperature=0.1, timeout=120,
        thinking=False, num_ctx=4096, num_threads=0, output_schema=None, effort=None,
    ) -> ChatResult:
        import google.generativeai as genai
        genai.configure(api_key=get_api_key("gemini"))
        gemini_model = genai.GenerativeModel(
            model_name=model,
            system_instruction=system,
        )
        response = gemini_model.generate_content(
            user,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=max_tokens,
                temperature=temperature,
            ),
        )
        meta   = response.usage_metadata
        finish = response.candidates[0].finish_reason.name if response.candidates else "UNKNOWN"
        return ChatResult(
            text=response.text,
            in_tok=meta.prompt_token_count,
            out_tok=meta.candidates_token_count,
            finish=finish,
        )
