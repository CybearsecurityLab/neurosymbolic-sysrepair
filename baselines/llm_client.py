"""LLM client wrapping the OpenAI-compatible Ollama endpoint."""

from __future__ import annotations

import openai

# ---------------------------------------------------------------------------
# Model registry
# ---------------------------------------------------------------------------

MODEL_REGISTRY: dict[str, str] = {
    "mistral-large-3":  "mistral-large:123b-instruct-2511-q4_K_M",
    "qwen-3.5-122b":    "qwen3:122b",
    "nemotron-3-super": "nemotron3:120b",
    "gpt-oss-120b":     "gpt-oss:120b",
}

JUDGE_MODEL = "gpt-oss-120b"  # key in MODEL_REGISTRY


# ---------------------------------------------------------------------------
# LLMClient
# ---------------------------------------------------------------------------

class LLMClient:
    """Thin wrapper around the OpenAI client pointed at a local Ollama instance."""

    def __init__(
        self,
        model_key: str,
        base_url: str = "http://localhost:11434/v1",
    ) -> None:
        self.model_key = model_key
        self.model_name = MODEL_REGISTRY[model_key]
        self.client = openai.OpenAI(base_url=base_url, api_key="ollama")

    def chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> openai.types.chat.ChatCompletion:
        """Send a chat completion request, optionally with tool definitions."""
        kwargs: dict = dict(
            model=self.model_name,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        return self.client.chat.completions.create(**kwargs)

    def structured(
        self,
        messages: list[dict],
        schema: type,        # pydantic BaseModel subclass
        temperature: float = 0.1,
        max_tokens: int = 8192,
    ):
        """Force JSON output and parse the response into a pydantic schema instance."""
        resp = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
        )
        content = resp.choices[0].message.content
        return schema.model_validate_json(content)
