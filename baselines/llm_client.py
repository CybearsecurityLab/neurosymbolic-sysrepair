"""LLM client wrapping the OpenAI-compatible Ollama endpoint."""

from __future__ import annotations

import json
import logging
import re

import httpx
import openai

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Model registry
# ---------------------------------------------------------------------------

MODEL_REGISTRY: dict[str, str] = {
    "mistral-large-3":  "devstral-2:123b",
    "qwen-3.5-122b":    "qwen3.5:122b",
    "qwen-3.5-35b":     "qwen3.5:35b",
    "nemotron-nano":     "nemotron-3-nano:latest",
    "nemotron-3-super":  "nemotron-3-super:120b",
    "gpt-oss-120b":      "gpt-oss:120b",
}

JUDGE_MODEL = "gpt-oss-120b"  # key in MODEL_REGISTRY (legacy single-judge fallback)

JUDGE_PANEL = [
    {"key": "qwen-3.5-35b",  "weight": 0.25, "samples": 2},
    {"key": "nemotron-nano",  "weight": 0.25, "samples": 2},
    {"key": "gpt-oss-120b",  "weight": 0.50, "samples": 1},
]


# ---------------------------------------------------------------------------
# LLMClient
# ---------------------------------------------------------------------------

class LLMClient:
    """Thin wrapper around the OpenAI client pointed at a local Ollama instance."""

    # Models that use thinking mode and need native Ollama API for structured output
    _THINKING_MODELS = {"qwen3.5:35b", "qwen3.5:122b"}

    def __init__(
        self,
        model_key: str,
        base_url: str = "http://10.100.203.130:11434/v1",
    ) -> None:
        self.model_key = model_key
        self.model_name = MODEL_REGISTRY[model_key]
        self.client = openai.OpenAI(base_url=base_url, api_key="ollama")
        # Derive native Ollama API URL for thinking-mode models
        base = base_url.rstrip("/")
        if base.endswith("/v1"):
            self._native_url = base[:-3] + "/api/chat"
        else:
            self._native_url = base + "/api/chat"
        self._uses_thinking = self.model_name in self._THINKING_MODELS

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

        # Validate input
        user_msgs = [m for m in messages if m.get("role") == "user"]
        if user_msgs and not (user_msgs[-1].get("content") or "").strip():
            logger.warning(
                f"[LLM] Empty user message sent to {self.model_name} "
                f"(total messages={len(messages)})"
            )

        try:
            resp = self.client.chat.completions.create(**kwargs)
        except (openai.APIConnectionError, openai.APITimeoutError) as e:
            logger.error(
                f"[LLM] Cannot reach Ollama server at {self.client.base_url} "
                f"for model {self.model_name}: {e}"
            )
            raise
        except openai.APIError as e:
            logger.error(
                f"[LLM] API error from {self.model_name}: {e}"
            )
            raise

        content = resp.choices[0].message.content if resp.choices else None
        tool_calls = resp.choices[0].message.tool_calls if resp.choices else None
        if not content and not tool_calls:
            logger.warning(
                f"[LLM] Empty response from {self.model_name} "
                f"(no content, no tool calls, messages={len(messages)})"
            )

        return resp

    def structured(
        self,
        messages: list[dict],
        schema: type,        # pydantic BaseModel subclass
        temperature: float = 0.1,
        max_tokens: int = 8192,
    ):
        """Force JSON output and parse the response into a pydantic schema instance.

        Uses native Ollama API for thinking-mode models (Qwen3) since the
        OpenAI-compatible API returns empty content for these models.
        """
        if self._uses_thinking:
            return self._structured_native(messages, schema, temperature, max_tokens)

        try:
            resp = self.client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                response_format={"type": "json_object"},
            )
        except (openai.APIConnectionError, openai.APITimeoutError) as e:
            logger.error(
                f"[LLM] Cannot reach Ollama server at {self.client.base_url} "
                f"for structured call to {self.model_name}: {e}"
            )
            raise
        content = resp.choices[0].message.content or ""
        content = re.sub(r"<think>.*?</think>\s*", "", content, flags=re.DOTALL).strip()
        if not content:
            logger.error(
                f"[LLM] Empty structured response from {self.model_name} "
                f"after stripping think tags (messages={len(messages)})"
            )
            raise ValueError(f"Empty response from {self.model_name} after stripping think tags")
        return schema.model_validate_json(content)

    def _structured_native(
        self,
        messages: list[dict],
        schema: type,
        temperature: float,
        max_tokens: int,
    ):
        """Use native Ollama /api/chat for thinking-mode models (Qwen3).

        Keeps thinking enabled for better reasoning quality but sets
        num_predict high enough for both thinking + JSON content.
        """
        # Thinking typically uses 4-16K tokens; add that on top of
        # the requested max_tokens for the actual JSON content
        total_predict = max_tokens + 16384

        try:
            resp = httpx.post(
                self._native_url,
                json={
                    "model": self.model_name,
                    "messages": messages,
                    "stream": False,
                    "format": "json",
                    "options": {
                        "temperature": temperature,
                        "num_predict": total_predict,
                    },
                },
                timeout=300.0,
            )
            resp.raise_for_status()
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            logger.error(
                f"[LLM] Cannot reach Ollama native API at {self._native_url} "
                f"for model {self.model_name}: {e}"
            )
            raise
        data = resp.json()
        msg = data.get("message", {})
        content = (msg.get("content") or "").strip()

        if not content:
            thinking_len = len(msg.get("thinking", ""))
            logger.error(
                f"[LLM] Empty native structured response from {self.model_name} "
                f"(thinking_len={thinking_len}, messages={len(messages)})"
            )
            raise ValueError(
                f"Empty content from {self.model_name} via native API "
                f"(thinking_len={thinking_len})"
            )

        return schema.model_validate_json(content)
