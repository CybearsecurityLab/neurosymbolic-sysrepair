"""
phase2/llm.py

LLM client for Phase 2 via OpenAI-compatible API (vLLM).
"""

import logging
import time
from typing import Optional

from phase2.config import LLMConfig

logger = logging.getLogger("Phase2.LLM")


class LLMInterface:
    """LLM client using the OpenAI-compatible chat completions API."""

    def __init__(self, config: LLMConfig):
        self.config = config
        self._client = None

    def _get_client(self):
        """Lazy initialization of OpenAI client."""
        if self._client is None:
            try:
                from openai import OpenAI

                self._client = OpenAI(
                    base_url=self.config.base_url,
                    api_key=self.config.api_key,
                    timeout=self.config.timeout,
                )
            except ImportError:
                raise RuntimeError(
                    "openai package not installed. Install with: pip install openai"
                )
        return self._client

    def generate(self, prompt: str, system_prompt: str = "", temperature: Optional[float] = None) -> str:
        """Generate text from the LLM."""
        client = self._get_client()

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        temp = temperature if temperature is not None else self.config.temperature

        try:
            start = time.time()
            response = client.chat.completions.create(
                model=self.config.model_name,
                messages=messages,
                max_tokens=self.config.max_tokens,
                temperature=temp,
            )
            elapsed = time.time() - start
            logger.debug(f"LLM generation took {elapsed:.2f}s")

            return response.choices[0].message.content

        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            raise

    def is_available(self) -> bool:
        """Check if the LLM server is reachable."""
        try:
            import urllib.request

            base_url = self.config.base_url.replace("/v1", "")
            urllib.request.urlopen(f"{base_url}/health", timeout=5)
            return True
        except Exception:
            return False


def get_llm_interface(config: Optional[LLMConfig] = None) -> LLMInterface:
    """
    Create an LLM client.

    Args:
        config: LLM configuration

    Returns:
        LLMInterface instance

    Raises:
        RuntimeError: If the LLM server is not reachable
    """
    config = config or LLMConfig()
    llm = LLMInterface(config)

    if not llm.is_available():
        raise RuntimeError(
            f"LLM server not available at {config.base_url}. "
            f"Start your vLLM server first."
        )

    logger.info(f"Using LLM at {config.base_url} (model: {config.model_name})")
    return llm
