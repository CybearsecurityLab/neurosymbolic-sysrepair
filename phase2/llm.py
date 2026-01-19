import threading
import asyncio  # <--- Fixes 'base_events' NameError
import logging
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed

from phase2.config import LLMConfig

logger = logging.getLogger("Phase2.LLM")

class LLMInterface(ABC):
    @abstractmethod
    def generate(self, prompt: str, system_prompt: str = "") -> str:
        pass

class VLLMInterface(LLMInterface):
    def __init__(self, config: LLMConfig):
        self.config = config
        self._semaphore = threading.Semaphore(config.max_concurrent_requests)

    def _get_client(self):
        """Create a fresh client to avoid thread-safety issues."""
        try:
            from openai import OpenAI
            return OpenAI(
                base_url=self.config.base_url,
                api_key="not-needed",
            )
        except ImportError:
            raise RuntimeError("openai package required: pip install openai")

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        with self._semaphore:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            try:
                # Instantiate client per request to be thread-safe
                client = self._get_client()
                response = client.chat.completions.create(
                    model=self.config.model_name,
                    messages=messages,
                    max_tokens=self.config.max_tokens,
                    temperature=self.config.temperature,
                    timeout=self.config.request_timeout,
                )
                return response.choices[0].message.content
            except Exception as e:
                logger.error(f"LLM generation failed: {e}")
                return ""

class MockLLMInterface(LLMInterface):
    def generate(self, prompt: str, system_prompt: str = "") -> str:
        return "; Mock PDDL output\n(:types package - object)\n(:predicates (installed ?p - package))"

def get_llm_interface(config: LLMConfig, use_mock: bool = False) -> LLMInterface:
    if use_mock:
        return MockLLMInterface()
    return VLLMInterface(config)