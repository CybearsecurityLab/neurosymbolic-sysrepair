import logging
import threading
from abc import ABC, abstractmethod
import httpx
from phase2.config import LLMConfig
from openai import OpenAI

logger = logging.getLogger("Phase2.LLM")

class LLMInterface(ABC):
    @abstractmethod
    def generate(self, prompt: str, system_prompt: str = "") -> str:
        pass

class VLLMInterface(LLMInterface):
    def __init__(self, config: LLMConfig):
        self.config = config
        self._semaphore = threading.Semaphore(config.max_concurrent_requests)
        self._http_client = httpx.Client(
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            timeout=config.request_timeout
        )
        self._client = None
        self._client_lock = threading.Lock()

    def _get_client(self):
        with self._client_lock:
            if self._client is None:
                self._client = OpenAI(
                    base_url=self.config.base_url,
                    api_key="not-needed",
                    http_client=self._http_client,
                )
            return self._client

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