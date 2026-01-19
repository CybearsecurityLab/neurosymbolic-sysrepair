import threading
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed

from phase2.config import LLMConfig
import logging

logger = logging.getLogger("Phase2.LLM")

class LLMInterface(ABC):
    """Abstract LLM interface for PDDL generation."""

    @abstractmethod
    def generate(self, prompt: str, system_prompt: str = "") -> str:
        pass

    @abstractmethod
    def generate_batch(self, prompts: list[str], system_prompt: str = "") -> list[str]:
        pass


class VLLMInterface(LLMInterface):
    """
    vLLM-based LLM interface using OpenAI-compatible API.

    Start vLLM server with:
    python -m vllm.entrypoints.openai.api_server \
        --model mistralai/Mistral-7B-Instruct-v0.3 \
        --tensor-parallel-size 2 \
        --max-model-len 8192 \
        --gpu-memory-utilization 0.9
    """

    def __init__(self, config: LLMConfig):
        self.config = config
        self._client = None
        self._semaphore = threading.Semaphore(config.max_concurrent_requests)

    @property
    def client(self):
        if self._client is None:
            try:
                from openai import OpenAI

                self._client = OpenAI(
                    base_url=self.config.base_url,
                    api_key="not-needed",  # vLLM doesn't require API key
                )
            except ImportError:
                raise RuntimeError("openai package required: pip install openai")
        return self._client

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        """Generate single completion."""
        with self._semaphore:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            try:
                response = self.client.chat.completions.create(
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

    def generate_batch(self, prompts: list[str], system_prompt: str = "") -> list[str]:
        """Generate batch completions in parallel."""
        results = [None] * len(prompts)

        def process_single(idx: int, prompt: str):
            results[idx] = self.generate(prompt, system_prompt)

        with ThreadPoolExecutor(
            max_workers=self.config.max_concurrent_requests
        ) as executor:
            futures = [
                executor.submit(process_single, i, p) for i, p in enumerate(prompts)
            ]
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception as e:
                    logger.error(f"Batch generation error: {e}")

        return results


class MockLLMInterface(LLMInterface):
    """Mock LLM for testing without GPU."""

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        # Return template-based responses for testing
        if "apt" in prompt.lower() or "package" in prompt.lower():
            return self._package_template()
        elif "systemctl" in prompt.lower() or "service" in prompt.lower():
            return self._service_template()
        return "; Mock PDDL output\n"

    def generate_batch(self, prompts: list[str], system_prompt: str = "") -> list[str]:
        return [self.generate(p, system_prompt) for p in prompts]

    def _package_template(self) -> str:
        return """
(:types
  package repository - object
)

(:predicates
  (package_installed ?p - package)
  (package_available ?p - package)
  (repo_enabled ?r - repository)
)

(:action install_package
  :parameters (?p - package)
  :precondition (and (not (package_installed ?p)) (package_available ?p))
  :effect (package_installed ?p)
)
"""

    def _service_template(self) -> str:
        return """
(:types
  service - object
)

(:predicates
  (service_running ?s - service)
  (service_enabled ?s - service)
)

(:action start_service
  :parameters (?s - service)
  :precondition (not (service_running ?s))
  :effect (service_running ?s)
)
"""

def get_llm_interface(config: LLMConfig, use_mock: bool = False) -> LLMInterface:
    """Factory function to get LLM interface."""
    if use_mock:
        return MockLLMInterface()
    return VLLMInterface(config)