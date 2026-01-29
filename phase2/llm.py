"""
phase2/llm.py

LLM interface abstraction for Phase 2.
Supports vLLM, OpenAI API, and mock mode for testing.
"""

import logging
import time
from abc import ABC, abstractmethod
from typing import Optional

from phase2.config import LLMConfig

logger = logging.getLogger("Phase2.LLM")


class LLMInterface(ABC):
    """Abstract base class for LLM interfaces."""

    @abstractmethod
    def generate(self, prompt: str, system_prompt: str = "", temperature: Optional[float] = None) -> str:
        """Generate text from the LLM."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the LLM is available."""
        pass


class VLLMInterface(LLMInterface):
    """Interface for vLLM-served models via OpenAI-compatible API."""

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
        """Generate text using vLLM."""
        client = self._get_client()

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        # Use provided temperature or fall back to config default
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
        """Check if vLLM server is reachable."""
        try:
            import urllib.request

            # vLLM health endpoint is at /health, not /v1/health
            base_url = self.config.base_url.replace("/v1", "")
            urllib.request.urlopen(f"{base_url}/health", timeout=5)
            return True
        except Exception:
            return False


class OllamaInterface(LLMInterface):
    """Interface for Ollama-served models."""

    def __init__(self, config: LLMConfig):
        self.config = config
        self.base_url = config.base_url.replace("/v1", "")
        if "localhost:8000" in self.base_url:
            self.base_url = "http://localhost:11434"

    def generate(self, prompt: str, system_prompt: str = "", temperature: Optional[float] = None) -> str:
        """Generate text using Ollama."""
        import requests

        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt

        # Use provided temperature or fall back to config default
        temp = temperature if temperature is not None else self.config.temperature

        try:
            start = time.time()
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.config.model_name,
                    "prompt": full_prompt,
                    "stream": False,
                    "options": {
                        "temperature": temp,
                        "num_predict": self.config.max_tokens,
                    },
                },
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            elapsed = time.time() - start
            logger.debug(f"Ollama generation took {elapsed:.2f}s")

            return response.json().get("response", "")

        except Exception as e:
            logger.error(f"Ollama generation failed: {e}")
            raise

    def is_available(self) -> bool:
        """Check if Ollama server is reachable."""
        try:
            import requests

            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except Exception:
            return False


class MockLLMInterface(LLMInterface):
    """Mock LLM interface for testing without GPU."""

    MOCK_PDDL = """
(:types
  package service user group - object
  file directory - object
)

(:predicates
  (package_installed ?p - package)
  (service_running ?s - service)
  (user_exists ?u - user)
  (file_exists ?f - file)
)

(:action install_package
  :parameters (?p - package)
  :precondition (and
    (not (package_installed ?p))
    (network_available)
  )
  :effect (and
    (package_installed ?p)
  )
)

(:action start_service
  :parameters (?s - service)
  :precondition (and
    (not (service_running ?s))
  )
  :effect (and
    (service_running ?s)
  )
)
"""

    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config
        self._call_count = 0

    def generate(self, prompt: str, system_prompt: str = "", temperature: Optional[float] = None) -> str:
        """Return mock PDDL for testing."""
        self._call_count += 1
        logger.info(f"MockLLM: Returning mock PDDL (call #{self._call_count})")

        # Vary output slightly based on prompt content
        if "package" in prompt.lower():
            return self._generate_package_domain()
        elif "service" in prompt.lower():
            return self._generate_service_domain()
        elif "user" in prompt.lower():
            return self._generate_user_domain()
        else:
            return self.MOCK_PDDL

    def _generate_package_domain(self) -> str:
        return """
(:types
  package repository - object
)

(:predicates
  (package_installed ?p - package)
  (package_outdated ?p - package)
  (repository_enabled ?r - repository)
)

(:action apt_install
  :parameters (?p - package)
  :precondition (and
    (not (package_installed ?p))
    (network_available)
  )
  :effect (and
    (package_installed ?p)
  )
)

(:action apt_remove
  :parameters (?p - package)
  :precondition (and
    (package_installed ?p)
  )
  :effect (and
    (not (package_installed ?p))
  )
)

(:action apt_upgrade
  :parameters (?p - package)
  :precondition (and
    (package_installed ?p)
    (package_outdated ?p)
    (network_available)
  )
  :effect (and
    (not (package_outdated ?p))
  )
)
"""

    def _generate_service_domain(self) -> str:
        return """
(:types
  service configuration_file - object
)

(:predicates
  (service_running ?s - service)
  (service_enabled ?s - service)
  (config_applied ?s - service)
  (configures ?f - configuration_file ?s - service)
)

(:action systemctl_start
  :parameters (?s - service)
  :precondition (and
    (not (service_running ?s))
  )
  :effect (and
    (service_running ?s)
  )
)

(:action systemctl_stop
  :parameters (?s - service)
  :precondition (and
    (service_running ?s)
  )
  :effect (and
    (not (service_running ?s))
  )
)

(:action systemctl_enable
  :parameters (?s - service)
  :precondition (and
    (not (service_enabled ?s))
  )
  :effect (and
    (service_enabled ?s)
  )
)
"""

    def _generate_user_domain(self) -> str:
        return """
(:types
  user group - object
  system_user human_user - user
)

(:predicates
  (user_exists ?u - user)
  (group_exists ?g - group)
  (member_of ?u - user ?g - group)
  (user_locked ?u - user)
)

(:action useradd
  :parameters (?u - user)
  :precondition (and
    (not (user_exists ?u))
  )
  :effect (and
    (user_exists ?u)
  )
)

(:action userdel
  :parameters (?u - user)
  :precondition (and
    (user_exists ?u)
    (not (user_critical ?u))
  )
  :effect (and
    (not (user_exists ?u))
  )
)

(:action usermod_add_group
  :parameters (?u - user ?g - group)
  :precondition (and
    (user_exists ?u)
    (group_exists ?g)
    (not (member_of ?u ?g))
  )
  :effect (and
    (member_of ?u ?g)
  )
)
"""

    def is_available(self) -> bool:
        """Mock is always available."""
        return True


def get_llm_interface(
    config: Optional[LLMConfig] = None,
    use_mock: bool = False,
    backend: str = "auto",
) -> LLMInterface:
    """
    Factory function to get the appropriate LLM interface.

    Args:
        config: LLM configuration
        use_mock: If True, return mock interface (deprecated, use backend="mock")
        backend: Backend to use - "auto", "vllm", "ollama", or "mock"

    Returns:
        LLMInterface instance
    """
    # Handle legacy use_mock parameter
    if use_mock:
        backend = "mock"

    config = config or LLMConfig()

    # Explicit backend selection
    if backend == "mock":
        logger.info("Using MockLLM interface")
        return MockLLMInterface(config)

    if backend == "vllm":
        vllm = VLLMInterface(config)
        if vllm.is_available():
            logger.info(f"Using vLLM interface at {config.base_url}")
            return vllm
        else:
            raise RuntimeError(
                f"vLLM backend requested but not available at {config.base_url}"
            )

    if backend == "ollama":
        ollama = OllamaInterface(config)
        if ollama.is_available():
            logger.info(f"Using Ollama interface at {ollama.base_url}")
            return ollama
        else:
            raise RuntimeError(
                f"Ollama backend requested but not available at {ollama.base_url}"
            )

    # Auto-detection mode (default)
    # Try vLLM first
    vllm = VLLMInterface(config)
    if vllm.is_available():
        logger.info(f"Using vLLM interface at {config.base_url}")
        return vllm

    # Try Ollama
    ollama = OllamaInterface(config)
    if ollama.is_available():
        logger.info("Using Ollama interface")
        return ollama

    # Fall back to mock
    logger.warning("No LLM server available, falling back to MockLLM")
    return MockLLMInterface(config)
