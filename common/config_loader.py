"""
Unified configuration loader for auto-sysrepair.

Loads config.yaml and exposes typed accessors.  CLI args and env vars
override YAML values (CLI > env > yaml > defaults).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_CONFIG_PATH = _PROJECT_ROOT / "config.yaml"
_DEFAULT_ENV_PATH = _PROJECT_ROOT / ".env"

_cached_config: Optional[dict] = None
_env_loaded: bool = False

# Matches ${VAR} or ${VAR:-default}
_ENV_PATTERN = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}")


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base*, returning a new dict."""
    merged = dict(base)
    for key, val in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(val, dict):
            merged[key] = _deep_merge(merged[key], val)
        else:
            merged[key] = val
    return merged


def _load_dotenv(path: Path = _DEFAULT_ENV_PATH) -> None:
    """Populate os.environ from a .env file. Existing env vars take precedence."""
    global _env_loaded
    if _env_loaded or not path.exists():
        _env_loaded = True
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val
    _env_loaded = True


def _expand_env(value: Any) -> Any:
    """Recursively substitute ${VAR} / ${VAR:-default} in strings within a config tree."""
    if isinstance(value, str):
        def replace(match: re.Match) -> str:
            var, default = match.group(1), match.group(2)
            return os.environ.get(var, default if default is not None else match.group(0))
        return _ENV_PATTERN.sub(replace, value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def load_raw(path: Path | str | None = None) -> dict:
    """Load config.yaml and return the raw dict (cached after first call)."""
    global _cached_config
    if _cached_config is not None:
        return _cached_config

    _load_dotenv()

    cfg_path = Path(path) if path else _DEFAULT_CONFIG_PATH
    if cfg_path.exists():
        with open(cfg_path) as f:
            raw = yaml.safe_load(f) or {}
        _cached_config = _expand_env(raw)
    else:
        _cached_config = {}
    return _cached_config


def reload(path: Path | str | None = None) -> dict:
    """Force-reload the configuration from disk."""
    global _cached_config
    _cached_config = None
    return load_raw(path)


def get(dotpath: str, default: Any = None, *, config: dict | None = None) -> Any:
    """Retrieve a value using dot-notation (e.g. ``'llm.base_url'``).

    Checks environment variables first:  ``SYSREPAIR_LLM_BASE_URL`` for
    ``llm.base_url``.
    """
    env_key = "SYSREPAIR_" + dotpath.upper().replace(".", "_")
    env_val = os.environ.get(env_key)
    if env_val is not None:
        return env_val

    cfg = config if config is not None else load_raw()
    parts = dotpath.split(".")
    node: Any = cfg
    for part in parts:
        if isinstance(node, dict):
            node = node.get(part)
        else:
            return default
        if node is None:
            return default
    return node


@dataclass
class LLMSettings:
    model: str = "gemma-4-31b"
    base_url: str = "http://localhost:8001/v1"
    api_key: str | None = None
    max_tokens: int = 4096
    temperature: float = 0.3


def llm_settings(phase: str | None = None) -> LLMSettings:
    """Return LLM settings, optionally with phase-specific overrides."""
    cfg = load_raw()
    llm_section = cfg.get("llm", {})
    base = {
        "model": llm_section.get("model", "gemma-4-31b"),
        "base_url": llm_section.get("base_url", "http://localhost:8001/v1"),
        "api_key": llm_section.get("api_key"),
        "max_tokens": llm_section.get("max_tokens", 4096),
        "temperature": llm_section.get("temperature", 0.3),
    }

    _SCALAR_KEYS = {"model", "base_url", "api_key", "max_tokens", "temperature"}
    if phase and llm_section.get(phase):
        override = llm_section[phase]
        if isinstance(override, dict):
            base.update({k: v for k, v in override.items() if v is not None and k in _SCALAR_KEYS})

    # Env-var overrides
    env_url = os.environ.get("SYSREPAIR_LLM_BASE_URL")
    if env_url:
        base["base_url"] = env_url
    env_model = os.environ.get("SYSREPAIR_LLM_MODEL")
    if env_model:
        base["model"] = env_model
    env_key = os.environ.get("SYSREPAIR_LLM_API_KEY")
    if env_key:
        base["api_key"] = env_key

    return LLMSettings(**base)


def neurosymbolic_settings() -> dict:
    """Return the ``neurosymbolic`` section of the config."""
    cfg = load_raw()
    return cfg.get("neurosymbolic", {})


def eval_settings() -> dict:
    """Return the ``eval`` section of the config."""
    cfg = load_raw()
    return cfg.get("eval", {})


def planner_settings() -> dict:
    """Return the ``planner`` section of the config."""
    cfg = load_raw()
    return cfg.get("planner", {})


def project_root() -> Path:
    return _PROJECT_ROOT
