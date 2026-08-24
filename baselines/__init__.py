"""baselines package – LLM-based remediation agent implementations.

Public API
----------
baseline_factory(baseline_name, model, exec_fn) -> BaseAgent
    Instantiate a baseline agent by name.
"""

from __future__ import annotations

from typing import Callable

from .base_agent import BaseAgent
from .lats import LATSAgent
from .llm_client import MODEL_REGISTRY
from .plan_and_solve import PlanAndSolveAgent
from .raw_computer_use import RawComputerUseAgent
from .react import ReActAgent
from .reflexion import ReflexionAgent
from .state import (
    AgentResult,
    CommandRecord,
    HallucinationLabel,
    HallucinationLabelResponse,
    PlanStep,
    ReflectionRecord,
    StepResult,
    TreeNode,
)

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_BASELINE_REGISTRY: dict[str, type[BaseAgent]] = {
    "raw": RawComputerUseAgent,
    "react": ReActAgent,
    "plan_and_solve": PlanAndSolveAgent,
    "reflexion": ReflexionAgent,
    "lats": LATSAgent,
}


def baseline_factory(
    baseline_name: str,
    model: str,
    exec_fn: Callable,
    base_url: str = "http://10.100.203.130:11434/v1",
    verify_fn: Callable | None = None,
) -> BaseAgent:
    """Instantiate a baseline agent by name.

    Parameters
    ----------
    baseline_name:
        One of ``"raw"``, ``"react"``, ``"plan_and_solve"``, ``"reflexion"``,
        ``"lats"``.
    model:
        Key into ``MODEL_REGISTRY`` (e.g. ``"mistral-large-3"``).
    exec_fn:
        Callable ``(cmd: str) -> CommandRecord`` already curried with the
        target container id.
    base_url:
        Base URL for the OpenAI-compatible Ollama endpoint.

    Returns
    -------
    BaseAgent
        An uninvoked agent instance ready for ``.run(system_prompt)``.

    Raises
    ------
    ValueError
        If *baseline_name* or *model* is not recognised.
    """
    if baseline_name not in _BASELINE_REGISTRY:
        raise ValueError(
            f"Unknown baseline '{baseline_name}'. "
            f"Available: {sorted(_BASELINE_REGISTRY)}"
        )
    if model not in MODEL_REGISTRY:
        raise ValueError(
            f"Unknown model key '{model}'. "
            f"Available: {sorted(MODEL_REGISTRY)}"
        )
    cls = _BASELINE_REGISTRY[baseline_name]
    return cls(model=model, exec_fn=exec_fn, base_url=base_url, verify_fn=verify_fn)


__all__ = [
    # Factory
    "baseline_factory",
    # Agents
    "BaseAgent",
    "RawComputerUseAgent",
    "ReActAgent",
    "PlanAndSolveAgent",
    "ReflexionAgent",
    "LATSAgent",
    # State types
    "AgentResult",
    "CommandRecord",
    "HallucinationLabel",
    "HallucinationLabelResponse",
    "PlanStep",
    "ReflectionRecord",
    "StepResult",
    "TreeNode",
    # Registry
    "MODEL_REGISTRY",
]
