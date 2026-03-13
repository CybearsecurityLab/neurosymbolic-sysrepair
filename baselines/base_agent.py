"""Abstract base class shared by all baseline agents."""

from __future__ import annotations

import json
import re
import time
from abc import ABC, abstractmethod
from typing import Callable

from .llm_client import LLMClient, MODEL_REGISTRY
from .state import CommandRecord, AgentResult


class BaseAgent(ABC):
    """Abstract base for all remediation agents.

    Parameters
    ----------
    model:
        Key into MODEL_REGISTRY identifying which LLM to use.
    exec_fn:
        Callable that takes a bash command string and returns a
        ``CommandRecord`` with ``stdout``, ``stderr``, and ``exit_code``
        already populated (curried with the target container id).
    base_url:
        Base URL for the OpenAI-compatible Ollama endpoint.
    """

    def __init__(
        self,
        model: str,
        exec_fn: Callable[[str], CommandRecord],
        base_url: str = "http://localhost:11434/v1",
    ) -> None:
        self.model = model
        self.llm = LLMClient(model, base_url)
        self._exec_fn = exec_fn
        self.commands: list[CommandRecord] = []

    @abstractmethod
    def run(self, system_prompt: str) -> AgentResult:
        """Execute the full remediation loop.

        ``system_prompt`` already contains the vulnerability description and
        OS context assembled by the eval harness.
        """

    # ------------------------------------------------------------------
    # Execution helpers
    # ------------------------------------------------------------------

    def bash(self, cmd: str, step: int) -> CommandRecord:
        """Execute *cmd*, annotate the record, append to history, and return it."""
        t0 = time.time()
        record = self._exec_fn(cmd)          # stdout/stderr/exit_code set by exec_fn
        record.step = step
        record.timestamp = t0
        record.duration_ms = (time.time() - t0) * 1000
        record.is_hallucination = False      # set later by HallucinationJudge
        record.is_false_assumption = self._detect_false_assumption(record)
        self.commands.append(record)
        return record

    def _detect_false_assumption(self, r: CommandRecord) -> bool:
        """Return True when the command failed due to a state-mismatch assumption."""
        if r.exit_code == 0:
            return False
        patterns = [
            r"Unit .+ not loaded",
            r"Failed to (start|stop|restart|enable|disable)",
            r"service not found",
            r"No such file or directory",
            r"is not running",
            r"already (installed|enabled|disabled|stopped|active)",
            r"nothing to (do|upgrade|remove)",
            r"dpkg: warning.+not installed",
            r"E: Package .+ has no installation candidate",
        ]
        text = r.stderr + r.stdout
        return any(re.search(p, text, re.IGNORECASE) for p in patterns)

    def _is_done(self, record: CommandRecord) -> bool:
        """Return True when the agent has signalled completion via REMEDIATION_COMPLETE."""
        return (
            "REMEDIATION_COMPLETE" in record.stdout
            or "REMEDIATION_COMPLETE" in record.stderr
        )

    def _parse_tool_call(self, response) -> str | None:
        """Extract the bash command from an OpenAI tool-call response.

        Returns ``None`` if the response contains no tool call.
        """
        msg = response.choices[0].message
        if not msg.tool_calls:
            return None
        tc = msg.tool_calls[0]
        if tc.function.name == "bash":
            args = json.loads(tc.function.arguments)
            return args.get("command", "")
        return None
