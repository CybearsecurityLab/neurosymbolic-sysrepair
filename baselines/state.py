"""Shared dataclasses and pydantic models used across all baselines and the eval harness."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from pydantic import BaseModel


# ---------------------------------------------------------------------------
# CommandRecord
# ---------------------------------------------------------------------------

@dataclass
class CommandRecord:
    """Represents one bash command execution."""
    step: int
    command: str
    stdout: str
    stderr: str
    exit_code: int
    timestamp: float = field(default_factory=time.time)   # time.time() at execution start
    duration_ms: float = 0.0
    is_hallucination: bool = False    # set by HallucinationJudge post-run
    is_false_assumption: bool = False  # set by BaseAgent._detect_false_assumption() at exec time


# ---------------------------------------------------------------------------
# ReflectionRecord
# ---------------------------------------------------------------------------

@dataclass
class ReflectionRecord:
    """One reflection cycle in the Reflexion baseline."""
    cycle: int
    generator_commands: list[CommandRecord]
    reflection_text: str
    correction_strategy: str


# ---------------------------------------------------------------------------
# TreeNode
# ---------------------------------------------------------------------------

@dataclass
class TreeNode:
    """LATS Monte Carlo Tree Search node."""
    node_id: str           # uuid
    parent_id: str | None
    command: str           # command executed to reach this node (empty for root)
    stdout: str
    stderr: str
    exit_code: int
    value: float = 0.0     # backpropagated score
    visit_count: int = 0
    is_terminal: bool = False
    is_fatal: bool = False
    children: list[str] = field(default_factory=list)  # list of child node_ids
    depth: int = 0


# ---------------------------------------------------------------------------
# PlanStep / StepResult
# ---------------------------------------------------------------------------

@dataclass
class PlanStep:
    """One step in a Plan-and-Solve plan."""
    id: int
    description: str
    command_hint: str


@dataclass
class StepResult:
    """Result of executing one PlanStep."""
    step_id: int
    commands: list[CommandRecord]
    success: bool
    retry_count: int = 0


# ---------------------------------------------------------------------------
# AgentResult
# ---------------------------------------------------------------------------

@dataclass
class AgentResult:
    """Final result returned by any BaseAgent.run()."""
    baseline: str
    model: str
    scenario_id: str
    commands: list[CommandRecord]       # ALL commands executed (cumulative)
    wall_time_seconds: float
    declared_done: bool                 # agent output REMEDIATION_COMPLETE
    forced_halt: bool                   # hit iteration limit
    # Baseline-specific optional fields
    plan: list[PlanStep] | None = None
    plan_length: int | None = None
    steps_wasted: int | None = None
    reflection_cycles: int | None = None
    reflections: list[ReflectionRecord] | None = None
    tree_nodes_visited: int | None = None
    lats_rollout_count: int | None = None


# ---------------------------------------------------------------------------
# Hallucination judge pydantic models
# ---------------------------------------------------------------------------

class HallucinationLabel(BaseModel):
    """Per-command label from the LLM hallucination judge."""
    index: int
    is_hallucination: bool
    reason: str


class HallucinationLabelResponse(BaseModel):
    """Full response from the LLM hallucination judge."""
    labels: list[HallucinationLabel]
