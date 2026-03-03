"""
Data models for Phase 3: Iterative Refinement via Exploration Walks
"""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
from datetime import datetime


class ActionOutcome(Enum):
    """Outcome of executing an action in the environment."""
    SUCCESS = "success"  # Action executed, effects match PDDL prediction
    EXECUTION_FAILED = "execution_failed"  # Command failed to execute
    PRECONDITION_MISMATCH = "precondition_mismatch"  # Preconditions not met in env
    EFFECT_MISMATCH = "effect_mismatch"  # Action ran but effects don't match
    TIMEOUT = "timeout"  # Execution timed out
    UNKNOWN = "unknown"  # Could not determine outcome


@dataclass
class PDDLAction:
    """Parsed PDDL action from the domain."""
    name: str
    parameters: list[tuple[str, str]]  # [(var_name, type_name), ...]
    preconditions: list[str]
    effects: list[str]
    raw_pddl: str = ""


@dataclass
class GroundedAction:
    """A PDDL action with concrete parameter bindings."""
    action: PDDLAction
    bindings: dict[str, str]  # {?var -> concrete_value}

    @property
    def name(self) -> str:
        return self.action.name

    def get_grounded_name(self) -> str:
        """Return action name with bound parameters."""
        params = " ".join(self.bindings.get(p[0], p[0]) for p in self.action.parameters)
        return f"({self.action.name} {params})"


@dataclass
class ExecutionResult:
    """Result of executing a single action in the environment."""
    action: GroundedAction
    command: str  # The bash command that was executed
    exit_code: int
    stdout: str
    stderr: str
    execution_time: float  # seconds
    outcome: ActionOutcome

    # Effect verification
    expected_effects: list[str] = field(default_factory=list)
    actual_effects: list[str] = field(default_factory=list)
    mismatched_effects: list[str] = field(default_factory=list)


@dataclass
class ExplorationWalk:
    """A single exploration walk (sequence of actions)."""
    walk_id: int
    planned_actions: list[GroundedAction]
    executed_actions: list[ExecutionResult]

    # Walk metrics
    steps_planned: int = 0
    steps_executed: int = 0
    steps_successful: int = 0

    # Termination
    terminated_early: bool = False
    termination_reason: str = ""

    def calculate_success_rate(self) -> float:
        """Calculate success rate for this walk."""
        if self.steps_executed == 0:
            return 0.0
        return self.steps_successful / self.steps_executed


@dataclass
class Discrepancy:
    """A discrepancy between PDDL model and environment."""
    action_name: str
    discrepancy_type: str  # "precondition", "effect", "execution"
    expected: str
    actual: str
    context: str  # Additional context for debugging
    severity: str = "medium"  # "low", "medium", "high"

    def to_feedback_string(self) -> str:
        """Format as feedback for LLM."""
        return (
            f"Action: {self.action_name}\n"
            f"Type: {self.discrepancy_type}\n"
            f"Expected: {self.expected}\n"
            f"Actual: {self.actual}\n"
            f"Context: {self.context}"
        )


@dataclass
class EWScore:
    """Exploration Walk score calculation result."""
    score: float  # The EW(d) value between 0 and 1
    num_walks: int  # N
    max_depth: int  # T_max
    total_steps: int
    successful_steps: int

    # Breakdown by walk
    walk_scores: list[float] = field(default_factory=list)

    # Discrepancies found
    discrepancies: list[Discrepancy] = field(default_factory=list)

    def meets_target(self, target: float = 0.9) -> bool:
        return self.score >= target


@dataclass
class RefinementIteration:
    """Record of a single refinement iteration."""
    iteration: int
    timestamp: datetime

    # Input
    domain_before: str

    # EW evaluation
    ew_score: EWScore

    # Refinement
    domain_after: str
    changes_made: list[str]

    # Timing
    evaluation_time: float  # seconds
    refinement_time: float  # seconds

    def improved(self, previous_score: float) -> bool:
        return self.ew_score.score > previous_score


@dataclass
class RefinementSession:
    """Complete refinement session state."""
    session_id: str
    started_at: datetime

    # Configuration
    target_score: float
    max_iterations: int

    # Initial state
    initial_domain: str
    problem_pddl: str

    # Progress
    iterations: list[RefinementIteration] = field(default_factory=list)
    current_domain: str = ""
    current_score: float = 0.0

    # Final state
    completed: bool = False
    success: bool = False
    final_domain: str = ""
    final_score: float = 0.0
    total_time: float = 0.0

    def get_latest_iteration(self) -> Optional[RefinementIteration]:
        return self.iterations[-1] if self.iterations else None

    def get_score_history(self) -> list[float]:
        return [it.ew_score.score for it in self.iterations]


@dataclass
class EnvironmentState:
    """Snapshot of environment state for PDDL grounding."""
    packages: list[dict]  # [{name, version, installed}]
    services: list[dict]  # [{name, active, enabled}]
    users: list[dict]  # [{name, uid, groups}]
    groups: list[dict]  # [{name, gid, members}]
    files: list[dict]  # [{path, exists, permissions}]

    def get_objects_by_type(self, type_name: str) -> list[str]:
        """Get object names for a given PDDL type."""
        type_map = {
            "package": [p["name"] for p in self.packages],
            "service": [s["name"] for s in self.services],
            "user": [u["name"] for u in self.users],
            "group": [g["name"] for g in self.groups],
            "file": [f["path"] for f in self.files],
            "directory": [f["path"] for f in self.files if f.get("is_dir")],
        }
        result = type_map.get(type_name)
        if result is not None:
            return result

        # "object" is the PDDL supertype — return all available objects
        if type_name == "object":
            all_objects = []
            for key in ("user", "package", "service", "group", "file"):
                all_objects.extend(type_map.get(key, []))
            return all_objects

        return []
