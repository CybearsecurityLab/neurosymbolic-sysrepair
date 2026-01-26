"""
Phase 3: Iterative Refinement via Exploration Walks

This phase takes the candidate PDDL domain from Phase 2 and iteratively refines it
using the Exploration Walk (EW) metric. The refinement loop:
1. Generates random valid action sequences using Fast Downward
2. Executes actions in a sandboxed Ubuntu 25.10 Docker container
3. Compares PDDL predicted effects vs actual environment outcomes
4. Uses LLM to update the domain based on discrepancies
5. Repeats until EW score > 0.9
"""

from .orchestrator import Phase3Orchestrator
from .config import Phase3Config, DockerConfig, PlannerConfig
from .refiner import DomainRefiner

__all__ = [
    "Phase3Orchestrator",
    "Phase3Config",
    "DockerConfig",
    "PlannerConfig",
    "DomainRefiner",
]
