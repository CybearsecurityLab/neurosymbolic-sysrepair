"""Inspect AI task that wraps sysrepair-bench scenarios with the neurosymbolic solver.

Reuses sysrepair-bench's sample construction and scoring, but substitutes our
PDDL-planning solver.

Usage (CLI):
    uv run inspect eval neurosymbolic/task.py:neurosymbolic_bench \
        --model openai/gemma-4-31b \
        -T benchmarks='["ccdc"]' \
        -T domain_path=./pddl_output/phase3/sysadmin_refined.pddl

Usage (preset runner):
    python -m neurosymbolic.run smoke
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure sysrepair-bench's inspect_eval package is importable
_BENCH_EVAL = Path(__file__).resolve().parents[1].parent / "sysrepair-bench" / "inspect_eval"
if str(_BENCH_EVAL) not in sys.path:
    sys.path.insert(0, str(_BENCH_EVAL))

from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset

from sysrepair_bench.task import _build_sample, _discover_scenarios, REPO_ROOT  # noqa: E402
from sysrepair_bench.scorer import dispatch_scorer  # noqa: E402
from sysrepair_bench.rate_limiter import init_rate_limiter  # noqa: E402

# Inspect AI loads this file via importlib (file path) without package context,
# so relative imports break under `inspect eval`. The package import path
# (`python -m neurosymbolic.run`) still works. Try both.
try:
    from .solver import neurosymbolic_solver
except ImportError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
    from neurosymbolic.solver import neurosymbolic_solver


@task
def neurosymbolic_bench(
    benchmarks: list[str] | None = None,
    scenarios: list[str] | None = None,
    mode: str = "day1",
    message_limit: int = 50,
    time_limit: int | None = None,
    token_limit: int | None = None,
    bash_timeout: int = 240,
    verify_timeout: int = 360,
    request_limit: int = 0,
    request_window: int = 18_000,
    domain_path: str = "",
    fd_path: str = "/home/resbears/fast_downward/fast-downward.py",
    plan_timeout: int = 120,
    enable_llm_fallback: bool = True,
) -> Task:
    """SysRepair-Bench evaluated with the neurosymbolic PDDL solver.

    Parameters
    ----------
    benchmarks : list[str]
        Subset of ["meta2", "vulnhub", "ccdc", "meta3/ubuntu", "meta4"].
    scenarios : list[str]
        Explicit scenario paths (overrides benchmarks).
    mode : str
        "day1" (full briefing) or "zero_day" (blind discovery).
    domain_path : str
        Path to the PDDL domain produced by the Phase 1-3 pipeline.
    fd_path : str
        Path to Fast Downward planner.
    plan_timeout : int
        Seconds to allow Fast Downward per planning call.
    enable_llm_fallback : bool
        Fall back to ReAct loop when planner fails.
    """
    if mode not in ("day1", "zero_day"):
        raise ValueError(f"mode must be 'day1' or 'zero_day', got '{mode}'")

    init_rate_limiter(request_limit=request_limit, window_seconds=request_window)

    scenario_dirs = _discover_scenarios(benchmarks, scenarios)
    if not scenario_dirs:
        raise ValueError("No scenarios matched the given filters.")
    samples = [_build_sample(d, mode=mode) for d in scenario_dirs]

    return Task(
        dataset=MemoryDataset(samples=samples, name="neurosymbolic-bench"),
        solver=neurosymbolic_solver(
            message_limit=message_limit,
            bash_timeout=bash_timeout,
            verify_timeout=verify_timeout,
            domain_path=domain_path,
            fd_path=fd_path,
            plan_timeout=plan_timeout,
            enable_llm_fallback=enable_llm_fallback,
        ),
        scorer=dispatch_scorer(),
        message_limit=message_limit,
        time_limit=time_limit or None,
        token_limit=token_limit or None,
    )
