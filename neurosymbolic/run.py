"""Run a named preset from neurosymbolic/runs.yaml.

Usage:
    python -m neurosymbolic.run <preset>
    python -m neurosymbolic.run smoke
    python -m neurosymbolic.run day1
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import yaml
from inspect_ai import eval as inspect_eval

from .task import neurosymbolic_bench

DEFAULT_RUNS = Path(__file__).resolve().parent / "runs.yaml"

# Shared base images needed by meta2 scenarios.
BENCH_ROOT = Path(__file__).resolve().parents[1].parent / "sysrepair-bench"
BASE_IMAGES = {
    "sysrepair/meta2-hardy:latest": BENCH_ROOT / "meta2" / "_base",
}


def _ensure_base_images(cfg: dict) -> None:
    benchmarks = cfg.get("benchmarks") or []
    scenarios = cfg.get("scenarios") or []
    touches_meta2 = (
        "meta2" in benchmarks
        or any(s.startswith("meta2/") for s in scenarios)
        or not benchmarks and not scenarios
    )
    if not touches_meta2:
        return
    tag = "sysrepair/meta2-hardy:latest"
    ctx = BASE_IMAGES[tag]
    if not ctx.exists():
        return
    probe = subprocess.run(
        ["docker", "image", "inspect", tag],
        capture_output=True, text=True,
    )
    if probe.returncode == 0:
        return
    print(f"[pre-build] {tag} missing; building from {ctx} ...")
    subprocess.run(["docker", "build", "-t", tag, str(ctx)], check=True)


def _load(runs_path: Path, preset_name: str) -> dict:
    cfg = yaml.safe_load(runs_path.read_text(encoding="utf-8")) or {}
    presets = cfg.get("presets", {})
    if preset_name not in presets:
        raise SystemExit(
            f"Preset '{preset_name}' not in {runs_path}. "
            f"Available: {sorted(presets)}"
        )
    return {**(cfg.get("defaults") or {}), **presets[preset_name]}


# Keys forwarded to neurosymbolic_bench()
_TASK_KEYS = (
    "benchmarks", "scenarios", "message_limit", "time_limit", "token_limit",
    "bash_timeout", "verify_timeout", "request_limit", "request_window",
    "domain_path", "fd_path", "plan_timeout", "enable_llm_fallback",
)

# Keys forwarded to inspect_eval()
_EVAL_KEYS = (
    "max_connections", "log_dir", "fail_on_error", "max_samples",
    "max_tasks", "retry_on_error",
)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="Run neurosymbolic solver presets")
    p.add_argument("preset", help="Preset name in runs.yaml")
    p.add_argument("--runs", default=str(DEFAULT_RUNS), help="Path to runs.yaml")
    args = p.parse_args(argv)

    cfg = _load(Path(args.runs), args.preset)
    _ensure_base_images(cfg)

    if "model" not in cfg:
        raise SystemExit(f"Preset '{args.preset}' missing required 'model' field.")

    modes = cfg.get("modes") or ([cfg.get("mode", "day1")])
    task_kwargs = {k: cfg[k] for k in _TASK_KEYS if k in cfg}
    eval_kwargs = {k: cfg[k] for k in _EVAL_KEYS if k in cfg}

    for i, mode in enumerate(modes):
        print(f"\n=== [{i+1}/{len(modes)}] model={cfg['model']} mode={mode} ===")
        inspect_eval(
            neurosymbolic_bench(mode=mode, **task_kwargs),
            model=cfg["model"],
            **eval_kwargs,
        )


if __name__ == "__main__":
    main(sys.argv[1:])
