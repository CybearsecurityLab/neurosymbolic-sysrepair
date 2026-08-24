#!/usr/bin/env python3
"""
Pipeline Runner: Phase 1 + Phase 2 + Phase 3 against scenario containers.

Operates on one or more benchmark scenarios. For each scenario, a fresh
Docker container is spawned per phase from the scenario's own image:

  Phase 1: System Introspection (osquery + man-page mining) — runs inside container
  Phase 2: Parallel Synthesis   (LLM Map-Reduce)             — fetches docs from container
  Phase 3: Iterative Refinement (Exploration Walks)          — executes actions in container

Scenario selection (combine freely):
  --bench <path>            Benchmark root (default: eval.bench_path from config.yaml)
  --collection ccdc|meta2   Restrict to a sub-folder of the bench
  --scenarios id1,id2,...   Explicit scenario IDs
  --scenarios-file <path>   Newline-delimited file of scenario IDs
"""

import sys
import json
import argparse
import logging
import os
import time
from pathlib import Path
from datetime import datetime
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))


def _configure_llm_debug_logging() -> None:
    """Enable request/response logging for OpenAI-compatible API traffic.

    Triggered by --debug-llm (or LLM_DEBUG=1). httpx logs every request line;
    openai logs full request/response bodies (so you can see exactly what the
    model is generating, including any pre-JSON reasoning text).
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s/%(levelname)s] %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.INFO)
    logging.getLogger("openai").setLevel(logging.DEBUG)

from common import config_loader
from common.scenarios import Scenario, select_scenarios, load_all_scenarios
from common.container import ScenarioContainerManager


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║   NEUROSYMBOLIC PDDL DOMAIN GENERATOR — scenario containers                  ║
║   Phase 1: System Introspection   Phase 2: Synthesis   Phase 3: Refinement   ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")


def run_phase1(output_dir: Path, container, llm_settings) -> dict:
    print("\n" + "=" * 70)
    print("PHASE 1: SYSTEM INTROSPECTION (scenario container)")
    print("=" * 70)

    from phase1.orchestrator import Phase1Orchestrator, EnumEncoder

    import os as _os
    # Phase-1 man-page mining is LLM-bound and was serial (default 1 worker),
    # pinning the account to concurrency 1 during its longest phase. Mine
    # utilities in parallel up to the MiniMax per-account concurrent cap (~6).
    # Chunk-level langextract workers are pinned to 1 (see manpage_parser), so
    # total in-flight requests equals this worker count exactly.
    phase1_workers = int(_os.environ.get("NEUROPLAN_PHASE1_WORKERS", "6"))
    orchestrator = Phase1Orchestrator(
        output_dir=str(output_dir),
        llm_model=llm_settings.model,
        llm_url=llm_settings.base_url,
        llm_api_key=llm_settings.api_key or "vllm",
        container=container,
        max_llm_workers=phase1_workers,
    )
    results = orchestrator.run()

    # objects/predicates/relationships/actions live under results["phase1_state"]
    # (Phase1State.to_dict()), NOT at the top level of results.
    state = results.get("phase1_state") or {}

    state_file = output_dir / "phase1_state.json"
    with open(state_file, "w") as f:
        # EnumEncoder handles PDDLType values inside serialized action parameters.
        json.dump(
            {
                "objects": state.get("objects", {}),
                "predicates": state.get("predicates", []),
                "relationships": state.get("relationships", {}),
                "actions": state.get("actions", results.get("actions", [])),
                "metadata": state.get("metadata", {}),
                "statistics": results.get("statistics", {}),
            },
            f,
            indent=2,
            cls=EnumEncoder,
        )

    obj_total = sum(len(v) for v in state.get("objects", {}).values())
    print(f"[OK] Phase 1 state saved to: {state_file} "
          f"(objects={obj_total}, predicates={len(state.get('predicates', []))}, "
          f"actions={len(state.get('actions', []))})")
    # Hand the structured state to Phase 2 directly.
    results["_state"] = state
    return results


def run_phase2(output_dir: Path, phase1_results: dict, container, llm_settings,
               reuse_phase1_actions: bool = False) -> dict:
    print("\n" + "=" * 70)
    print("PHASE 2: PARALLEL SYNTHESIS (scenario container)")
    print("=" * 70)

    from phase2.orchestrator import Phase2Orchestrator
    from phase2.config import HardwareConfig, LLMConfig
    from common.models import Phase1State

    hardware = HardwareConfig.detect()
    # Cap phase-2 map-reduce concurrency to the MiniMax Token-Plan limit (~4-5
    # agents). The auto-detected worker count (CPU/GPU-based) hit ~7 and 429'd,
    # dropping whole action groups from the synthesized domain. Overridable via
    # NEUROPLAN_MAX_WORKERS.
    import os as _os
    # Phase-2 synthesis is LLM-API-bound, not CPU-bound: the binding limit is the
    # MiniMax per-account concurrent cap (~6), not local cores/RAM. The hardware
    # auto-detect caps at 4, so min()-ing with it throttled the API to 4 even when
    # asked for more. Set the group-worker count directly from NEUROPLAN_MAX_WORKERS
    # (default 6). Chunk-level workers stay at 1, so total in-flight == this count.
    hardware.max_parallel_workers = int(_os.environ.get("NEUROPLAN_MAX_WORKERS", "6"))
    llm_config = LLMConfig(
        model_name=llm_settings.model,
        base_url=llm_settings.base_url,
        api_key=llm_settings.api_key or "vllm",
        max_tokens=llm_settings.max_tokens,
        temperature=llm_settings.temperature,
    )

    state = phase1_results.get("_state") or phase1_results.get("phase1_state") or {}
    phase1_state = Phase1State(
        objects=state.get("objects", {}),
        predicates=state.get("predicates", []),
        relationships=state.get("relationships", {}),
        actions=state.get("actions", []),
        metadata=state.get("metadata", {}),
    )
    obj_total = sum(len(v) for v in phase1_state.objects.values())
    print(f"[*] Phase 1 → Phase 2 handoff: objects={obj_total}, "
          f"predicates={len(phase1_state.predicates)}, actions={len(phase1_state.actions)}")

    if reuse_phase1_actions:
        print(f"[*] Reusing Phase 1 actions as merge candidates "
              f"({len(phase1_state.actions)} actions; LLM still generates, merger picks best)")
    orchestrator = Phase2Orchestrator(
        hardware_config=hardware,
        llm_config=llm_config,
        phase1_state=phase1_state,
        output_dir=str(output_dir),
        container=container,
        reuse_phase1_actions=reuse_phase1_actions,
    )
    return orchestrator.run()


def run_phase3(
    output_dir: Path,
    domain_path: Path,
    problem_path: Path,
    scenario_image: str,
    target_score: float,
    max_iterations: int,
    llm_settings=None,
) -> dict:
    print("\n" + "=" * 70)
    print("PHASE 3: ITERATIVE REFINEMENT (scenario container)")
    print("=" * 70)

    from phase3 import Phase3Orchestrator, Phase3Config

    config = Phase3Config()
    config.input_domain_path = str(domain_path)
    config.input_problem_path = str(problem_path)
    config.output_dir = str(output_dir / "phase3")
    config.ew_target_score = target_score
    config.max_refinement_iterations = max_iterations
    # Override planner path from config.yaml (default is a foreign absolute path).
    fd_path = config_loader.get("planner.fast_downward_path")
    if fd_path:
        config.planner.fast_downward_path = fd_path
    # Point the action concretizer at THIS scenario's Phase 1 metadata
    # (command templates). The default is a static, scenario-unaware path
    # that ends up reading stale data from earlier runs.
    config.phase1_metadata_path = str(output_dir / "phase1_statep2.json")
    # CRITICAL: Phase3Config.llm defaults to localhost:8001 (vLLM) — Phase 3
    # would silently call a dead local endpoint and every LLM call returns
    # ECONNREFUSED. Point it at the same provider Phase 1/2 use.
    if llm_settings is not None:
        config.llm.base_url = llm_settings.base_url
        config.llm.api_key = llm_settings.api_key or "vllm"
        config.llm.model_name = llm_settings.model
        config.llm.concretizer_model = llm_settings.model
        if llm_settings.max_tokens:
            config.llm.max_tokens = llm_settings.max_tokens
        config.llm.temperature = llm_settings.temperature
    print(f"  Phase 3 LLM: {config.llm.model_name} @ {config.llm.base_url}")

    orchestrator = Phase3Orchestrator(config=config, scenario_image=scenario_image)
    return orchestrator.run()


def generate_report(
    output_dir: Path,
    scenario_id: str,
    phase1_results: dict,
    phase2_results: dict,
    elapsed_time: float,
    phase3_results: Optional[dict] = None,
) -> dict:
    report = {
        "scenario": scenario_id,
        "timestamp": datetime.now().isoformat(),
        "elapsed_time_seconds": elapsed_time,
        "phase1": {
            "success": phase1_results.get("success", False),
            "statistics": phase1_results.get("statistics", {}),
        },
        "phase2": {
            "success": phase2_results.get("success", False),
            "statistics": phase2_results.get("statistics", {}),
            "validation_passed": phase2_results.get("validation_passed", False),
        },
        "outputs": {
            "domain_file": str(output_dir / "sysadmin.pddl"),
            "problem_file": str(output_dir / "sysadmin_problem.pddl"),
        },
    }
    if phase3_results:
        report["phase3"] = {
            "success": phase3_results.get("success", False),
            "final_score": phase3_results.get("final_score", 0.0),
            "target_achieved": phase3_results.get("target_achieved", False),
            "iterations": phase3_results.get("iterations", 0),
        }
        report["outputs"]["refined_domain_file"] = str(output_dir / "phase3" / "sysadmin_refined.pddl")

    report_file = output_dir / "pipeline_report.json"
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)

    print("\n" + "=" * 70)
    print(f"SCENARIO COMPLETE — {scenario_id}")
    print("=" * 70)
    print(f"  Elapsed: {elapsed_time:.1f}s")
    print(f"  Phase 1: {'OK' if phase1_results.get('success') else 'FAIL'}  "
          f"Phase 2: {'OK' if phase2_results.get('success') else 'FAIL'}  "
          f"Phase 3: {('OK' if phase3_results.get('success') else 'FAIL') if phase3_results else '-'}")
    print(f"  Report:  {report_file}")
    return report


def validate_final_pddl(domain_path: Path) -> tuple:
    try:
        from pddl import parse_domain
    except ImportError:
        return True, "pddl library not installed — skipping validation"
    try:
        parse_domain(str(domain_path))
        return True, "Domain syntax validated"
    except Exception as e:
        msg = str(e)
        return False, f"Parse error: {msg[:300]}"



def resolve_scenarios(args, default_bench: str) -> list[Scenario]:
    bench = Path(args.bench or default_bench)
    if not bench.exists():
        raise SystemExit(f"Benchmark path does not exist: {bench}")

    ids = None
    if args.scenarios:
        ids = [s.strip() for s in args.scenarios.split(",") if s.strip()]

    scenarios = select_scenarios(
        bench_path=bench,
        collection=args.collection,
        ids=ids,
        scenarios_file=args.scenarios_file,
    )
    if not scenarios:
        # Helpful diagnostic
        all_s = load_all_scenarios(bench)
        available = ", ".join(s.id for s in all_s) or "(none)"
        raise SystemExit(
            f"No scenarios matched. Bench={bench}, collection={args.collection}, "
            f"ids={ids}, file={args.scenarios_file}.\nAvailable: {available}"
        )
    return scenarios



def run_one_scenario(
    scenario: Scenario,
    output_root: Path,
    mgr: ScenarioContainerManager,
    args,
    llm_settings,
) -> int:
    print("\n" + "#" * 78)
    print(f"#  SCENARIO: {scenario.id}  —  {scenario.title}")
    print(f"#  collection={scenario.collection}  base_image={scenario.base_image}")
    print("#" * 78)

    output_dir = output_root / scenario.id
    output_dir.mkdir(parents=True, exist_ok=True)
    start = time.time()

    # Build the scenario image once; each phase spawns a fresh container off of it.
    image_tag = mgr.build_image(scenario)
    print(f"[OK] Scenario image: {image_tag}")

    # -------- Phase 1 (fresh container) --------
    if args.skip_phase1 and args.phase1_state:
        print(f"\n[*] Loading existing Phase 1 state: {args.phase1_state}")
        with open(args.phase1_state) as f:
            loaded = json.load(f)
        # phase1_state.json is a flat {objects,predicates,...} dict; wrap it so
        # run_phase2 finds it under the expected "_state" key.
        state = loaded.get("_state") or loaded.get("phase1_state") or loaded
        phase1_results = {"success": True, "_state": state,
                          "statistics": loaded.get("statistics", {})}
    else:
        with mgr.container_for(scenario, phase="phase1") as c:
            phase1_results = run_phase1(output_dir, c, llm_settings)

    # -------- Phase 2 (fresh container) --------
    domain_path = output_dir / "sysadmin.pddl"
    problem_path = output_dir / "sysadmin_problem.pddl"
    if args.skip_phase2:
        # When Phase 2 is skipped but a prior domain exists on disk, treat it
        # as available so Phase 3 can run against it.
        reuse = domain_path.exists()
        print(f"\n[*] Phase 2 skipped (--skip-phase2)"
              + (f"; reusing existing {domain_path.name}" if reuse else ""))
        phase2_results = {"success": reuse, "skipped": True, "reused_existing": reuse}
    else:
        with mgr.container_for(scenario, phase="phase2") as c:
            phase2_results = run_phase2(output_dir, phase1_results, c, llm_settings,
                                        reuse_phase1_actions=args.reuse_phase1_actions)

    # Phase 2's orchestrator now runs the environment-enrichment pass
    # internally (so single-phase runs and the full pipeline both benefit).
    # No explicit enrichment call needed here.

    # -------- Phase 3 (its own container, built from the scenario image) --------
    phase3_results = None
    if phase2_results.get("success") and not args.skip_phase3 and domain_path.exists():
        phase3_results = run_phase3(
            output_dir=output_dir,
            domain_path=domain_path,
            problem_path=problem_path,
            scenario_image=image_tag,
            target_score=args.ew_target,
            max_iterations=args.max_refinement_iterations,
            llm_settings=llm_settings,
        )
    elif args.skip_phase3:
        print("\n[*] Phase 3 skipped (--skip-phase3)")

    # -------- Final PDDL gate --------
    final_domain = None
    if phase3_results and phase3_results.get("domain_path"):
        final_domain = Path(phase3_results["domain_path"])
    elif phase2_results.get("success"):
        final_domain = domain_path
    if final_domain and final_domain.exists():
        valid, msg = validate_final_pddl(final_domain)
        print(f"[{'OK' if valid else 'WARN'}] {msg}")

    elapsed = time.time() - start
    generate_report(output_dir, scenario.id, phase1_results, phase2_results, elapsed, phase3_results)

    if not phase2_results.get("success"):
        return 1
    if phase3_results and not phase3_results.get("success"):
        return 2
    return 0



def main():
    parser = argparse.ArgumentParser(
        description="Run the auto-sysrepair pipeline against benchmark scenarios.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all CCDC scenarios from the configured bench path
  python run_pipeline.py --collection ccdc

  # Run two specific scenarios
  python run_pipeline.py --scenarios ccdc-01,meta2-16

  # Use a custom bench root + scenarios file
  python run_pipeline.py --bench /tmp/my-bench --scenarios-file scen.txt

  # Skip refinement (Phase 3)
  python run_pipeline.py --scenarios ccdc-01 --skip-phase3
""",
    )

    eval_cfg = config_loader.eval_settings()

    parser.add_argument("--bench", default=None,
                        help=f"Benchmark root (default: {eval_cfg.get('bench_path')})")
    parser.add_argument("--collection", choices=["ccdc", "meta2", "vulnhub"], default=None,
                        help="Restrict to a sub-folder of the bench")
    parser.add_argument("--scenarios", default=None,
                        help="Comma-separated scenario IDs (e.g. ccdc-01,meta2-16)")
    parser.add_argument("--scenarios-file", default=None,
                        help="File with one scenario ID per line")

    parser.add_argument("--output-dir", "-o", default="./pddl_output",
                        help="Root output directory (one sub-dir per scenario)")
    parser.add_argument("--install-osquery", action="store_true",
                        help="Inject an osquery install layer into each scenario image")
    parser.add_argument("--debug-llm", action="store_true",
                        help="Print full LLM request/response bodies to stderr "
                             "(also enabled by setting LLM_DEBUG=1)")

    parser.add_argument("--skip-phase1", action="store_true",
                        help="Skip Phase 1 and reuse --phase1-state")
    parser.add_argument("--phase1-state", default=None,
                        help="Existing Phase 1 state JSON to reuse")
    parser.add_argument("--reuse-phase1-actions", action="store_true",
                        help="Feed Phase 1's mined actions into Phase 2 as merge "
                             "candidates (LLM still generates; merger keeps the best)")
    parser.add_argument("--skip-phase2", action="store_true",
                        help="Skip Phase 2 synthesis (implies --skip-phase3)")
    parser.add_argument("--skip-phase3", action="store_true",
                        help="Skip Phase 3 refinement")
    parser.add_argument("--ew-target", type=float, default=0.9,
                        help="Phase 3 target EW score")
    parser.add_argument("--max-refinement-iterations", type=int, default=10,
                        help="Phase 3 max iterations")

    args = parser.parse_args()
    if args.debug_llm or os.environ.get("LLM_DEBUG"):
        _configure_llm_debug_logging()
    print_banner()

    scenarios = resolve_scenarios(args, default_bench=eval_cfg.get("bench_path", ""))
    print(f"[*] Selected {len(scenarios)} scenario(s): {', '.join(s.id for s in scenarios)}")

    output_root = Path(args.output_dir)
    output_root.mkdir(parents=True, exist_ok=True)
    print(f"[*] Output root: {output_root.absolute()}")

    llm_settings = config_loader.llm_settings()
    print(f"[*] LLM: {llm_settings.model} @ {llm_settings.base_url}")

    mgr = ScenarioContainerManager(install_osquery=args.install_osquery)

    overall_rc = 0
    for scenario in scenarios:
        try:
            rc = run_one_scenario(scenario, output_root, mgr, args, llm_settings)
            overall_rc = max(overall_rc, rc)
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
            return 130
        except Exception as e:
            print(f"\n[!] Scenario {scenario.id} crashed: {e}")
            import traceback
            traceback.print_exc()
            overall_rc = max(overall_rc, 3)
    return overall_rc


if __name__ == "__main__":
    sys.exit(main())
