#!/usr/bin/env python3
"""
run_eval.py -- Evaluation harness CLI for SysRepair-Bench baselines.

Examples:
  # Full run, all baselines, all models, CCDC only
  python run_eval.py --bench /path/to/sysrepair-bench --collection ccdc --baselines all --models all

  # Smoke test: single scenario, react, qwen
  python run_eval.py --bench /path/to/sysrepair-bench --scenarios ccdc-01 --baselines react --models qwen-3.5-122b

  # Resume interrupted run
  python run_eval.py --bench /path/to/sysrepair-bench --baselines all --models all --resume

  # Generate report from existing DB
  python run_eval.py --report-only --output eval/results/eval_results.db
"""

import argparse
import logging
import sys
from pathlib import Path


def parse_args():
    p = argparse.ArgumentParser(description="SysRepair-Bench Baseline Evaluation Harness")
    p.add_argument(
        "--bench",
        type=Path,
        default=Path("/Users/abanisenioluwaorojo/projects/sysrepair-bench"),
        help="Path to sysrepair-bench root",
    )
    p.add_argument(
        "--collection",
        choices=["ccdc", "meta2"],
        default=None,
        help="Filter by collection",
    )
    p.add_argument(
        "--scenarios",
        nargs="+",
        default=None,
        help="Specific scenario IDs (e.g. ccdc-01 meta2-05)",
    )
    p.add_argument(
        "--baselines",
        nargs="+",
        default=["all"],
        choices=["raw", "react", "plan_and_solve", "reflexion", "lats", "all"],
        help="Which baselines to run",
    )
    p.add_argument(
        "--models",
        nargs="+",
        default=["all"],
        choices=["mistral-large-3", "qwen-3.5-122b", "nemotron-3-super", "gpt-oss-120b", "all"],
        help="Which models to evaluate",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=Path("eval/results/eval_results.db"),
        help="SQLite output path",
    )
    p.add_argument(
        "--parallel",
        type=int,
        default=2,
        help="Number of concurrent containers",
    )
    p.add_argument(
        "--resume",
        action="store_true",
        help="Skip already-completed (scenario, baseline, model) triples",
    )
    p.add_argument(
        "--report-only",
        action="store_true",
        help="Skip evaluation, only generate reports from existing DB",
    )
    p.add_argument(
        "--report-format",
        choices=["csv", "latex", "both"],
        default="both",
    )
    p.add_argument(
        "--ollama-url",
        default="http://localhost:11434/v1",
        help="Ollama server base URL",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print run matrix without executing",
    )
    p.add_argument("--verbose", "-v", action="store_true")
    return p.parse_args()


def resolve_list(arg: list, all_values: list) -> list:
    if "all" in arg:
        return all_values
    return arg


ALL_BASELINES = ["raw", "react", "plan_and_solve", "reflexion", "lats"]
ALL_MODELS = ["mistral-large-3", "qwen-3.5-122b", "nemotron-3-super", "gpt-oss-120b"]


def main():
    args = parse_args()
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s")
    log = logging.getLogger(__name__)

    baselines = resolve_list(args.baselines, ALL_BASELINES)
    models = resolve_list(args.models, ALL_MODELS)

    if args.report_only:
        from eval.reporter import generate_all_reports
        report_dir = args.output.parent / "reports"
        generate_all_reports(args.output, report_dir)
        return

    from eval.scenario_loader import load_scenarios, load_all_scenarios
    from eval.harness import EvalHarness

    if args.scenarios:
        scenarios = load_scenarios(args.bench, ids=args.scenarios)
    elif args.collection:
        scenarios = load_scenarios(args.bench, collection=args.collection)
    else:
        scenarios = load_all_scenarios(args.bench)

    if not scenarios:
        log.error(f"No scenarios found in {args.bench}")
        sys.exit(1)

    log.info(f"Loaded {len(scenarios)} scenarios")
    log.info(f"Baselines: {baselines}")
    log.info(f"Models: {models}")
    log.info(f"Output: {args.output}")

    if args.dry_run:
        total = len(scenarios) * len(baselines) * len(models)
        print(f"DRY RUN: {total} runs planned")
        print(f"  Scenarios: {[s.id for s in scenarios[:5]]}{'...' if len(scenarios) > 5 else ''}")
        print(f"  Baselines: {baselines}")
        print(f"  Models: {models}")
        return

    harness = EvalHarness(
        bench_root=args.bench,
        results_db_path=args.output,
        ollama_url=args.ollama_url,
        max_parallel=args.parallel,
    )

    records = harness.run_all(
        baselines=baselines,
        models=models,
        scenarios=scenarios,
        resume=args.resume,
    )

    log.info(f"Completed {len(records)} runs")

    # Generate reports
    report_dir = args.output.parent / "reports"
    if args.report_format in ("csv", "both"):
        from eval.reporter import generate_summary_csv, generate_full_csv
        generate_summary_csv(harness.db, report_dir / "summary.csv")
        generate_full_csv(harness.db, report_dir / "full_results.csv")
    if args.report_format in ("latex", "both"):
        from eval.reporter import generate_latex_table
        generate_latex_table(harness.db, report_dir / "table_baselines.tex")

    log.info(f"Reports saved to {report_dir}/")

    # Print quick summary
    from eval.reporter import generate_all_reports
    generate_all_reports(args.output, report_dir)


if __name__ == "__main__":
    main()
