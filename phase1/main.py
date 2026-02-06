import json
import sys
import os

from phase1.common.logger import (
    set_log_stream,
    log,
    setup_logging,
    close_logging,
    suppress_console,
)
from phase1.orchestrator import Phase1Orchestrator


def main():
    """Main entry point for Phase 1 execution."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Phase 1: System Introspection for PDDL Domain Generation"
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        default="./pddl_output/phase1",
        help="Output directory for PDDL files (default: ./pddl_output/phase1)",
    )
    parser.add_argument(
        "--json-output",
        "-j",
        action="store_true",
        help="Output results as JSON to stdout (progress goes to stderr)",
    )
    parser.add_argument(
        "--include-pddl",
        action="store_true",
        help="Include PDDL content in JSON output (use with -j)",
    )
    parser.add_argument(
        "--osquery-socket",
        "-s",
        default=None,
        help="Path to osqueryd socket (e.g., /var/osquery/osquery.em). "
        "If not specified, spawns standalone instance.",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress progress output"
    )
    parser.add_argument(
        "--validate",
        "-v",
        action="store_true",
        help="Validate generated PDDL with VAL validator",
    )
    parser.add_argument(
        "--scoping",
        choices=["dynamic", "static"],
        default="dynamic",
        help="Scoping method: 'dynamic' (graph-based Anchor & Propagate) or "
        "'static' (legacy arbitrary caps). Default: dynamic",
    )
    parser.add_argument(
        "--gpu",
        "-g",
        type=str,
        default=None,
        help="GPU device(s) to use (e.g., '0', '1', '0,1'). Sets CUDA_VISIBLE_DEVICES. "
        "Default: use all available GPUs.",
    )
    parser.add_argument(
        "--llm-model",
        default="qwen2.5:32b",
        help="LLM model for action extraction (default: qwen2.5:32b)",
    )
    parser.add_argument(
        "--llm-url",
        default="http://localhost:11434",
        help="Ollama server URL (default: http://localhost:11434)",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable LLM extraction (use regex-only extraction)",
    )
    parser.add_argument(
        "--max-llm-workers",
        type=int,
        default=1,
        help="Max parallel LLM extraction workers (default: 1). "
        "Increase based on GPU count and model size.",
    )

    args = parser.parse_args()

    # Set GPU device(s) if specified (before any CUDA initialization)
    if args.gpu is not None:
        os.environ["CUDA_VISIBLE_DEVICES"] = args.gpu

    # Ensure output directory exists
    os.makedirs(args.output_dir, exist_ok=True)

    # Set up file logging (always logs to file)
    log_file_path = setup_logging(args.output_dir, "phase1.log")

    # Configure console output
    if args.json_output:
        # Send progress to stderr so stdout is clean JSON
        set_log_stream(sys.stderr)

    if args.quiet:
        # Suppress console output (file logging continues)
        suppress_console(True)

    log(f"Output directory: {args.output_dir}")
    log(f"Log file: {log_file_path}")
    if args.gpu is not None:
        log(f"GPU device(s): {args.gpu}")
    if not args.no_llm:
        log(f"LLM: {args.llm_model} @ {args.llm_url} (workers: {args.max_llm_workers})")
    else:
        log("LLM: disabled")

    # Run orchestrator
    orchestrator = Phase1Orchestrator(
        output_dir=args.output_dir,
        osquery_socket=args.osquery_socket,
        validate=args.validate,
        scoping_mode=args.scoping,
        llm_model=args.llm_model,
        llm_url=args.llm_url,
        enable_llm=not args.no_llm,
        max_llm_workers=args.max_llm_workers,
    )
    results = orchestrator.run()

    # Always write PDDL files if generation succeeded
    if results.get("pddl_generated"):
        domain_path = os.path.join(args.output_dir, "sysadmin.pddl")
        problem_path = os.path.join(args.output_dir, "problem.pddl")

        with open(domain_path, "w") as f:
            f.write(results.get("domain_pddl", ""))
        with open(problem_path, "w") as f:
            f.write(results.get("problem_pddl", ""))

        log(f"\nFiles written to {args.output_dir}/")
        log(f"  - sysadmin.pddl ({len(results.get('domain_pddl', ''))} bytes)")
        log(f"  - problem.pddl ({len(results.get('problem_pddl', ''))} bytes)")
        log(f"  - phase1.log")

    if args.json_output:
        # Build JSON output
        output = {
            "success": results.get("success", False),
            "state_extracted": results.get("state_extracted", False),
            "actions_mined": results.get("actions_mined", False),
            "pddl_generated": results.get("pddl_generated", False),
            "statistics": results.get("statistics", {}),
            "errors": results.get("errors", []),
            "warnings": results.get("warnings", []),
        }

        if args.include_pddl:
            output["domain_pddl"] = results.get("domain_pddl", "")
            output["problem_pddl"] = results.get("problem_pddl", "")

        # Output clean JSON to stdout
        print(json.dumps(output, indent=2))
    else:
        # Print PDDL to stdout
        if results.get("domain_pddl"):
            print("\n" + "=" * 60)
            print("GENERATED DOMAIN (sysadmin.pddl)")
            print("=" * 60)
            print(results["domain_pddl"])

    # Close log file
    close_logging()

    return 0 if results["success"] else 1


if __name__ == "__main__":
    exit(main())
