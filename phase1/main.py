import json
import sys

from phase1.common.logger import set_log_stream, log
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
        default="./pddl_output",
        help="Output directory for PDDL files",
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
        "--write-files",
        "-w",
        action="store_true",
        help="Write PDDL files to output directory",
    )
    parser.add_argument(
        "--scoping",
        choices=["dynamic", "static"],
        default="dynamic",
        help="Scoping method: 'dynamic' (graph-based Anchor & Propagate) or "
        "'static' (legacy arbitrary caps). Default: dynamic",
    )

    args = parser.parse_args()

    # Configure logging output
    if args.json_output:
        # Send progress to stderr so stdout is clean JSON
        set_log_stream(sys.stderr)

    if args.quiet:
        # Suppress all progress output (cross-platform null device)
        import os

        set_log_stream(open(os.devnull, "w"))

    # Run orchestrator
    orchestrator = Phase1Orchestrator(
        output_dir=args.output_dir,
        osquery_socket=args.osquery_socket,
        validate=args.validate,
        scoping_mode=args.scoping,
    )
    results = orchestrator.run()

    # Write files if requested
    if args.write_files and results.get("pddl_generated"):
        import os

        os.makedirs(args.output_dir, exist_ok=True)

        domain_path = os.path.join(args.output_dir, "sysadmin.pddl")
        problem_path = os.path.join(args.output_dir, "problem.pddl")

        with open(domain_path, "w") as f:
            f.write(results.get("domain_pddl", ""))
        with open(problem_path, "w") as f:
            f.write(results.get("problem_pddl", ""))

        log(f"\nFiles written to {args.output_dir}/")
        log(f"  - sysadmin.pddl ({len(results.get('domain_pddl', ''))} bytes)")
        log(f"  - problem.pddl ({len(results.get('problem_pddl', ''))} bytes)")

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

    return 0 if results["success"] else 1


if __name__ == "__main__":
    exit(main())
