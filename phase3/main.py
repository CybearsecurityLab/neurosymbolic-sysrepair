"""
Main entry point for Phase 3: Iterative Refinement via Exploration Walks

Usage:
    python -m phase3.main [options]

    # Run with default settings
    python -m phase3.main

    # Custom domain path
    python -m phase3.main --domain ./my_domain.pddl --problem ./my_problem.pddl

    # Adjust parameters
    python -m phase3.main --target-score 0.85 --max-iterations 5
"""

import argparse
import json
import logging
import sys
from pathlib import Path

from common.config_loader import llm_settings
from .config import Phase3Config
from .orchestrator import Phase3Orchestrator

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def setup_logging(output_dir: str, level: int = logging.INFO):
    """Configure logging to both console and phase3.log file."""
    log_path = Path(output_dir) / "phase3.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    # Console handler
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(logging.Formatter(LOG_FORMAT))
    root.addHandler(console)

    # File handler
    file_handler = logging.FileHandler(str(log_path), mode="w")
    file_handler.setLevel(logging.DEBUG)  # always capture full detail in file
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    root.addHandler(file_handler)

    logging.info(f"Logging to {log_path}")


def main():
    """Main entry point for Phase 3 execution."""
    parser = argparse.ArgumentParser(
        description="Phase 3: Iterative Refinement via Exploration Walks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with custom domain
  python -m phase3 --domain ./pddl_output/sysadmin.pddl

  # Run with lower target for faster completion
  python -m phase3 --target-score 0.7 --max-iterations 3

  # Output as JSON
  python -m phase3 --json-output
        """,
    )

    # Input/Output
    parser.add_argument(
        "--domain", "-d",
        default="./pddl_output/phase2/sysadmin.pddl",
        help="Path to input PDDL domain file",
    )
    parser.add_argument(
        "--problem", "-p",
        default="./pddl_output/phase2/sysadmin_problem.pddl",
        help="Path to input PDDL problem file",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default="./pddl_output/phase3",
        help="Output directory for refined domain and reports",
    )

    # Refinement parameters
    parser.add_argument(
        "--target-score", "-t",
        type=float,
        default=0.9,
        help="Target EW score to achieve (default: 0.9)",
    )
    parser.add_argument(
        "--max-iterations", "-i",
        type=int,
        default=10,
        help="Maximum refinement iterations (default: 10)",
    )
    parser.add_argument(
        "--walks-per-iteration", "-n",
        type=int,
        default=None,
        help="Number of exploration walks per iteration (default: auto-scaled based on domain size)",
    )
    parser.add_argument(
        "--walk-depth", "-w",
        type=int,
        default=None,
        help="Maximum depth of each walk (default: auto-scaled based on domain size)",
    )

    # Docker configuration
    parser.add_argument(
        "--docker-image",
        default="pddl-sandbox:latest",
        help="Docker image for sandbox (default: pddl-sandbox:latest)",
    )

    # LLM configuration (defaults from config.yaml)
    cfg = llm_settings("phase3")

    parser.add_argument(
        "--llm-url",
        default=cfg.base_url,
        help=f"LLM API base URL (default: {cfg.base_url})",
    )
    parser.add_argument(
        "--llm-model",
        default=cfg.model,
        help=f"LLM model name (default: {cfg.model})",
    )
    parser.add_argument(
        "--llm-api-key",
        default=cfg.api_key or "vllm",
        help="API key for LLM service (default: from config.yaml)",
    )

    # Concretizer configuration
    parser.add_argument(
        "--concretizer-model",
        default=cfg.model,
        help=f"LLM model for action concretization (default: {cfg.model})",
    )
    parser.add_argument(
        "--phase1-metadata",
        default="./pddl_output/phase1/phase1_statep2.json",
        help="Path to Phase 1 metadata (phase1_statep2.json)",
    )
    parser.add_argument(
        "--concretizer-cache",
        default="",
        help="Path to concretizer cache file (default: output_dir/concretizer_cache.json)",
    )

    # Planner configuration
    parser.add_argument(
        "--plan-timeout",
        type=int,
        default=None,
        help="Planner timeout in seconds (default: 300)",
    )

    # Output options
    parser.add_argument(
        "--json-output", "-j",
        action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug output",
    )
    parser.add_argument(
        "--save-intermediate",
        action="store_true",
        default=True,
        help="Save intermediate domain versions (default: true)",
    )

    args = parser.parse_args()

    # Configure logging (console + file)
    log_level = logging.WARNING if args.quiet else logging.DEBUG if args.verbose else logging.INFO
    setup_logging(args.output_dir, log_level)

    # Build configuration
    config = Phase3Config()

    # I/O paths
    config.input_domain_path = args.domain
    config.input_problem_path = args.problem
    config.output_dir = args.output_dir

    # Refinement parameters
    config.ew_target_score = args.target_score
    config.max_refinement_iterations = args.max_iterations
    config.save_intermediate_domains = args.save_intermediate

    # EW walk params: only override defaults if user explicitly set them
    if args.walks_per_iteration is not None:
        config.walks_per_iteration = args.walks_per_iteration
        config.ew_params_explicitly_set = True
    if args.walk_depth is not None:
        config.walk_depth = args.walk_depth
        config.ew_params_explicitly_set = True

    # Docker
    config.docker.image = args.docker_image

    # LLM
    config.llm.base_url = args.llm_url
    config.llm.model_name = args.llm_model
    config.llm.api_key = args.llm_api_key
    config.llm.concretizer_model = args.concretizer_model

    # Concretizer
    config.phase1_metadata_path = args.phase1_metadata
    config.concretizer_cache_path = args.concretizer_cache

    # Planner
    if args.plan_timeout is not None:
        config.planner.plan_timeout = args.plan_timeout

    # Validate inputs
    if not Path(config.input_domain_path).exists():
        print(f"Error: Domain file not found: {config.input_domain_path}", file=sys.stderr)
        print("Run Phase 1 and Phase 2 first, or specify --domain path", file=sys.stderr)
        return 1

    # Run orchestrator
    orchestrator = Phase3Orchestrator(config=config)
    results = orchestrator.run()

    # Output results
    if args.json_output:
        # Clean results for JSON output
        output = {
            "success": results["success"],
            "final_score": results["final_score"],
            "target_score": results["target_score"],
            "target_achieved": results["target_achieved"],
            "iterations": results["iterations"],
            "statistics": results.get("statistics", {}),
            "domain_path": results.get("domain_path", ""),
            "errors": results.get("errors", []),
        }
        print(json.dumps(output, indent=2))

    return 0 if results["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
