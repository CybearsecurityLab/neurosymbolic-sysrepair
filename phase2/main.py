"""Phase 2: Parallel Synthesis entry point."""

import argparse
import json
import logging
import sys
import os
from datetime import datetime


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import Phase1State
from common.config_loader import llm_settings

from phase2.config import HardwareConfig, LLMConfig
from phase2.orchestrator import Phase2Orchestrator, launch_vllm_server

# Global for log file path
_log_file_path = None


def setup_logging(output_dir: str, log_filename: str = "phase2.log") -> str:
    """
    Set up logging to both console and file.

    Args:
        output_dir: Directory where log file will be created
        log_filename: Name of the log file

    Returns:
        Path to the log file
    """
    global _log_file_path

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    _log_file_path = os.path.join(output_dir, log_filename)

    # Create formatters
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    # Get root logger and Phase2 loggers
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # Remove existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler
    file_handler = logging.FileHandler(_log_file_path, mode='w')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    # Write header to file
    with open(_log_file_path, 'a') as f:
        f.write(f"{'=' * 70}\n")
        f.write(f"Phase 2: Parallel Synthesis Log\n")
        f.write(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"{'=' * 70}\n\n")

    return _log_file_path


logger = logging.getLogger("Phase2.Main")


def main():
    """Main entry point for Phase 2 execution."""

    parser = argparse.ArgumentParser(
        description="Phase 2: Parallel Synthesis for PDDL Domain Generation"
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        default="./pddl_output/phase2",
        help="Output directory for PDDL files",
    )
    # Read defaults from config.yaml
    cfg = llm_settings("phase2")

    parser.add_argument(
        "--model",
        default=cfg.model,
        help=f"LLM model to use (default: {cfg.model})"
    )
    parser.add_argument(
        "--phase1-state",
        help="Path to Phase 1 state JSON file (full state including actions)"
    )
    parser.add_argument(
        "--launch-vllm",
        action="store_true",
        help="Auto-launch vLLM server"
    )
    parser.add_argument(
        "--json-output",
        "-j",
        action="store_true",
        help="Output results as JSON"
    )
    parser.add_argument(
        "--reuse-phase1-actions",
        action="store_true",
        default=False,
        help="Reuse Phase 1 extracted actions instead of regenerating (default: True)"
    )
    parser.add_argument(
        "--no-reuse-actions",
        action="store_true",
        help="Force regeneration of all actions (ignore Phase 1 actions)"
    )
    parser.add_argument(
        "--workers",
        "-w",
        type=int,
        default=None,
        help="Number of parallel workers (default: auto-detect based on hardware)"
    )
    parser.add_argument(
        "--max-llm-workers",
        type=int,
        default=1,
        help="Max parallel LLM extraction workers for chunk processing (default: 1). "
        "Increase based on GPU count and model size."
    )
    parser.add_argument(
        "--base-url",
        "--ollama-url",
        dest="base_url",
        default=None,
        help=f"Base URL for LLM service (default: {cfg.base_url}). "
        "Overrides default based on backend."
    )
    parser.add_argument(
        "--llm-api-key",
        default=None,
        help="API key for LLM service (default: from config.yaml)",
    )

    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    log_file_path = setup_logging(args.output_dir, "phase2.log")
    logger.info(f"Output directory: {args.output_dir}")
    logger.info(f"Log file: {log_file_path}")

    phase1_state = None

    if args.phase1_state:
        logger.info(f"Loading Phase 1 state from: {args.phase1_state}")
        try:
            phase1_state = Phase1State.from_file(args.phase1_state)

            logger.info(f"  Objects: {sum(len(v) for v in phase1_state.objects.values())}")
            logger.info(f"  Predicates: {len(phase1_state.predicates)}")
            logger.info(f"  Actions: {len(phase1_state.actions)}")
            logger.info(f"  Relationships: {sum(len(v) for v in phase1_state.relationships.values())}")

            if phase1_state.metadata:
                logger.info(f"  Scoping: {phase1_state.metadata.get('scoping_method', 'unknown')}")
                if 'detected_variants' in phase1_state.metadata:
                    logger.info(f"  Variants: {phase1_state.metadata['detected_variants']}")

        except Exception as e:
            logger.error(f"Failed to load Phase 1 state: {e}")
            phase1_state = None
    else:
        logger.warning("No Phase 1 state provided. Phase 2 will generate from scratch.")
        phase1_state = Phase1State()

    # Configure hardware
    hardware = HardwareConfig.detect()
    if args.workers is not None:
        hardware.max_parallel_workers = args.workers
        logger.info(f"Using {args.workers} parallel workers (CLI override)")

    # Configure LLM (CLI > config.yaml > defaults)
    llm_kwargs = {
        "model_name": args.model,
        "base_url": args.base_url or cfg.base_url,
        "api_key": args.llm_api_key or cfg.api_key or "vllm",
        "max_llm_workers": args.max_llm_workers,
    }
    if args.base_url:
        logger.info(f"Using custom base URL: {args.base_url}")

    llm_config = LLMConfig(**llm_kwargs)

    if args.max_llm_workers > 1:
        logger.info(f"Using {args.max_llm_workers} parallel LLM workers for chunk processing")

    # Launch vLLM if requested
    vllm_process = None
    if args.launch_vllm:
        vllm_process = launch_vllm_server(llm_config, hardware)

    try:
        # Determine whether to reuse Phase 1 actions
        reuse_actions = args.reuse_phase1_actions and not args.no_reuse_actions

        if reuse_actions and phase1_state and phase1_state.actions:
            logger.info(f"Will reuse {len(phase1_state.actions)} Phase 1 actions")
        else:
            logger.info("Will generate actions from scratch")

        orchestrator = Phase2Orchestrator(
            hardware_config=hardware,
            llm_config=llm_config,
            phase1_state=phase1_state,
            output_dir=args.output_dir,
            reuse_phase1_actions=reuse_actions,
        )

        results = orchestrator.run()

        # Log completion
        logger.info(f"Log file saved to: {log_file_path}")

        if args.json_output:
            output = {k: v for k, v in results.items() if k != "domain_pddl"}
            output["log_file"] = log_file_path
            print(json.dumps(output, indent=2))
        else:
            if results.get("domain_pddl"):
                print("\n" + "=" * 70)
                print("GENERATED UNIFIED DOMAIN")
                print("=" * 70)
                print(results["domain_pddl"][:3000])
                if len(results["domain_pddl"]) > 3000:
                    print(
                        f"\n... [{len(results['domain_pddl']) - 3000} more characters]"
                    )

        return 0 if results["success"] else 1

    finally:
        if vllm_process:
            vllm_process.terminate()


if __name__ == "__main__":
    exit(main())
