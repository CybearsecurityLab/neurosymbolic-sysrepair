"""
phase2/main.py

Main entry point for Phase 2: Parallel Synthesis.
Updated to accept the full Phase 1 state including actions, predicates, and relationships.
"""

import argparse
import json
import logging
import sys
import os

# Add parent directory to path for common imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import Phase1State

from phase2.config import HardwareConfig, LLMConfig
from phase2.orchestrator import Phase2Orchestrator, launch_vllm_server

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
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
    parser.add_argument(
        "--model",
        default="mistralai/Mistral-7B-Instruct-v0.3",
        help="LLM model to use"
    )
    parser.add_argument(
        "--mock-llm",
        action="store_true",
        help="Use mock LLM for testing without GPU"
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

    args = parser.parse_args()

    # =================================================================
    # Load Phase 1 state - now loading FULL state, not just objects
    # =================================================================

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
    llm_config = LLMConfig(model_name=args.model)

    # Launch vLLM if requested
    vllm_process = None
    if args.launch_vllm and not args.mock_llm:
        vllm_process = launch_vllm_server(llm_config, hardware)

    try:
        # Determine whether to reuse Phase 1 actions
        reuse_actions = args.reuse_phase1_actions and not args.no_reuse_actions

        if reuse_actions and phase1_state and phase1_state.actions:
            logger.info(f"Will reuse {len(phase1_state.actions)} Phase 1 actions")
        else:
            logger.info("Will generate actions from scratch")

        # =================================================================
        # Run orchestrator with full Phase 1 state
        # =================================================================

        orchestrator = Phase2Orchestrator(
            hardware_config=hardware,
            llm_config=llm_config,
            phase1_state=phase1_state,  # Pass full state
            use_mock_llm=args.mock_llm,
            output_dir=args.output_dir,
            reuse_phase1_actions=reuse_actions,
        )

        results = orchestrator.run()

        if args.json_output:
            output = {k: v for k, v in results.items() if k != "domain_pddl"}
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
