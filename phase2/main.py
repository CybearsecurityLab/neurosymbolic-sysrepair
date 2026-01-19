import argparse
import json
import logging
from .config import HardwareConfig, LLMConfig
from .orchestrator import Phase2Orchestrator, launch_vllm_server

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


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
        "--model", default="mistralai/Mistral-7B-Instruct-v0.3", help="LLM model to use"
    )
    parser.add_argument(
        "--mock-llm", action="store_true", help="Use mock LLM for testing without GPU"
    )
    parser.add_argument("--phase1-state", help="Path to Phase 1 state JSON file")
    parser.add_argument(
        "--launch-vllm", action="store_true", help="Auto-launch vLLM server"
    )
    parser.add_argument(
        "--json-output", "-j", action="store_true", help="Output results as JSON"
    )

    args = parser.parse_args()

    # Load Phase 1 state if provided
    osquery_data = {}
    if args.phase1_state:
        with open(args.phase1_state) as f:
            phase1_data = json.load(f)
            osquery_data = phase1_data.get("objects", {})

    # Configure
    hardware = HardwareConfig.detect()
    llm_config = LLMConfig(model_name=args.model)

    # Launch vLLM if requested
    vllm_process = None
    if args.launch_vllm and not args.mock_llm:
        vllm_process = launch_vllm_server(llm_config, hardware)

    try:
        # Run orchestrator
        orchestrator = Phase2Orchestrator(
            hardware_config=hardware,
            llm_config=llm_config,
            osquery_data=osquery_data,
            use_mock_llm=args.mock_llm,
            output_dir=args.output_dir,
        )

        results = orchestrator.run()

        if args.json_output:
            # Remove large PDDL string for JSON output
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