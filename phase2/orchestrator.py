import json
import time
import logging
import subprocess
from pathlib import Path
from typing import Optional

from .config import HardwareConfig, LLMConfig
from .llm import get_llm_interface
from .supervisor import SupervisorAgent
from .merger import MergerAgent
from .repair import PDDLValidator
from .models import PartialPDDLDomain

logger = logging.getLogger("Phase2.Orchestrator")

class Phase2Orchestrator:
    """
    Main orchestrator for Phase 2: Parallel Synthesis.
    Coordinates Map and Reduce phases.
    """

    def __init__(
        self,
        hardware_config: Optional[HardwareConfig] = None,
        llm_config: Optional[LLMConfig] = None,
        osquery_data: Optional[dict] = None,
        use_mock_llm: bool = False,
        output_dir: str = "./pddl_output",
    ):
        self.hardware = hardware_config or HardwareConfig.detect()
        self.llm_config = llm_config or LLMConfig()
        self.osquery_data = osquery_data or {}
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize LLM interface
        self.llm = get_llm_interface(self.llm_config, use_mock=use_mock_llm)

        # Initialize components
        self.supervisor = SupervisorAgent(
            llm=self.llm,
            hardware_config=self.hardware,
            osquery_data=self.osquery_data,
            output_dir=str(self.output_dir),
        )
        self.merger = MergerAgent(llm=self.llm)
        self.validator = PDDLValidator()

        # Results
        self.partial_domains: list[PartialPDDLDomain] = []
        self.unified_domain: str = ""

    def run(self) -> dict:
        """Execute the complete Phase 2 pipeline."""
        results = {
            "success": False,
            "map_phase_complete": False,
            "reduce_phase_complete": False,
            "validation_passed": False,
            "errors": [],
            "warnings": [],
            "statistics": {},
            "merge_log": [],
        }

        print("\n" + "=" * 70)
        print("PHASE 2: PARALLEL SYNTHESIS (MAP-REDUCE)")
        print("=" * 70)
        print(f"\nHardware Configuration:")
        print(
            f"  GPUs: {self.hardware.num_gpus}x (detected @ {self.hardware.gpu_memory_gb:.1f}GB)"
        )
        print(f"  RAM: {self.hardware.total_ram_gb:.0f}GB")
        print(f"  CPUs: {self.hardware.num_cpus}")
        print(f"  Parallel Workers: {self.hardware.max_parallel_workers}")
        print(f"\nLLM: {self.llm_config.model_name}")

        try:
            # MAP PHASE
            print("\n" + "-" * 70)
            self.partial_domains = self.supervisor.execute_map_phase()
            results["map_phase_complete"] = True

            # Statistics
            successful = [d for d in self.partial_domains if not d.error]
            results["statistics"]["workers_total"] = len(self.partial_domains)
            results["statistics"]["workers_successful"] = len(successful)
            results["statistics"]["total_types"] = sum(len(d.types) for d in successful)
            results["statistics"]["total_predicates"] = sum(
                len(d.predicates) for d in successful
            )
            results["statistics"]["total_actions"] = sum(
                len(d.actions) for d in successful
            )

            # REDUCE PHASE
            print("\n" + "-" * 70)
            self.unified_domain = self.merger.merge(self.partial_domains)
            results["reduce_phase_complete"] = True
            results["merge_log"] = self.merger.get_merge_log()

            # VALIDATION
            print("\n" + "-" * 70)
            print("VALIDATION PHASE")
            print("-" * 70)

            is_valid, validation_msgs = self.validator.validate_domain(
                self.unified_domain
            )
            results["validation_passed"] = is_valid

            if is_valid:
                print("  ✓ Domain validation passed")
            else:
                print("  ⚠ Validation issues found:")
                for msg in validation_msgs:
                    print(f"    - {msg}")
                results["warnings"].extend(validation_msgs)

            # Save outputs
            domain_path = self.output_dir / "sysadmin.pddl"
            domain_path.write_text(self.unified_domain)
            print(f"\n  → Domain saved to: {domain_path}")

            # Save partial domains for debugging
            partials_path = self.output_dir / "partial_domains.json"
            partials_data = [d.to_dict() for d in self.partial_domains]
            partials_path.write_text(json.dumps(partials_data, indent=2))
            print(f"  → Partial domains saved to: {partials_path}")

            # Save merge log
            log_path = self.output_dir / "merge_log.txt"
            log_path.write_text("\n".join(results["merge_log"]))

            results["success"] = True
            results["domain_path"] = str(domain_path)
            results["domain_pddl"] = self.unified_domain

        except Exception as e:
            logger.exception("Phase 2 failed")
            results["errors"].append(str(e))

        # Final summary
        print("\n" + "=" * 70)
        print("PHASE 2 SUMMARY")
        print("=" * 70)
        print(f"  Status: {'SUCCESS' if results['success'] else 'FAILED'}")
        print(
            f"  Workers: {results['statistics'].get('workers_successful', 0)}/"
            f"{results['statistics'].get('workers_total', 0)} successful"
        )
        print(
            f"  Types: {results['statistics'].get('total_types', 0)} → "
            f"{len(self.merger.unified_types)} unified"
        )
        print(
            f"  Predicates: {results['statistics'].get('total_predicates', 0)} → "
            f"{len(self.merger.unified_predicates)} unified"
        )
        print(
            f"  Actions: {results['statistics'].get('total_actions', 0)} → "
            f"{len(self.merger.unified_actions)} unified"
        )
        print(
            f"  Validation: {'PASSED' if results['validation_passed'] else 'WARNINGS'}"
        )

        return results

def launch_vllm_server(config: LLMConfig, hardware: HardwareConfig) -> subprocess.Popen:
    """
    Launch vLLM server for LLM inference.

    For 2x L40S with 48GB each:
    - Can run Llama-3.1-70B with tensor parallelism
    - Or run multiple instances of smaller models
    """
    cmd = [
        "python",
        "-m",
        "vllm.entrypoints.openai.api_server",
        "--model",
        config.model_name,
        "--tensor-parallel-size",
        str(config.tensor_parallel_size),
        "--max-model-len",
        "8192",
        "--gpu-memory-utilization",
        "0.90",
        "--host",
        "0.0.0.0",
        "--port",
        "8000",
    ]

    logger.info(f"Launching vLLM server: {' '.join(cmd)}")

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Wait for server to be ready
    import time

    for _ in range(60):  # Wait up to 60 seconds
        try:
            import urllib.request

            urllib.request.urlopen(f"{config.base_url}/health", timeout=1)
            logger.info("vLLM server is ready")
            return process
        except Exception:
            time.sleep(1)

    raise RuntimeError("vLLM server failed to start")