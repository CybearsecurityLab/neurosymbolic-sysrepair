"""
phase2/orchestrator.py

Main orchestrator for Phase 2: Parallel Synthesis.
Updated to use full Phase 1 state including actions, predicates, and relationships.
"""

import json
import time
import logging
import subprocess
from pathlib import Path
from typing import Optional
import sys
import os

# Add parent directory to path for common imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import Phase1State
from common.predicates import get_base_predicates

from phase2.config import HardwareConfig, LLMConfig
from phase2.llm import get_llm_interface
from phase2.supervisor import SupervisorAgent
from phase2.merger import MergerAgent
from phase2.repair import PDDLValidator
from phase2.models import PartialPDDLDomain

logger = logging.getLogger("Phase2.Orchestrator")


class Phase2Orchestrator:
    """
    Main orchestrator for Phase 2: Parallel Synthesis.
    Coordinates Map and Reduce phases.

    Updated to:
    - Accept full Phase1State (objects, predicates, actions, relationships)
    - Reuse Phase 1 actions instead of regenerating
    - Pass known predicates to workers
    """

    def __init__(
        self,
        hardware_config: Optional[HardwareConfig] = None,
        llm_config: Optional[LLMConfig] = None,
        phase1_state: Optional[Phase1State] = None,
        output_dir: str = "./pddl_output",
        reuse_phase1_actions: bool = False,
    ):
        self.hardware = hardware_config or HardwareConfig.detect()
        self.llm_config = llm_config or LLMConfig()
        self.phase1_state = phase1_state or Phase1State()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.reuse_phase1_actions = reuse_phase1_actions

        # Initialize LLM interface
        self.llm = get_llm_interface(self.llm_config)

        # =================================================================
        # Build known predicates from Phase 1 + base predicates
        # =================================================================
        self.known_predicates = self._build_known_predicates()

        # =================================================================
        # Phase 1 action handling
        # If reuse enabled: Phase 1 actions included as candidates alongside
        # LLM-generated versions; merger decides quality via heuristic.
        # If reuse disabled (default): Phase 2 regenerates everything.
        # =================================================================
        self.phase1_actions = []

        # Check if Phase 1 actually has actions to offer
        has_legacy_actions = self.phase1_state and self.phase1_state.actions

        if reuse_phase1_actions and has_legacy_actions:
            self.phase1_actions = self.phase1_state.get_actions()
            logger.info(
                f"Including {len(self.phase1_actions)} Phase 1 actions as candidates. "
                f"LLM will also generate its versions; merger decides quality."
            )
        elif has_legacy_actions:
            count = len(self.phase1_state.actions)
            logger.info(
                f"Phase 1 has {count} actions but reuse is disabled. "
                f"Phase 2 will regenerate from documentation."
            )
            # We explicitly do NOT load them into self.phase1_actions
        else:
            logger.info(
                "Phase 1 state contains no actions. Pure Phase 2 generation enabled."
            )

        # Initialize components with Phase 1 context
        self.supervisor = SupervisorAgent(
            llm=self.llm,
            hardware_config=self.hardware,
            phase1_state=self.phase1_state,
            phase1_actions=self.phase1_actions,
            known_predicates=self.known_predicates,
            output_dir=str(self.output_dir),
            reuse_phase1_actions=reuse_phase1_actions,
            llm_config=self.llm_config,
        )
        self.merger = MergerAgent(llm=self.llm)
        self.validator = PDDLValidator()

        # Results
        self.partial_domains: list[PartialPDDLDomain] = []
        self.unified_domain: str = ""

    def _build_known_predicates(self) -> list[str]:
        """
        Build list of known predicates from:
        1. Base predicates (from shared common module)
        2. Phase 1 extracted predicates
        """
        # Start with base predicates
        known = set(get_base_predicates())

        # Add predicates from Phase 1 state
        for pred in self.phase1_state.predicates:
            pred_name = pred.get("name", "")
            args = pred.get("arguments", [])
            # Reconstruct predicate format
            if pred_name:
                if args:
                    # We don't have types in the state, so use generic format
                    known.add(f"({pred_name} ?arg)")
                else:
                    known.add(f"({pred_name})")

        return sorted(list(known))

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
        print("\nHardware Configuration:")
        print(
            f"  GPUs: {self.hardware.num_gpus}x (detected @ {self.hardware.gpu_memory_gb:.1f}GB)"
        )
        print(f"  RAM: {self.hardware.total_ram_gb:.0f}GB")
        print(f"  CPUs: {self.hardware.num_cpus}")
        print(f"  Parallel Workers: {self.hardware.max_parallel_workers}")
        print(f"\nLLM: {self.llm_config.model_name}")

        # =================================================================
        # Report Phase 1 integration status
        # =================================================================
        print("\nPhase 1 Integration:")
        print(f"  Objects: {sum(len(v) for v in self.phase1_state.objects.values())}")
        print(f"  Predicates: {len(self.phase1_state.predicates)}")
        print(
            f"  Actions: {len(self.phase1_actions)} (reuse: {self.reuse_phase1_actions})"
        )
        print(f"  Known predicates: {len(self.known_predicates)}")

        results["statistics"]["phase1_objects"] = sum(
            len(v) for v in self.phase1_state.objects.values()
        )
        results["statistics"]["phase1_predicates"] = len(self.phase1_state.predicates)
        results["statistics"]["phase1_actions"] = len(self.phase1_actions)
        results["statistics"]["known_predicates"] = len(self.known_predicates)

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

            # Count reused vs new actions
            reused_count = sum(
                1
                for d in successful
                for a in d.actions
                if getattr(a, "source_worker", "") == "phase1_reuse"
            )
            results["statistics"]["actions_reused_from_phase1"] = reused_count
            results["statistics"]["actions_generated_new"] = (
                results["statistics"]["total_actions"] - reused_count
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

            # Generate problem file from Phase 1 state
            problem_pddl = self._generate_problem_file()
            if problem_pddl:
                problem_path = self.output_dir / "sysadmin_problem.pddl"
                problem_path.write_text(problem_pddl)
                print(f"  → Problem saved to: {problem_path}")
                results["problem_path"] = str(problem_path)
                results["problem_pddl"] = problem_pddl
            else:
                print("  ⚠ No problem file generated (Phase 1 state has no objects)")
                results["warnings"].append("No problem file generated")

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
            f"    - Reused from Phase 1: {results['statistics'].get('actions_reused_from_phase1', 0)}"
        )
        print(
            f"    - Generated new: {results['statistics'].get('actions_generated_new', 0)}"
        )
        print(
            f"  Validation: {'PASSED' if results['validation_passed'] else 'WARNINGS'}"
        )

        return results

    def _generate_problem_file(self) -> Optional[str]:
        """
        Generate a PDDL problem file from Phase 1 state.

        Uses Phase 1 objects (from osquery) and predicates (grounded state)
        to produce a problem file compatible with the Phase 2 domain.
        The goal is left as a placeholder for Phase 3 to populate.
        """
        from common.type_hierarchy import normalize_type
        from common.predicates import sanitize_pddl_name

        if not self.phase1_state.objects:
            return None

        lines = [
            ";; =============================================================================",
            ";; SYSADMIN PDDL PROBLEM - Ubuntu 25.10 'Questing Quokka'",
            ";; Auto-generated by Phase 2 from Phase 1 osquery state",
            ";; =============================================================================",
            "",
            "(define (problem sysadmin-initial)",
            "  (:domain sysadmin)",
            "",
            "  (:objects",
        ]

        # Objects section — from Phase 1 osquery extraction
        included_objects = set()
        for pddl_type, objects in self.phase1_state.objects.items():
            if objects:
                safe_type = normalize_type(pddl_type)
                obj_names = " ".join(obj["name"] for obj in objects)
                included_objects.update(obj["name"] for obj in objects)
                lines.append(f"    {obj_names} - {safe_type}")
        lines.append("  )")
        lines.append("")

        # Init section — grounded predicates from Phase 1
        lines.append("  (:init")
        for pred in self.phase1_state.predicates:
            if pred.get("value", True):
                pred_name = sanitize_pddl_name(pred.get("name", ""))
                args = pred.get("arguments", [])
                # Only include predicates whose args are all known objects
                if all(arg in included_objects for arg in args):
                    args_str = " ".join(args)
                    if args_str:
                        lines.append(f"    ({pred_name} {args_str})")
                    else:
                        lines.append(f"    ({pred_name})")

        # Relationships
        for rel_type, relations in self.phase1_state.relationships.items():
            safe_rel = sanitize_pddl_name(rel_type)
            for rel in relations:
                if rel_type == "depends_on":
                    svc, pkg = rel.get("service"), rel.get("package")
                    if svc in included_objects and pkg in included_objects:
                        lines.append(f"    ({safe_rel} {svc} {pkg})")
                elif rel_type == "configures":
                    cfg, svc = rel.get("config"), rel.get("service")
                    if cfg in included_objects and svc in included_objects:
                        lines.append(f"    ({safe_rel} {cfg} {svc})")
                elif rel_type == "can_escalate":
                    user = rel.get("user")
                    if user in included_objects:
                        lines.append(f"    ({safe_rel} {user})")
                elif rel_type == "member_of":
                    user, group = rel.get("user"), rel.get("group")
                    if user in included_objects and group in included_objects:
                        lines.append(f"    ({safe_rel} {user} {group})")

        # Default environmental predicates
        lines.append("    (network_available)")
        lines.append("  )")
        lines.append("")

        # Goal — placeholder for Phase 3
        lines.append("  (:goal")
        lines.append("    (and")
        lines.append("      ;; Phase 3 will populate goals based on repair scenarios")
        lines.append("      (network_available)")
        lines.append("    )")
        lines.append("  )")
        lines.append("")
        lines.append(")")

        return "\n".join(lines)


def launch_vllm_server(config: LLMConfig, hardware: HardwareConfig) -> subprocess.Popen:
    """Launch vLLM server for LLM inference."""
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

    for _ in range(60):
        try:
            import urllib.request

            urllib.request.urlopen(f"{config.base_url}/health", timeout=1)
            logger.info("vLLM server is ready")
            return process
        except Exception:
            time.sleep(1)

    raise RuntimeError("vLLM server failed to start")
