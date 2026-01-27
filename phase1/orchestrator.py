"""
phase1/orchestrator.py

Main orchestrator for Phase 1: System Introspection.
Coordinates extraction, action mining, and PDDL generation.

Updated to:
- Serialize actions properly for Phase 2 consumption
- Use shared common modules
- Output complete Phase1State for integration
"""

import json
import os
import sys
from typing import Optional

# Add parent directory to path for common imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import Phase1State, ActionSchema
from common.predicates import get_base_predicates

from phase1.common.config import MODEL
from phase1.common.logger import log
from phase1.introspection.extractor import SystemStateExtractor
from phase1.mining.manpage_parser import create_hybrid_parser
from phase1.pddl.generator import PDDLGenerator
from phase1.pddl.validator import PDDLValidator


class Phase1Orchestrator:
    """
    Main orchestrator for Phase 1: System Introspection.
    Coordinates extraction, action mining, and PDDL generation.

    Outputs a complete Phase1State that can be consumed by Phase 2.
    """

    def __init__(
            self,
            output_dir: str = "./pddl_output",
            osquery_socket: Optional[str] = None,
            validate: bool = False,
            scoping_mode: str = "dynamic",
            llm_model: str = MODEL,
            llm_url: str = "http://localhost:11434",
            enable_llm: bool = True,
    ):
        self.output_dir = output_dir
        self.osquery_socket = osquery_socket
        self.validate = validate
        self.scoping_mode = scoping_mode
        self.extractor = None
        self.parser = None
        self.generator = PDDLGenerator()
        self.validator = PDDLValidator() if validate else None
        self.state = {}
        self.actions: list[ActionSchema] = []
        self.llm_model = llm_model
        self.llm_url = llm_url
        self.enable_llm = enable_llm

    def run(self) -> dict:
        """
        Execute the complete Phase 1 pipeline.

        Returns:
            dict containing:
            - success: bool
            - state_extracted: bool
            - actions_mined: bool
            - pddl_generated: bool
            - domain_pddl: str
            - problem_pddl: str
            - phase1_state: dict (serialized Phase1State for Phase 2)
            - actions: list[dict] (serialized actions)
            - statistics: dict
            - errors: list[str]
            - warnings: list[str]
        """
        results = {
            "success": False,
            "state_extracted": False,
            "actions_mined": False,
            "pddl_generated": False,
            "errors": [],
            "warnings": [],
            "statistics": {},
        }

        # Step 1: Initialize osquery interface
        log("=" * 60)
        log("Phase 1: System Introspection")
        log("=" * 60)
        log("\n[1/4] Initializing osquery Thrift API (osquery==3.1.1)...")

        try:
            self.extractor = SystemStateExtractor(
                socket_path=self.osquery_socket, scoping_mode=self.scoping_mode
            )
            log("  ✓ Connected to osquery")
        except Exception as e:
            results["errors"].append(f"Failed to initialize osquery: {e}")
            log(f"  ✗ Failed: {e}")
            log("  Hint: pip install osquery==3.1.1")

        # Step 2: Extract system state
        log(f"\n[2/4] Extracting system state (scoping: {self.scoping_mode})...")

        if self.extractor:
            try:
                self.state = self.extractor.extract_all()
                results["state_extracted"] = True

                for obj_type, objs in self.state.get("objects", {}).items():
                    results["statistics"][f"{obj_type}_count"] = len(objs)
                results["statistics"]["predicate_count"] = len(
                    self.state.get("predicates", [])
                )

                metadata = self.state.get("metadata", {})
                if metadata.get("scoping_method") == "anchor_propagate":
                    log(
                        f"  ✓ Scoping: {metadata.get('anchor_count', 0)} anchors → "
                        f"{metadata.get('reachable_count', 0)} reachable "
                        f"(pruned {metadata.get('pruned_count', 0)})"
                    )

                log(f"  ✓ Extracted objects: {results['statistics']}")
            except Exception as e:
                results["errors"].append(f"State extraction failed: {e}")
                log(f"  ✗ Failed: {e}")
                self.state = {"objects": {}, "predicates": [], "relationships": {}}
        else:
            log("  ⚠ Skipping (osquery not available)")
            self.state = {"objects": {}, "predicates": [], "relationships": {}}

        # Step 3: Mine actions from man pages
        log("\n[3/4] Mining actions from system documentation...")

        known_preds = get_base_predicates()

        try:
            self.parser = create_hybrid_parser(
                model_id=self.llm_model,
                model_url=self.llm_url,
                enable_llm=self.enable_llm,
                known_predicates=known_preds,
            )
            self.actions = self.parser.extract_all_actions()
            results["actions_mined"] = True
            results["statistics"]["action_count"] = len(self.actions)

            if self.parser.detected_variants:
                log(f"  ✓ Detected variants: {self.parser.detected_variants}")
            log(f"  ✓ Extracted {len(self.actions)} action schemas")

        except Exception as e:
            results["errors"].append(f"Action mining failed: {e}")
            log(f"  ✗ Failed: {e}")
            self.actions = []

        # Step 4: Generate PDDL
        log("\n[4/4] Generating PDDL domain...")

        try:
            domain_pddl = self.generator.generate_domain(self.state, self.actions)
            problem_pddl = self.generator.generate_problem(
                self.state,
                ["(network_available)"],
                "sysadmin-initial",
            )

            results["pddl_generated"] = True
            results["domain_pddl"] = domain_pddl
            results["problem_pddl"] = problem_pddl

            log(f"  ✓ Generated domain ({len(domain_pddl)} chars)")
            log(f"  ✓ Generated problem ({len(problem_pddl)} chars)")

        except Exception as e:
            results["errors"].append(f"PDDL generation failed: {e}")
            log(f"  ✗ Failed: {e}")

        # Step 5: Validate PDDL (optional)
        if self.validate and results.get("pddl_generated"):
            log("\n[5/5] Validating PDDL...")

            if self.validator and self.validator.is_available():
                domain_valid, domain_msg = self.validator.validate_domain(
                    results.get("domain_pddl", "")
                )
                results["domain_valid"] = domain_valid
                if domain_valid:
                    log("  ✓ Domain syntax valid")
                else:
                    log(f"  ✗ Domain invalid: {domain_msg[:200]}")
                    results["warnings"].append(f"Domain validation: {domain_msg[:500]}")

                problem_valid, problem_msg = self.validator.validate_problem(
                    results.get("domain_pddl", ""), results.get("problem_pddl", "")
                )
                results["problem_valid"] = problem_valid
                if problem_valid:
                    log("  ✓ Problem syntax valid")
                else:
                    log(f"  ✗ Problem invalid: {problem_msg[:200]}")
                    results["warnings"].append(
                        f"Problem validation: {problem_msg[:500]}"
                    )
            else:
                log("  ⚠ VAL validator not installed (skipping)")

        # =================================================================
        # NEW: Serialize actions and create Phase1State for Phase 2
        # =================================================================

        serialized_actions = self._serialize_actions()
        results["actions"] = serialized_actions
        results["statistics"]["serialized_actions"] = len(serialized_actions)

        # Create complete Phase1State
        phase1_state = Phase1State(
            objects=self.state.get("objects", {}),
            predicates=self.state.get("predicates", []),
            relationships=self.state.get("relationships", {}),
            actions=serialized_actions,
            metadata={
                **self.state.get("metadata", {}),
                "scoping_mode": self.scoping_mode,
                "llm_model": self.llm_model,
                "action_count": len(self.actions),
                "detected_variants": getattr(self.parser, "detected_variants", {}),
            }
        )

        results["phase1_state"] = phase1_state.to_dict()

        log(f"\n  ✓ Serialized {len(serialized_actions)} actions for Phase 2")

        # Save Phase 2 compatible state
        self.save_phase2_compat_state()

        # Final status
        results["success"] = results["pddl_generated"] and len(results["errors"]) == 0

        # Cleanup osquery connection
        if self.extractor and hasattr(self.extractor.osquery, "close"):
            self.extractor.osquery.close()
            log("\n  ✓ Closed osquery connection")

        log("\n" + "=" * 60)
        log(f"Phase 1 Complete: {'SUCCESS' if results['success'] else 'PARTIAL'}")
        log("=" * 60)

        return results

    def _serialize_actions(self) -> list[dict]:
        """
        Serialize extracted actions for Phase 2 consumption.

        Returns:
            List of serialized action dictionaries
        """
        serialized = []

        for action in self.actions:
            # Convert ActionParameter objects to dicts
            params = []
            for p in action.parameters:
                if hasattr(p, 'to_dict'):
                    params.append(p.to_dict())
                elif hasattr(p, 'pddl_type'):
                    # Handle original ActionParameter from phase1.common.models
                    params.append({
                        "name": p.name,
                        "type": p.pddl_type.value if hasattr(p.pddl_type, 'value') else str(p.pddl_type)
                    })
                else:
                    params.append({"name": str(p), "type": "object"})

            serialized.append({
                "name": action.name,
                "parameters": params,
                "preconditions": action.preconditions,
                "effects": action.effects,
                "command_template": action.command_template,
                "requires_root": action.requires_root,
                "source_utility": action.source_utility,
                "extraction_method": getattr(action, 'extraction_method', 'unknown'),
            })

        return serialized

    def save_phase1_state(self, filepath: str = None) -> str:
        """
        Save the complete Phase 1 state to a JSON file.

        Args:
            filepath: Path to save the state. Defaults to output_dir/phase1_state.json

        Returns:
            Path to the saved file
        """
        if filepath is None:
            os.makedirs(self.output_dir, exist_ok=True)
            filepath = os.path.join(self.output_dir, "phase1_state.json")

        phase1_state = Phase1State(
            objects=self.state.get("objects", {}),
            predicates=self.state.get("predicates", []),
            relationships=self.state.get("relationships", {}),
            actions=self._serialize_actions(),
            metadata={
                **self.state.get("metadata", {}),
                "scoping_mode": self.scoping_mode,
                "llm_model": self.llm_model,
                "action_count": len(self.actions),
                "detected_variants": getattr(self.parser, "detected_variants", {}),
            }
        )

        with open(filepath, "w") as f:
            f.write(phase1_state.to_json(indent=2))

        log(f"  ✓ Saved Phase 1 state to {filepath}")
        return filepath

    def save_phase2_compat_state(self, filepath: str = None) -> str:
        """
        Save the state in a format compatible with Phase 2.

        Args:
            filepath: Path to save the state. Defaults to output_dir/phase1_statep2.json

        Returns:
            Path to the saved file
        """
        if filepath is None:
            os.makedirs(self.output_dir, exist_ok=True)
            filepath = os.path.join(self.output_dir, "phase1_statep2.json")

        # Create a dictionary with the required keys
        phase2_state = {
            "objects": self.state.get("objects", {}),
            "predicates": self.state.get("predicates", []),
            "relationships": self.state.get("relationships", {}),
            "statistics": {
                f"{obj_type}_count": len(objs)
                for obj_type, objs in self.state.get("objects", {}).items()
            },
        }

        with open(filepath, "w") as f:
            json.dump(phase2_state, f, indent=2)

        log(f"  ✓ Saved Phase 2 compatible state to {filepath}")
        return filepath
