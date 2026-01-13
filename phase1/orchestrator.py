from typing import Optional

from phase1.common.config import MODEL, get_base_predicates
from phase1.common.logger import log
from phase1.introspection.extractor import SystemStateExtractor
from phase1.mining.manpage_parser import create_hybrid_parser
from phase1.pddl.generator import PDDLGenerator
from phase1.pddl.validator import PDDLValidator


class Phase1Orchestrator:
    """
    Main orchestrator for Phase 1: System Introspection.
    Coordinates extraction, action mining, and PDDL generation.

    Uses osquery 3.1.1 Thrift API for system state extraction.
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
        """
        Initialize orchestrator.

        Args:
            output_dir: Directory for PDDL output files
            osquery_socket: Optional socket path for osqueryd connection.
                           If None, spawns standalone instance.
            validate: If True, validate generated PDDL with VAL
            scoping_mode: "dynamic" for graph-based Anchor & Propagate,
                         "static" for legacy arbitrary caps
        """
        self.output_dir = output_dir
        self.osquery_socket = osquery_socket
        self.validate = validate
        self.scoping_mode = scoping_mode
        self.extractor = None
        self.parser = None
        self.generator = PDDLGenerator()
        self.validator = PDDLValidator() if validate else None
        self.state = {}
        self.actions = []
        self.llm_model = llm_model
        self.llm_url = llm_url
        self.enable_llm = enable_llm

    def run(self) -> dict:
        """Execute the complete Phase 1 pipeline."""
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
            log(f"  ✓ Connected to osquery")
        except Exception as e:
            results["errors"].append(f"Failed to initialize osquery: {e}")
            log(f"  ✗ Failed: {e}")
            log("  Hint: pip install osquery==3.1.1")
            # Continue without osquery (will generate skeleton domain)

        # Step 2: Extract system state
        log(f"\n[2/4] Extracting system state (scoping: {self.scoping_mode})...")

        if self.extractor:
            try:
                self.state = self.extractor.extract_all()
                results["state_extracted"] = True

                # Statistics
                for obj_type, objs in self.state.get("objects", {}).items():
                    results["statistics"][f"{obj_type}_count"] = len(objs)
                results["statistics"]["predicate_count"] = len(
                    self.state.get("predicates", [])
                )

                # Show scoping results if using dynamic mode
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

            # Report detected variants
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
                ["(network_available)"],  # Trivial goal for validation
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
                # Validate domain
                domain_valid, domain_msg = self.validator.validate_domain(
                    results.get("domain_pddl", "")
                )
                results["domain_valid"] = domain_valid
                if domain_valid:
                    log("  ✓ Domain syntax valid")
                else:
                    log(f"  ✗ Domain invalid: {domain_msg[:200]}")
                    results["warnings"].append(f"Domain validation: {domain_msg[:500]}")

                # Validate problem
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
                log("    Install from: https://github.com/KCL-Planning/VAL")

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
