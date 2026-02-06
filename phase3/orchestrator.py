"""
Phase 3 Orchestrator: Coordinates the Iterative Refinement Pipeline

This module orchestrates the complete Phase 3 refinement process:
1. Load Phase 2 outputs (candidate PDDL domain)
2. Initialize sandbox environment
3. Run refinement loop
4. Save refined domain and reports
"""

import json
import logging
import re
import time
from pathlib import Path
from datetime import datetime
from typing import Optional

from .config import Phase3Config
from .refiner import DomainRefiner
from .models import RefinementSession

logger = logging.getLogger("Phase3.Orchestrator")


class Phase3Orchestrator:
    """
    Main orchestrator for Phase 3: Iterative Refinement via Exploration Walks.

    Coordinates:
    - Loading Phase 2 outputs
    - Docker sandbox management
    - Refinement iterations
    - Output generation
    """

    def __init__(
        self,
        config: Optional[Phase3Config] = None,
        domain_path: Optional[str] = None,
        problem_path: Optional[str] = None,
        output_dir: Optional[str] = None,
    ):
        self.config = config or Phase3Config()

        # Override paths if provided
        if domain_path:
            self.config.input_domain_path = domain_path
        if problem_path:
            self.config.input_problem_path = problem_path
        if output_dir:
            self.config.output_dir = output_dir

        # Output directory
        self.output_dir = Path(self.config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # State
        self.domain_pddl: str = ""
        self.problem_pddl: str = ""
        self.refiner: Optional[DomainRefiner] = None
        self.session: Optional[RefinementSession] = None

    def run(self) -> dict:
        """
        Execute the complete Phase 3 refinement pipeline.

        Returns:
            dict with results including:
            - success: bool
            - final_score: float
            - target_achieved: bool
            - iterations: int
            - domain_path: str (path to refined domain)
        """
        results = {
            "success": False,
            "phase": 3,
            "final_score": 0.0,
            "target_score": self.config.ew_target_score,
            "target_achieved": False,
            "iterations": 0,
            "errors": [],
            "warnings": [],
            "statistics": {},
        }

        start_time = time.time()

        print("\n" + "=" * 70)
        print("PHASE 3: ITERATIVE REFINEMENT VIA EXPLORATION WALKS")
        print("=" * 70)
        print(f"\nConfiguration:")
        print(f"  Target EW Score: {self.config.ew_target_score}")
        print(f"  Max Iterations: {self.config.max_refinement_iterations}")
        print(f"  Walks per Iteration: {self.config.walks_per_iteration}")
        print(f"  Walk Depth: {self.config.walk_depth}")
        print(f"  Docker Image: {self.config.docker.image}")
        print(f"  Output Directory: {self.output_dir}")

        try:
            # Load Phase 2 outputs
            print("\n" + "-" * 70)
            print("LOADING PHASE 2 OUTPUTS")
            print("-" * 70)
            self._load_inputs()

            # Auto-scale EW parameters based on domain size
            num_actions = len(re.findall(r'\(:action\s+', self.domain_pddl))
            self.config.auto_scale_ew_params(num_actions)

            print(f"  Domain: {self.config.input_domain_path}")
            print(f"    Size: {len(self.domain_pddl)} characters")
            print(f"    Actions: {num_actions}")
            print(f"  Problem: {self.config.input_problem_path}")
            print(f"  EW Params: walks={self.config.walks_per_iteration}, depth={self.config.walk_depth}")

            # Initialize session
            self.session = RefinementSession(
                session_id=datetime.now().strftime("%Y%m%d_%H%M%S"),
                started_at=datetime.now(),
                target_score=self.config.ew_target_score,
                max_iterations=self.config.max_refinement_iterations,
                initial_domain=self.domain_pddl,
                problem_pddl=self.problem_pddl,
            )

            # Initialize refiner
            print("\n" + "-" * 70)
            print("INITIALIZING REFINEMENT ENVIRONMENT")
            print("-" * 70)

            self.refiner = DomainRefiner(
                domain_pddl=self.domain_pddl,
                problem_pddl=self.problem_pddl,
                config=self.config,
            )
            self.refiner.initialize()

            print("  [✓] Docker sandbox started")
            print("  [✓] Planner initialized")
            print("  [✓] Action concretizer ready")

            # Run refinement loop
            print("\n" + "-" * 70)
            print("REFINEMENT LOOP")
            print("-" * 70)

            final_domain, final_score = self.refiner.refine()

            # Update session
            self.session.completed = True
            self.session.success = final_score >= self.config.ew_target_score
            self.session.final_domain = final_domain
            self.session.final_score = final_score
            self.session.total_time = time.time() - start_time
            self.session.iterations = self.refiner.iteration_history
            self.session.current_domain = final_domain
            self.session.current_score = final_score

            # Validate final domain with pddl library parser
            print("\n" + "-" * 70)
            print("PDDL VALIDATION GATE")
            print("-" * 70)

            valid, validation_msg = self._validate_final_domain(final_domain)
            if valid:
                print(f"  [OK] {validation_msg}")
            else:
                print(f"  [WARN] {validation_msg}")
                results["warnings"].append(f"PDDL validation: {validation_msg}")
                logger.warning(f"Final domain failed PDDL validation: {validation_msg}")

            # Save outputs
            print("\n" + "-" * 70)
            print("SAVING OUTPUTS")
            print("-" * 70)

            self._save_outputs(final_domain)

            # Build results
            summary = self.refiner.get_refinement_summary()
            results["success"] = True
            results["final_score"] = final_score
            results["target_achieved"] = final_score >= self.config.ew_target_score
            results["iterations"] = summary["iterations"]
            results["validation_passed"] = valid
            results["statistics"] = {
                "score_history": summary["score_history"],
                "total_discrepancies": summary["total_discrepancies"],
                "elapsed_time": time.time() - start_time,
            }
            results["domain_path"] = str(self.output_dir / "sysadmin_refined.pddl")

        except FileNotFoundError as e:
            logger.error(f"Input file not found: {e}")
            results["errors"].append(f"File not found: {e}")
        except Exception as e:
            logger.exception(f"Phase 3 failed: {e}")
            results["errors"].append(str(e))
        finally:
            # Cleanup
            if self.refiner:
                self.refiner.cleanup()

        # Print summary
        elapsed = time.time() - start_time
        self._print_summary(results, elapsed)

        return results

    def _validate_final_domain(self, domain_pddl: str) -> tuple[bool, str]:
        """
        Validate the final refined domain using the pddl library parser.
        Acts as a post-pipeline gate to catch syntax violations.

        Returns:
            (valid, message) tuple
        """
        import os
        import tempfile

        try:
            from pddl import parse_domain
        except ImportError:
            return True, "pddl library not installed — skipping validation"

        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".pddl", delete=False
            ) as f:
                f.write(domain_pddl)
                tmp_path = f.name

            parse_domain(tmp_path)
            return True, "Domain syntax validated successfully by pddl parser"

        except Exception as e:
            error_msg = str(e)
            # Truncate long error messages
            if len(error_msg) > 300:
                error_msg = error_msg[:300] + "..."
            return False, f"Parse error: {error_msg}"
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def _load_inputs(self):
        """Load domain and problem PDDL files."""
        domain_path = Path(self.config.input_domain_path)
        problem_path = Path(self.config.input_problem_path)

        if not domain_path.exists():
            raise FileNotFoundError(f"Domain file not found: {domain_path}")

        self.domain_pddl = domain_path.read_text()

        if problem_path.exists():
            self.problem_pddl = problem_path.read_text()
        else:
            logger.warning(f"Problem file not found: {problem_path}")
            self.problem_pddl = ""

    def _save_outputs(self, final_domain: str):
        """Save refined domain and reports."""
        # Save refined domain
        refined_path = self.output_dir / "sysadmin_refined.pddl"
        refined_path.write_text(final_domain)
        print(f"  [✓] Refined domain: {refined_path}")

        # Save intermediate domains if enabled
        if self.config.save_intermediate_domains and self.refiner:
            intermediates_dir = self.output_dir / "intermediate_domains"
            intermediates_dir.mkdir(exist_ok=True)

            for i, iteration in enumerate(self.refiner.iteration_history):
                iter_path = intermediates_dir / f"domain_iter_{i+1}.pddl"
                iter_path.write_text(iteration.domain_after)

            print(f"  [✓] Intermediate domains: {intermediates_dir}")

        # Save refinement report
        if self.session:
            report = self._generate_report()
            report_path = self.output_dir / "refinement_report.json"
            report_path.write_text(json.dumps(report, indent=2, default=str))
            print(f"  [✓] Refinement report: {report_path}")

        # Save discrepancy log
        if self.refiner and self.refiner.feedback_logs:
            discrepancy_log = [
                {
                    "action": d.action_name,
                    "type": d.discrepancy_type,
                    "expected": d.expected,
                    "actual": d.actual,
                    "context": d.context,
                    "severity": d.severity,
                }
                for d in self.refiner.feedback_logs
            ]
            log_path = self.output_dir / "discrepancy_log.json"
            log_path.write_text(json.dumps(discrepancy_log, indent=2))
            print(f"  [✓] Discrepancy log: {log_path}")

    def _generate_report(self) -> dict:
        """Generate detailed refinement report."""
        return {
            "session_id": self.session.session_id,
            "started_at": self.session.started_at.isoformat(),
            "completed": self.session.completed,
            "success": self.session.success,
            "configuration": {
                "target_score": self.session.target_score,
                "max_iterations": self.session.max_iterations,
                "walks_per_iteration": self.config.walks_per_iteration,
                "walk_depth": self.config.walk_depth,
                "docker_image": self.config.docker.image,
            },
            "results": {
                "final_score": self.session.final_score,
                "target_achieved": self.session.final_score >= self.session.target_score,
                "iterations_completed": len(self.session.iterations),
                "total_time_seconds": self.session.total_time,
            },
            "score_history": [
                {
                    "iteration": i + 1,
                    "score": it.ew_score.score,
                    "discrepancies": len(it.ew_score.discrepancies),
                    "eval_time": it.evaluation_time,
                    "refine_time": it.refinement_time,
                }
                for i, it in enumerate(self.session.iterations)
            ],
            "domain_stats": {
                "initial_size": len(self.session.initial_domain),
                "final_size": len(self.session.final_domain),
            },
        }

    def _print_summary(self, results: dict, elapsed: float):
        """Print final summary."""
        print("\n" + "=" * 70)
        print("PHASE 3 SUMMARY")
        print("=" * 70)

        status = "SUCCESS" if results["target_achieved"] else "INCOMPLETE"
        print(f"""
    Status: {status}
    Final EW Score: {results['final_score']:.3f} (target: {results['target_score']})
    Iterations: {results['iterations']}
    Total Time: {elapsed:.1f} seconds

    Output Files:
      - {self.output_dir / "sysadmin_refined.pddl"}
      - {self.output_dir / "refinement_report.json"}
        """)

        if results["errors"]:
            print("    Errors:")
            for error in results["errors"]:
                print(f"      - {error}")

        if results["warnings"]:
            print("    Warnings:")
            for warning in results["warnings"]:
                print(f"      - {warning}")


def run_phase3(
    domain_path: str,
    problem_path: str = "",
    output_dir: str = "./pddl_output/phase3",
    target_score: float = 0.9,
    max_iterations: int = 10,
    use_mock: bool = False,
) -> dict:
    """
    Convenience function to run Phase 3 refinement.

    Args:
        domain_path: Path to input PDDL domain
        problem_path: Path to input PDDL problem (optional)
        output_dir: Directory for outputs
        target_score: Target EW score
        max_iterations: Maximum refinement iterations
        use_mock: Use mock components for testing

    Returns:
        Results dictionary
    """
    config = Phase3Config()
    config.input_domain_path = domain_path
    config.input_problem_path = problem_path
    config.output_dir = output_dir
    config.ew_target_score = target_score
    config.max_refinement_iterations = max_iterations
    config.use_mock_docker = use_mock
    config.use_mock_planner = use_mock
    config.use_mock_llm = use_mock

    orchestrator = Phase3Orchestrator(config=config)
    return orchestrator.run()
