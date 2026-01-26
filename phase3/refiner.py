"""
Domain Refiner for Phase 3: Core EW Calculation and LLM-based Refinement

This module implements the main refinement loop:
1. Calculate Exploration Walk (EW) score
2. Collect discrepancies between PDDL predictions and actual environment
3. Use LLM to update domain based on feedback
4. Iterate until EW score meets target (>0.9)
"""

import logging
import time
from typing import Optional
from datetime import datetime

from .config import Phase3Config, LLMRefinementConfig
from .models import (
    EWScore,
    ExplorationWalk,
    Discrepancy,
    RefinementIteration,
    ActionOutcome,
    GroundedAction,
    ExecutionResult,
)
from .docker_executor import DockerExecutor
from .planner_wrapper import RandomWalkGenerator
from .action_concretizer import ActionConcretizer, EffectVerifier

logger = logging.getLogger("Phase3.DomainRefiner")


class DomainRefiner:
    """
    Iteratively refines a PDDL domain using Exploration Walk feedback.

    The refinement loop:
    1. Generate N random walks of depth T_max
    2. Execute walks in sandboxed environment
    3. Compare predicted vs actual effects
    4. Collect discrepancies
    5. Use LLM to update domain
    6. Repeat until EW(d) > target

    EW(d) = (1 / (N * T_max)) * Σ E[E_env(q)]

    Where E_env(q) = 1 if action q's predicted effects match actual environment
    """

    def __init__(
        self,
        domain_pddl: str,
        problem_pddl: str = "",
        config: Optional[Phase3Config] = None,
    ):
        self.config = config or Phase3Config()

        # Current domain state
        self.domain_pddl = domain_pddl
        self.problem_pddl = problem_pddl

        # Components
        self.docker: Optional[DockerExecutor] = None
        self.planner: Optional[RandomWalkGenerator] = None
        self.concretizer = ActionConcretizer()
        self.effect_verifier: Optional[EffectVerifier] = None
        self.llm = None

        # State tracking
        self.feedback_logs: list[Discrepancy] = []
        self.iteration_history: list[RefinementIteration] = []
        self.current_score = 0.0

    def initialize(self):
        """Initialize all components."""
        logger.info("Initializing DomainRefiner components...")

        # Initialize Docker executor
        self.docker = DockerExecutor(
            config=self.config.docker,
            use_mock=self.config.use_mock_docker,
        )
        self.docker.start_container()

        # Initialize planner
        self.planner = RandomWalkGenerator(
            config=self.config.planner,
            use_mock=self.config.use_mock_planner,
        )
        self.planner.load_domain_string(self.domain_pddl, self.problem_pddl)

        # Initialize effect verifier
        self.effect_verifier = EffectVerifier(self.docker)

        # Initialize LLM
        if not self.config.use_mock_llm:
            self._initialize_llm()

        logger.info("DomainRefiner initialized")

    def _initialize_llm(self):
        """Initialize LLM client for domain refinement."""
        try:
            from openai import OpenAI
            self.llm = OpenAI(
                base_url=self.config.llm.base_url,
                api_key="not-needed-for-vllm",
            )
        except ImportError:
            logger.warning("OpenAI package not installed, LLM refinement disabled")
            self.llm = None

    def cleanup(self):
        """Cleanup resources."""
        if self.docker:
            self.docker.stop_container()

    def calculate_ew_score(
        self,
        num_walks: Optional[int] = None,
        walk_depth: Optional[int] = None,
    ) -> EWScore:
        """
        Calculate the Exploration Walk (EW) score for the current domain.

        EW(d) = (1 / (N * T_max)) * Σᵢ Σₜ E_env(qᵢₜ)

        Args:
            num_walks: Number of exploration walks (N)
            walk_depth: Maximum depth of each walk (T_max)

        Returns:
            EWScore with overall score and breakdown
        """
        num_walks = num_walks or self.config.walks_per_iteration
        walk_depth = walk_depth or self.config.walk_depth

        logger.info(f"Calculating EW score with N={num_walks}, T_max={walk_depth}")

        # Reset feedback logs for this evaluation
        self.feedback_logs = []

        total_steps = 0
        successful_steps = 0
        walk_scores = []
        all_discrepancies = []

        # Get current environment state
        env_state = self.docker.get_environment_state()

        for walk_id in range(num_walks):
            logger.debug(f"Starting exploration walk {walk_id + 1}/{num_walks}")

            # Generate random walk
            planned_actions = self.planner.generate_random_walk(walk_depth, env_state)

            walk = ExplorationWalk(
                walk_id=walk_id,
                planned_actions=planned_actions,
                executed_actions=[],
                steps_planned=len(planned_actions),
            )

            walk_successes = 0

            for action in planned_actions:
                # Concretize action to bash command
                command = self.concretizer.concretize(action)

                if not command:
                    # Can't concretize - log as discrepancy
                    discrepancy = Discrepancy(
                        action_name=action.name,
                        discrepancy_type="concretization",
                        expected=f"Valid bash command for {action.get_grounded_name()}",
                        actual="No template found",
                        context=f"Action parameters: {action.bindings}",
                        severity="high",
                    )
                    all_discrepancies.append(discrepancy)
                    walk.terminated_early = True
                    walk.termination_reason = "Cannot concretize action"
                    break

                # Execute action in container
                result = self.docker.execute_action(action, command)
                walk.executed_actions.append(result)
                walk.steps_executed += 1
                total_steps += 1

                if result.outcome == ActionOutcome.SUCCESS:
                    # Verify effects match PDDL predictions
                    matched, mismatched = self.effect_verifier.verify_effects(
                        action, action.action.effects
                    )

                    if not mismatched:
                        # Full success
                        walk_successes += 1
                        successful_steps += 1
                    else:
                        # Effect mismatch
                        result.outcome = ActionOutcome.EFFECT_MISMATCH
                        result.mismatched_effects = mismatched

                        discrepancy = Discrepancy(
                            action_name=action.name,
                            discrepancy_type="effect",
                            expected=str(action.action.effects),
                            actual=str(mismatched),
                            context=f"Command: {command}, Exit: {result.exit_code}",
                            severity="medium",
                        )
                        all_discrepancies.append(discrepancy)
                else:
                    # Execution failed
                    discrepancy = Discrepancy(
                        action_name=action.name,
                        discrepancy_type="execution",
                        expected="Exit code 0",
                        actual=f"Exit code {result.exit_code}: {result.stderr[:200]}",
                        context=f"Command: {command}",
                        severity="high" if result.exit_code != 0 else "medium",
                    )
                    all_discrepancies.append(discrepancy)

                    # Stop walk on failure
                    walk.terminated_early = True
                    walk.termination_reason = f"Action failed: {result.outcome.value}"
                    break

            # Calculate walk score
            walk.steps_successful = walk_successes
            walk_score = walk.calculate_success_rate()
            walk_scores.append(walk_score)

            logger.debug(
                f"Walk {walk_id + 1}: {walk_successes}/{walk.steps_executed} "
                f"steps successful (score: {walk_score:.3f})"
            )

            # Reset container for next walk to ensure isolation
            if walk_id < num_walks - 1:
                self.docker.reset_container()
                env_state = self.docker.get_environment_state()

        # Calculate overall EW score
        if total_steps > 0:
            ew_score = successful_steps / total_steps
        else:
            ew_score = 0.0

        self.feedback_logs = all_discrepancies
        self.current_score = ew_score

        result = EWScore(
            score=ew_score,
            num_walks=num_walks,
            max_depth=walk_depth,
            total_steps=total_steps,
            successful_steps=successful_steps,
            walk_scores=walk_scores,
            discrepancies=all_discrepancies,
        )

        logger.info(
            f"EW Score: {ew_score:.3f} ({successful_steps}/{total_steps} steps, "
            f"{len(all_discrepancies)} discrepancies)"
        )

        return result

    def llm_update_domain(self, discrepancies: list[Discrepancy]) -> str:
        """
        Use LLM to update the domain based on observed discrepancies.

        Args:
            discrepancies: List of discrepancies from exploration walks

        Returns:
            Updated PDDL domain string
        """
        if self.config.use_mock_llm or not self.llm:
            return self._mock_update_domain(discrepancies)

        # Build feedback string from discrepancies
        feedback_items = discrepancies[: self.config.llm.max_feedback_items]
        feedback_str = "\n\n".join(d.to_feedback_string() for d in feedback_items)

        prompt = f"""You are an expert PDDL domain designer. The following PDDL domain was tested against
a real Ubuntu 25.10 environment using exploration walks. Several discrepancies were found between
the predicted effects and actual outcomes.

CURRENT DOMAIN:
```pddl
{self.domain_pddl}
```

DISCREPANCIES FOUND:
{feedback_str}

Please update the PDDL domain to fix these discrepancies. Common issues include:
1. Missing preconditions (action can't execute in real environment)
2. Incorrect effects (predicted state changes don't match actual)
3. Missing type definitions
4. Wrong parameter types

Return ONLY the updated PDDL domain, enclosed in ```pddl ... ``` markers.
Make minimal changes - only fix the specific issues identified."""

        try:
            response = self.llm.chat.completions.create(
                model=self.config.llm.model_name,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=self.config.llm.max_tokens,
                temperature=self.config.llm.temperature,
            )

            content = response.choices[0].message.content

            # Extract PDDL from response
            updated_domain = self._extract_pddl(content)

            if updated_domain:
                logger.info(f"LLM generated updated domain ({len(updated_domain)} chars)")
                return updated_domain
            else:
                logger.warning("Could not extract PDDL from LLM response")
                return self.domain_pddl

        except Exception as e:
            logger.exception(f"LLM refinement failed: {e}")
            return self.domain_pddl

    def _extract_pddl(self, text: str) -> Optional[str]:
        """Extract PDDL domain from LLM response."""
        import re

        # Look for ```pddl ... ``` block
        match = re.search(r"```pddl\s*(.*?)\s*```", text, re.DOTALL)
        if match:
            return match.group(1).strip()

        # Look for ``` ... ``` block containing (define
        match = re.search(r"```\s*(\(define\s+\(domain.*?)\s*```", text, re.DOTALL)
        if match:
            return match.group(1).strip()

        # Look for raw (define (domain ...
        match = re.search(r"(\(define\s+\(domain\s+\w+\).*)", text, re.DOTALL)
        if match:
            return match.group(1).strip()

        return None

    def _mock_update_domain(self, discrepancies: list[Discrepancy]) -> str:
        """Mock domain update for testing."""
        logger.info(f"[MOCK] Updating domain based on {len(discrepancies)} discrepancies")

        # Simulate minor improvements
        # In a real scenario, the LLM would make intelligent fixes
        # Here we just return the original domain with a comment

        updated = self.domain_pddl.replace(
            "(define (domain",
            f"; Updated at {datetime.now().isoformat()} - {len(discrepancies)} discrepancies addressed\n(define (domain"
        )

        return updated

    def refine(self, max_iterations: Optional[int] = None) -> tuple[str, float]:
        """
        Main refinement loop.

        Iteratively improves the domain until EW score meets target.

        Args:
            max_iterations: Override max iterations from config

        Returns:
            (final_domain_pddl, final_ew_score)
        """
        max_iterations = max_iterations or self.config.max_refinement_iterations
        target = self.config.ew_target_score

        logger.info(f"Starting refinement loop (target: {target}, max_iter: {max_iterations})")

        best_domain = self.domain_pddl
        best_score = 0.0

        for iteration in range(1, max_iterations + 1):
            iter_start = time.time()
            logger.info(f"\n{'='*60}\nIteration {iteration}/{max_iterations}\n{'='*60}")

            # Calculate current EW score
            eval_start = time.time()
            ew_score = self.calculate_ew_score()
            eval_time = time.time() - eval_start

            logger.info(f"EW Score: {ew_score.score:.3f} (target: {target})")

            # Track best
            if ew_score.score > best_score:
                best_score = ew_score.score
                best_domain = self.domain_pddl

            # Check if target met
            if ew_score.meets_target(target):
                logger.info(f"Target EW score {target} achieved!")

                self.iteration_history.append(RefinementIteration(
                    iteration=iteration,
                    timestamp=datetime.now(),
                    domain_before=self.domain_pddl,
                    ew_score=ew_score,
                    domain_after=self.domain_pddl,
                    changes_made=["Target achieved - no changes needed"],
                    evaluation_time=eval_time,
                    refinement_time=0.0,
                ))

                return self.domain_pddl, ew_score.score

            # Refine domain based on discrepancies
            refine_start = time.time()
            domain_before = self.domain_pddl

            if ew_score.discrepancies:
                self.domain_pddl = self.llm_update_domain(ew_score.discrepancies)
                # Update planner with new domain
                self.planner.load_domain_string(self.domain_pddl, self.problem_pddl)

            refine_time = time.time() - refine_start

            # Record iteration
            self.iteration_history.append(RefinementIteration(
                iteration=iteration,
                timestamp=datetime.now(),
                domain_before=domain_before,
                ew_score=ew_score,
                domain_after=self.domain_pddl,
                changes_made=[f"Addressed {len(ew_score.discrepancies)} discrepancies"],
                evaluation_time=eval_time,
                refinement_time=refine_time,
            ))

            iter_time = time.time() - iter_start
            logger.info(
                f"Iteration {iteration} complete in {iter_time:.1f}s "
                f"(eval: {eval_time:.1f}s, refine: {refine_time:.1f}s)"
            )

        logger.warning(f"Max iterations ({max_iterations}) reached without achieving target")
        logger.info(f"Best score achieved: {best_score:.3f}")

        return best_domain, best_score

    def get_refinement_summary(self) -> dict:
        """Get summary of refinement session."""
        return {
            "iterations": len(self.iteration_history),
            "final_score": self.current_score,
            "target_score": self.config.ew_target_score,
            "target_achieved": self.current_score >= self.config.ew_target_score,
            "score_history": [it.ew_score.score for it in self.iteration_history],
            "total_discrepancies": sum(
                len(it.ew_score.discrepancies) for it in self.iteration_history
            ),
        }

    def __enter__(self):
        self.initialize()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False
