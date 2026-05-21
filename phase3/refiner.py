"""
Domain Refiner for Phase 3: Core EW Calculation and LLM-based Refinement

This module implements the main refinement loop:
1. Calculate Exploration Walk (EW) score
2. Collect discrepancies between PDDL predictions and actual environment
3. Use LLM to update domain based on feedback (targeted per-action repair)
4. Iterate until EW score meets target (>0.9)

Follows Phase 2's targeted repair pattern:
- Never send the full domain to the LLM
- Extract only broken actions from discrepancies
- Send each broken action individually with its specific error
- Use PDDL_SYNTAX_GUIDE in prompts
- Use PDDLSanitizer to fix common syntax issues
- Validate results before accepting
- Rollback to best domain on catastrophic failure
"""

import logging
import random
import re
import sys
import os
import time
import tempfile
from typing import Optional
from datetime import datetime
from collections import defaultdict

from .config import Phase3Config, LLMRefinementConfig, LLM_CONCURRENCY_GATE
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
from .planner_wrapper import RandomWalkGenerator, PDDLParser
from .action_concretizer import ActionConcretizer, EffectVerifier
from .pddl_simulator import PDDLStateSimulator

# Import Phase 2 shared tools
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.pddl_rules import PDDL_SYNTAX_GUIDE
from common.pddl_sanitizer import PDDLSanitizer

logger = logging.getLogger("Phase3.DomainRefiner")


class DomainRefiner:
    """
    Iteratively refines a PDDL domain using Exploration Walk feedback.

    The refinement loop:
    1. Generate N random walks of depth T_max
    2. Execute walks in sandboxed environment
    3. Compare predicted vs actual effects
    4. Collect discrepancies
    5. Use LLM to update domain (targeted per-action repair)
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
        self.concretizer: Optional[ActionConcretizer] = None
        self.effect_verifier: Optional[EffectVerifier] = None
        self.llm = None
        self.sanitizer = PDDLSanitizer()

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
        )
        self.docker.start_container()

        # Initialize planner
        self.planner = RandomWalkGenerator(
            config=self.config.planner,
        )
        self.planner.load_domain_string(self.domain_pddl, self.problem_pddl)

        # Initialize effect verifier
        self.effect_verifier = EffectVerifier(self.docker)

        # Initialize LLM
        self._initialize_llm()

        # Initialize concretizer with Phase 1 metadata and LLM client
        cache_path = self.config.concretizer_cache_path or os.path.join(
            self.config.output_dir, "concretizer_cache.json"
        )
        self.concretizer = ActionConcretizer(
            phase1_metadata_path=self.config.phase1_metadata_path,
            llm_client=self.llm,
            llm_model=self.config.llm.concretizer_model,
            llm_max_tokens=self.config.llm.concretizer_max_tokens,
            llm_temperature=self.config.llm.concretizer_temperature,
            cache_path=cache_path,
        )

        logger.info("DomainRefiner initialized")

    def _initialize_llm(self):
        """Initialize LLM client for domain refinement.

        Generous timeout + retries because reasoning models (e.g. MiniMax M2.7)
        emit long <think> blocks before answering. A short 120s cap surfaced
        as opaque "Connection error" (actually read-timeout) on the concretizer
        path and tanked Phase 3 EW scores even though MiniMax was healthy.
        """
        try:
            from openai import OpenAI
            self.llm = OpenAI(
                base_url=self.config.llm.base_url,
                api_key=self.config.llm.api_key,
                timeout=600.0,    # 10 min per call
                max_retries=5,    # default is 2; absorb transient hiccups
            )
        except ImportError:
            logger.warning("OpenAI package not installed, LLM refinement disabled")
            self.llm = None

    def cleanup(self):
        """Cleanup resources."""
        if self.docker:
            self.docker.stop_container()

    # =========================================================================
    # EW Score Calculation (unchanged)
    # =========================================================================

    def calculate_ew_score(
        self,
        num_walks: Optional[int] = None,
        walk_depth: Optional[int] = None,
    ) -> EWScore:
        """
        Calculate the Exploration Walk (EW) score for the current domain.

        Implements the paper's algorithm (arxiv 2407.12979):
        1. Maintain PDDL state (set of ground facts, closed-world assumption)
        2. At each step, find all LEGAL actions (preconditions satisfied in state)
        3. Sample uniformly from legal actions
        4. Execute in Docker, apply PDDL effects to update state
        5. Docker failure on a PDDL-legal action = discrepancy

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

        # Track action diversity across all walks
        action_counts: dict[str, int] = defaultdict(int)
        concretization_failures = 0
        execution_failures = 0
        effect_mismatches = 0

        for walk_id in range(num_walks):
            # Build fresh simulator per walk (fresh PDDL state)
            simulator = PDDLStateSimulator(
                domain_pddl=self.planner.domain_pddl,
                env_state=env_state,
                problem_pddl=self.planner.problem_pddl,
            )

            walk_successes = 0
            walk_steps = 0

            for step in range(walk_depth):
                # Find all LEGAL actions (preconditions satisfied in PDDL state)
                applicable = simulator.get_applicable_actions()
                if not applicable:
                    logger.info(
                        f"Walk {walk_id + 1}: no applicable actions at step "
                        f"{step}, terminating ({walk_steps} steps completed)"
                    )
                    break  # Walk terminates naturally

                # Sample uniformly from legal actions
                grounded = random.choice(applicable)
                walk_steps += 1
                total_steps += 1
                action_counts[grounded.name] += 1

                # Find the ParsedAction for effect application
                parsed_action = None
                for pa in simulator.actions:
                    if pa.name == grounded.name:
                        parsed_action = pa
                        break

                # Concretize action to bash command
                command = self.concretizer.concretize(grounded)

                if not command or command.strip() == "true":
                    # Can't concretize — model has action but no bash mapping
                    # "true" is a bash no-op that always exits 0 — it tests
                    # nothing, so treat it the same as a missing template.
                    concretization_failures += 1
                    discrepancy = Discrepancy(
                        action_name=grounded.name,
                        discrepancy_type="concretization",
                        expected=f"Valid bash command for {grounded.get_grounded_name()}",
                        actual="No template found" if not command else "No-op (true)",
                        context=f"Action parameters: {grounded.bindings}",
                        severity="high",
                    )
                    all_discrepancies.append(discrepancy)
                    # Still apply effects (model believes action succeeded)
                    if parsed_action:
                        simulator.apply_effects(parsed_action, grounded.bindings)
                    continue

                # Execute action in Docker
                result = self.docker.execute_action(grounded, command)

                if result.outcome == ActionOutcome.SUCCESS:
                    # Verify effects match PDDL predictions
                    matched, mismatched = self.effect_verifier.verify_effects(
                        grounded, grounded.action.effects
                    )

                    if not mismatched:
                        # Full success — PDDL model matches environment
                        walk_successes += 1
                        successful_steps += 1
                    else:
                        # Effect mismatch
                        effect_mismatches += 1
                        result.outcome = ActionOutcome.EFFECT_MISMATCH
                        result.mismatched_effects = mismatched

                        discrepancy = Discrepancy(
                            action_name=grounded.name,
                            discrepancy_type="effect",
                            expected=str(grounded.action.effects),
                            actual=str(mismatched),
                            context=f"Command: {command}, Exit: {result.exit_code}",
                            severity="medium",
                        )
                        all_discrepancies.append(discrepancy)
                else:
                    # Check if failure was due to blocked dangerous command
                    if "Command blocked" in result.stderr:
                        # Don't count blocked commands as discrepancies —
                        # they are safety constraints, not PDDL issues
                        logger.debug(
                            f"Skipping blocked command for {grounded.name}: {command[:60]}"
                        )
                        # Still apply PDDL effects (model assumes success)
                        if parsed_action:
                            simulator.apply_effects(parsed_action, grounded.bindings)
                        # Don't count this step at all (reduce total_steps)
                        total_steps -= 1
                        continue

                    # Docker failure on PDDL-legal action = THE discrepancy
                    execution_failures += 1
                    discrepancy = Discrepancy(
                        action_name=grounded.name,
                        discrepancy_type="execution",
                        expected="Exit code 0",
                        actual=f"Exit code {result.exit_code}: {result.stderr[:200]}",
                        context=f"Command: {command}",
                        severity="high" if result.exit_code != 0 else "medium",
                    )
                    all_discrepancies.append(discrepancy)

                # Apply PDDL effects to update state (model assumes success)
                if parsed_action:
                    simulator.apply_effects(parsed_action, grounded.bindings)

            # Calculate walk score
            walk_score = walk_successes / walk_steps if walk_steps > 0 else 0.0
            walk_scores.append(walk_score)

            logger.info(
                f"Walk {walk_id + 1}/{num_walks}: {walk_successes}/{walk_steps} "
                f"steps successful (score: {walk_score:.3f})"
            )

            # Reset container for next walk to ensure isolation
            if walk_id < num_walks - 1:
                self.docker.reset_container()
                env_state = self.docker.get_environment_state()

        # Log diagnostic summary
        unique_actions = len(action_counts)
        top_actions = sorted(action_counts.items(), key=lambda x: -x[1])[:10]
        logger.info(
            f"Walk diagnostics: {unique_actions} unique actions sampled, "
            f"concretization_failures={concretization_failures}, "
            f"execution_failures={execution_failures}, "
            f"effect_mismatches={effect_mismatches}"
        )
        logger.info(
            f"Top 10 actions: "
            + ", ".join(f"{name}({count})" for name, count in top_actions)
        )

        # Log concretizer tier stats
        if self.concretizer:
            stats = self.concretizer.get_stats()
            logger.info(
                f"Concretizer stats: phase1={stats['phase1_hits']}, "
                f"cache={stats['cache_hits']}, llm={stats['llm_hits']}, "
                f"failures={stats['failures']}"
            )

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

    # =========================================================================
    # Action Extraction / Replacement Helpers
    # =========================================================================

    def _extract_action_blocks(self, domain_pddl: str) -> dict[str, str]:
        """
        Extract individual (:action ...) blocks from a domain string.

        Returns:
            Dict mapping action_name -> raw PDDL text of that action block
        """
        actions = {}
        # Find each (:action ...) by balanced parentheses
        i = 0
        while i < len(domain_pddl):
            match = re.search(r'\(:action\s+(\S+)', domain_pddl[i:])
            if not match:
                break

            action_start = i + match.start()
            action_name = match.group(1)

            # Find the balanced closing paren
            depth = 0
            action_end = action_start
            for j in range(action_start, len(domain_pddl)):
                if domain_pddl[j] == '(':
                    depth += 1
                elif domain_pddl[j] == ')':
                    depth -= 1
                    if depth == 0:
                        action_end = j + 1
                        break

            actions[action_name] = domain_pddl[action_start:action_end]
            i = action_end

        return actions

    def _replace_action_block(
        self, domain_pddl: str, action_name: str, new_action_pddl: str
    ) -> str:
        """
        Replace a single (:action action_name ...) block in the domain.

        Returns the domain with the action replaced, or unchanged if not found.
        """
        # Find the action block
        pattern = re.compile(r'\(:action\s+' + re.escape(action_name) + r'\s')
        match = pattern.search(domain_pddl)
        if not match:
            return domain_pddl

        action_start = match.start()

        # Find balanced closing paren
        depth = 0
        action_end = action_start
        for j in range(action_start, len(domain_pddl)):
            if domain_pddl[j] == '(':
                depth += 1
            elif domain_pddl[j] == ')':
                depth -= 1
                if depth == 0:
                    action_end = j + 1
                    break

        return domain_pddl[:action_start] + new_action_pddl + domain_pddl[action_end:]

    def _count_actions(self, domain_pddl: str) -> int:
        """Count the number of (:action ...) blocks in a domain."""
        return len(re.findall(r'\(:action\s+', domain_pddl))

    # =========================================================================
    # Domain Validation
    # =========================================================================

    def _validate_domain(self, candidate_domain: str, original_domain: str) -> bool:
        """
        Validate a candidate domain against the original.

        Checks:
        1. Has (define (domain ...)) structure
        2. Action count didn't drop catastrophically
        3. Basic parentheses balance
        4. Uses PDDLSanitizer for syntax fixes

        Returns:
            True if domain is acceptable, False if should rollback
        """
        # Check basic structure
        if "(define (domain" not in candidate_domain:
            logger.warning("Validation failed: missing (define (domain ...))")
            return False

        # Check parentheses balance
        if candidate_domain.count("(") != candidate_domain.count(")"):
            logger.warning("Validation failed: unbalanced parentheses")
            return False

        # Check action count
        original_count = self._count_actions(original_domain)
        candidate_count = self._count_actions(candidate_domain)

        if candidate_count == 0 and original_count > 0:
            logger.warning(
                f"Validation failed: candidate has 0 actions "
                f"(original had {original_count})"
            )
            return False

        if original_count > 0 and candidate_count < original_count * 0.5:
            logger.warning(
                f"Validation failed: lost >50% of actions "
                f"({candidate_count}/{original_count})"
            )
            return False

        # Check domain isn't drastically smaller (LLM truncation)
        if len(candidate_domain) < len(original_domain) * 0.3:
            logger.warning(
                f"Validation failed: domain shrank to {len(candidate_domain)} chars "
                f"from {len(original_domain)} chars (>70% reduction)"
            )
            return False

        return True

    # =========================================================================
    # Targeted LLM Repair (Phase 2 pattern)
    # =========================================================================

    def _repair_single_action_with_llm(
        self, action_name: str, action_pddl: str, errors: list[str]
    ) -> Optional[str]:
        """
        Send ONE action + its specific errors to the LLM for repair.

        Follows Phase 2's _repair_single_action_with_llm pattern:
        small, focused prompt with PDDL_SYNTAX_GUIDE.

        Args:
            action_name: Name of the broken action
            action_pddl: The raw PDDL text of the action
            errors: List of error/discrepancy descriptions

        Returns:
            Repaired action PDDL string, or None if repair failed
        """
        if not self.llm:
            return None

        errors_str = "\n".join(f"- {e}" for e in errors[:5])

        system_msg = (
            "You output ONLY valid PDDL. No explanation, no markdown. "
            "Your entire response must be a single (:action ...) block."
        )

        prompt = (
            f"Fix this PDDL action based on the discrepancies below.\n\n"
            f"ERRORS:\n{errors_str}\n\n"
            f"ACTION:\n{action_pddl}\n\n"
            f"PDDL SYNTAX RULES:\n{PDDL_SYNTAX_GUIDE}\n\n"
            f"RULES:\n"
            f"- Keep the action name '{action_name}' unchanged.\n"
            f"- Declare all variables used in :precondition/:effect in :parameters.\n"
            f"- Do not use reserved keywords as predicate names.\n"
            f"- Output ONLY the fixed (:action ...) block, nothing else."
        )

        try:
            # Try with system message first; fall back to single user
            # message if the model returns empty (some Ollama models
            # don't handle system messages well).
            # Simplified direct prompt (no PDDL_SYNTAX_GUIDE) as a fallback
            simple_prompt = (
                f"Fix this PDDL action. Output ONLY the fixed (:action ...) block.\n\n"
                f"ERRORS:\n{errors_str}\n\n"
                f"ACTION:\n{action_pddl}\n\n"
                f"Output the corrected (:action {action_name} ...) block:"
            )

            messages_variants = [
                # Variant 1: system + user (standard)
                [
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": prompt},
                ],
                # Variant 2: combined single user message
                [
                    {"role": "user", "content": system_msg + "\n\n" + prompt},
                ],
                # Variant 3: simplified direct prompt (no PDDL guide)
                [
                    {"role": "user", "content": simple_prompt},
                ],
            ]

            content = None
            for variant_idx, msg_variant in enumerate(messages_variants):
                # Throttle alongside the concretizer (shared gate).
                with LLM_CONCURRENCY_GATE:
                    response = self.llm.chat.completions.create(
                        model=self.config.llm.model_name,
                        messages=msg_variant,
                        max_tokens=self.config.llm.max_tokens or None,
                        temperature=self.config.llm.temperature,
                    )

                # Try multiple ways to extract content from the response
                content = None
                if response.choices:
                    choice = response.choices[0]
                    content = getattr(choice.message, 'content', None)
                    # Some APIs put content in different fields
                    if not content:
                        content = getattr(choice, 'text', None)
                    if not content:
                        # Try serializing the message to find any content
                        try:
                            msg_dict = choice.message.model_dump()
                            content = msg_dict.get('content')
                        except Exception:
                            pass

                    finish_reason = getattr(choice, 'finish_reason', 'unknown')
                else:
                    finish_reason = 'no_choices'

                if content and content.strip():
                    break  # Got valid content

                # Log detailed response info for debugging empty responses
                try:
                    raw_dump = response.model_dump()
                    logger.debug(
                        f"  LLM empty content for '{action_name}' "
                        f"(variant={variant_idx}, finish_reason={finish_reason}, "
                        f"n_choices={len(response.choices) if response.choices else 0}, "
                        f"raw_keys={list(raw_dump.get('choices', [{}])[0].get('message', {}).keys()) if raw_dump.get('choices') else 'none'})"
                    )
                except Exception:
                    logger.debug(
                        f"  LLM empty content for '{action_name}' "
                        f"(variant={variant_idx}, finish_reason={finish_reason})"
                    )

            if not content or not content.strip():
                logger.warning(
                    f"  LLM returned empty response for '{action_name}' "
                    f"after {len(messages_variants)} variants"
                )
                return None

            raw_response = content[:300]  # for logging
            content = content.strip()

            # Strip thinking tags (Qwen3, DeepSeek-R1, etc. wrap output
            # in <think>...</think> before the actual PDDL)
            content = re.sub(r'<think>.*?</think>\s*', '', content, flags=re.DOTALL)
            content = content.strip()

            # Strip markdown fences (various formats LLMs use)
            content = re.sub(r'^```(?:pddl|lisp|scheme|plaintext)?\s*\n?', '', content)
            content = re.sub(r'\n?\s*```\s*$', '', content)
            content = content.strip()

            # --- Robust action block extraction ---
            # Strategy 1: Find (:action action_name using exact match
            action_start = None
            pattern_exact = re.search(
                r'\(:action\s+' + re.escape(action_name) + r'\b',
                content
            )
            if pattern_exact:
                action_start = pattern_exact.start()

            # Strategy 2: Find any (:action with case-insensitive match
            if action_start is None:
                pattern_any = re.search(
                    r'\(:action\s+' + re.escape(action_name) + r'\b',
                    content, re.IGNORECASE
                )
                if pattern_any:
                    action_start = pattern_any.start()

            # Strategy 3: Find any (:action block at all
            if action_start is None:
                pattern_generic = re.search(r'\(:action\s+\w+', content)
                if pattern_generic:
                    action_start = pattern_generic.start()
                    found_name = re.match(
                        r'\(:action\s+(\S+)', content[action_start:]
                    )
                    if found_name:
                        logger.debug(
                            f"  LLM returned action '{found_name.group(1)}' "
                            f"instead of '{action_name}'"
                        )

            if action_start is None:
                logger.warning(
                    f"  LLM response has no (:action block for '{action_name}'. "
                    f"Response start: {raw_response!r}"
                )
                return None

            # Use balanced-paren extraction from action_start
            depth = 0
            action_end = action_start
            for j in range(action_start, len(content)):
                if content[j] == '(':
                    depth += 1
                elif content[j] == ')':
                    depth -= 1
                    if depth == 0:
                        action_end = j + 1
                        break
            else:
                # Never balanced - add missing closing parens
                needed = depth
                action_end = len(content)
                content = content + ')' * needed
                action_end = len(content)

            content = content[action_start:action_end]

            # Ensure parentheses are balanced after extraction
            open_count = content.count('(')
            close_count = content.count(')')
            if open_count > close_count:
                content += ')' * (open_count - close_count)
            elif close_count > open_count:
                excess = close_count - open_count
                for _ in range(excess):
                    last = content.rfind(')')
                    if last > 0:
                        content = content[:last] + content[last + 1:]

            # Run through PDDLSanitizer for common fixes
            content = self.sanitizer.repair(content)

            # Verify the result starts with (:action
            name_match = re.match(r'\(:action\s+(\S+)', content)
            if not name_match:
                logger.warning(
                    f"  After sanitizer, no (:action found for '{action_name}'"
                )
                return None

            # Accept the action even if the LLM changed the name -
            # just fix it back to the original
            extracted_name = name_match.group(1)
            if extracted_name != action_name:
                logger.debug(
                    f"  Fixing LLM action name: '{extracted_name}' -> '{action_name}'"
                )
                content = (
                    content[:name_match.start(1)]
                    + action_name
                    + content[name_match.end(1):]
                )

            # Minimal validation: must have :parameters, :precondition or :effect
            if ':parameters' not in content and ':effect' not in content:
                logger.warning(
                    f"  LLM repair for '{action_name}' missing required sections"
                )
                return None

            # Validate repaired action parses as valid PDDL
            if not self._validate_single_action_pddl(content):
                logger.warning(
                    f"  LLM repair for '{action_name}' failed PDDL validation, keeping original"
                )
                return None

            logger.info(
                f"  LLM repaired action '{action_name}' "
                f"({len(content)} chars)"
            )
            return content

        except Exception as e:
            logger.error(f"LLM repair failed for '{action_name}': {e}")
            return None

    def _validate_single_action_pddl(self, action_pddl: str) -> bool:
        """
        Validate that a single action block is syntactically valid PDDL.

        Wraps the action in a minimal domain and attempts to parse it.
        """
        try:
            from pddl import parse_domain

            # Build minimal domain with just this action
            test_domain = (
                "(define (domain test)\n"
                "  (:requirements :strips :typing :negative-preconditions)\n"
                "  (:types object)\n"
                "  (:predicates (dummy ?x - object))\n"
                f"  {action_pddl}\n"
                ")"
            )

            # Parse it
            tmp_path = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".pddl", delete=False
                ) as tmp:
                    tmp_path = tmp.name
                    tmp.write(test_domain)

                parse_domain(tmp_path)
                return True
            except Exception as e:
                logger.debug(f"  Action validation error: {str(e)[:200]}")
                return False
            finally:
                if tmp_path:
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass

        except ImportError:
            # pddl library not available — skip validation
            return True

    def llm_update_domain(self, discrepancies: list[Discrepancy]) -> str:
        """
        Use LLM to update the domain based on observed discrepancies.

        TARGETED REPAIR: Only sends broken actions to the LLM, not the
        full domain. Follows Phase 2's _validate_and_repair_actions pattern.

        Args:
            discrepancies: List of discrepancies from exploration walks

        Returns:
            Updated PDDL domain string
        """
        if not self.llm:
            logger.error("LLM not available, cannot repair domain")
            return self.domain_pddl

        original_domain = self.domain_pddl
        original_action_count = self._count_actions(original_domain)

        # Group discrepancies by action name — only include execution and
        # effect failures (actual PDDL problems). Concretization failures are
        # mapping issues in the concretizer, NOT broken PDDL.
        action_errors: dict[str, list[str]] = defaultdict(list)
        skipped_concretization = 0
        for d in discrepancies[:self.config.llm.max_feedback_items]:
            if d.discrepancy_type == "concretization":
                skipped_concretization += 1
                continue
            error_desc = (
                f"[{d.discrepancy_type}] Expected: {d.expected[:150]} | "
                f"Actual: {d.actual[:150]}"
            )
            if d.context:
                error_desc += f" | Context: {d.context[:100]}"
            action_errors[d.action_name].append(error_desc)

        # Categorize errors — skip those that can't be fixed by PDDL repair
        UNFIXABLE_PATTERNS = [
            "System has not been booted with systemd",
            "command not found",
            "Command blocked",
            "Read-only file system",
            "Cannot allocate memory",
            "Connection refused",
            "Host is down",
        ]

        fixable_errors: dict[str, list[str]] = defaultdict(list)
        unfixable_count = 0
        for action_name, errors in action_errors.items():
            fixable = []
            for err in errors:
                if any(pat in err for pat in UNFIXABLE_PATTERNS):
                    unfixable_count += 1
                else:
                    fixable.append(err)
            if fixable:
                fixable_errors[action_name] = fixable

        if unfixable_count:
            logger.info(
                f"Skipped {unfixable_count} unfixable errors "
                f"(container capability / missing tools)"
            )

        action_errors = fixable_errors

        if skipped_concretization:
            logger.info(
                f"Skipped {skipped_concretization} concretization discrepancies "
                f"(not PDDL issues)"
            )

        if not action_errors:
            logger.info("No actionable discrepancies to repair")
            return original_domain

        # Prioritize: repair actions with the most discrepancies first.
        # Cap matters because each repair is a separate LLM call; under a
        # 2-iteration budget (as set by the user's constraint), only
        # ~20 actions were ever getting touched out of 1000+. Raise to
        # 100/iter — still bounded LLM cost, but enough breadth to make
        # repair-driven EW lift visible within 2 iterations.
        max_repairs_per_iter = 100
        if len(action_errors) > max_repairs_per_iter:
            sorted_actions = sorted(
                action_errors.items(), key=lambda x: -len(x[1])
            )
            action_errors = dict(sorted_actions[:max_repairs_per_iter])
            logger.info(
                f"Capping repairs to top {max_repairs_per_iter} most "
                f"frequently failing actions"
            )

        # Extract all action blocks from current domain
        action_blocks = self._extract_action_blocks(original_domain)

        logger.info(
            f"Targeted repair: {len(action_errors)} broken actions "
            f"out of {len(action_blocks)} total"
        )

        # Repair each broken action individually
        updated_domain = original_domain
        repaired_count = 0
        failed_count = 0

        for action_name, errors in action_errors.items():
            if action_name not in action_blocks:
                logger.warning(
                    f"  Action '{action_name}' not found in domain, skipping"
                )
                continue

            action_pddl = action_blocks[action_name]
            logger.info(
                f"  Repairing '{action_name}' "
                f"({len(errors)} discrepancies, "
                f"{len(action_pddl)} chars)..."
            )

            repaired = self._repair_single_action_with_llm(
                action_name, action_pddl, errors
            )

            if repaired:
                updated_domain = self._replace_action_block(
                    updated_domain, action_name, repaired
                )
                repaired_count += 1
            else:
                failed_count += 1
                logger.warning(
                    f"  Could not repair '{action_name}', keeping original"
                )

        logger.info(
            f"Targeted repair complete: "
            f"{repaired_count} fixed, {failed_count} kept original"
        )

        # Validate the updated domain
        if not self._validate_domain(updated_domain, original_domain):
            logger.warning(
                "Updated domain failed validation, reverting to original"
            )
            return original_domain

        # Final sanitizer pass on the whole domain
        updated_domain = self.sanitizer.repair(updated_domain)
        repairs = self.sanitizer.get_repairs_log()
        if repairs:
            logger.info(
                f"Sanitizer applied {len(repairs)} fixes: "
                f"{', '.join(repairs[:5])}"
            )

        # Final action count check
        updated_count = self._count_actions(updated_domain)
        logger.info(
            f"Domain actions: {original_action_count} -> {updated_count} "
            f"({len(updated_domain)} chars)"
        )

        return updated_domain

    def _extract_pddl(self, text: str) -> Optional[str]:
        """Extract PDDL domain from LLM response."""
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

    # =========================================================================
    # Main Refinement Loop
    # =========================================================================

    def refine(self, max_iterations: Optional[int] = None) -> tuple[str, float]:
        """
        Main refinement loop.

        Iteratively improves the domain until EW score meets target.
        Includes:
        - Rollback to best domain when score drops
        - Stuck loop detection (0 discrepancies + score < target)
        - Domain validation after each LLM update

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
        previous_score = -1.0
        stuck_count = 0
        MAX_STUCK_ITERATIONS = 3

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
                stuck_count = 0
                logger.info(f"New best score: {best_score:.3f}")

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

            # ---- Stuck loop detection ----
            # Case 1: 0 discrepancies but score < target means the domain
            # is broken (0 actions -> 0 walks -> 0 discrepancies)
            if not ew_score.discrepancies and ew_score.total_steps == 0:
                logger.warning(
                    "STUCK: 0 steps executed, 0 discrepancies. "
                    "Domain likely broken (no parseable actions). "
                    "Reverting to best known domain."
                )
                self.domain_pddl = best_domain
                self.planner.load_domain_string(self.domain_pddl, self.problem_pddl)
                stuck_count += 1

                if stuck_count >= MAX_STUCK_ITERATIONS:
                    logger.warning(
                        f"Stuck for {stuck_count} iterations, stopping early. "
                        f"Best score: {best_score:.3f}"
                    )
                    self.iteration_history.append(RefinementIteration(
                        iteration=iteration,
                        timestamp=datetime.now(),
                        domain_before=self.domain_pddl,
                        ew_score=ew_score,
                        domain_after=best_domain,
                        changes_made=["Stuck loop - reverted to best domain"],
                        evaluation_time=eval_time,
                        refinement_time=0.0,
                    ))
                    return best_domain, best_score

                self.iteration_history.append(RefinementIteration(
                    iteration=iteration,
                    timestamp=datetime.now(),
                    domain_before=self.domain_pddl,
                    ew_score=ew_score,
                    domain_after=best_domain,
                    changes_made=["Reverted to best domain (stuck loop)"],
                    evaluation_time=eval_time,
                    refinement_time=0.0,
                ))
                continue

            # Case 2: Score dropped significantly from best score
            # Use 25% threshold from best (not previous) to catch gradual decay
            if best_score > 0 and ew_score.score < best_score * 0.75:
                logger.warning(
                    f"Score dropped significantly from best: {best_score:.3f} -> "
                    f"{ew_score.score:.3f} (>{25}% drop). Reverting to best domain."
                )
                self.domain_pddl = best_domain
                self.planner.load_domain_string(self.domain_pddl, self.problem_pddl)
                stuck_count += 1

                self.iteration_history.append(RefinementIteration(
                    iteration=iteration,
                    timestamp=datetime.now(),
                    domain_before=self.domain_pddl,
                    ew_score=ew_score,
                    domain_after=best_domain,
                    changes_made=["Reverted to best domain (score dropped)"],
                    evaluation_time=eval_time,
                    refinement_time=0.0,
                ))
                previous_score = best_score
                continue

            previous_score = ew_score.score

            # ---- Refine domain based on discrepancies ----
            refine_start = time.time()
            domain_before = self.domain_pddl

            if ew_score.discrepancies:
                candidate = self.llm_update_domain(ew_score.discrepancies)

                # Validate the candidate domain
                if self._validate_domain(candidate, domain_before):
                    self.domain_pddl = candidate
                    self.planner.load_domain_string(
                        self.domain_pddl, self.problem_pddl
                    )
                else:
                    logger.warning(
                        "LLM candidate failed validation, keeping current domain"
                    )

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
