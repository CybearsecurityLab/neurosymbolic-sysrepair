"""
phase2/merger.py

Merger agent that synthesizes partial domains into a unified PDDL domain.
Updated to use shared type hierarchy and predicate definitions.
"""

import tempfile
import time
import re
import logging
from pathlib import Path
from typing import Optional
import sys
import os
from phase2.repair import PDDLValidator
from common.pddl_rules import PDDL_SYNTAX_GUIDE

# Add parent directory to path for common imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.type_hierarchy import (
    CORE_TYPE_HIERARCHY,
    VALID_TYPES,
    normalize_type,
    generate_types_pddl,
)
from common.predicates import (
    get_canonical_predicate_name,
)
from common.pddl_sanitizer import PDDLSanitizer, PDDL_RESERVED_KEYWORDS

from phase2.models import PartialPDDLDomain, PDDLType, PDDLPredicate, PDDLAction
from phase2.llm import LLMInterface

logger = logging.getLogger("Phase2.Merger")


class MergerAgent:
    """
    Merger agent that synthesizes partial domains into a unified PDDL domain.
    Implements the Reduce phase with conflict resolution.

    Updated to use shared common modules for:
    - Type hierarchy (common.type_hierarchy)
    - Predicate definitions (common.predicates)
    - Sanitization (common.pddl_sanitizer)
    - Strict validation to reject invalid LLM-generated constructs
    """

    # Invalid patterns that should cause action rejection
    INVALID_PATTERNS = [
        r"\(assert\s",  # (assert ...) - not valid PDDL
        r"\(equal\s",  # (equal ?x ?y) - not valid PDDL
        r"\(create_process\s",  # functions not allowed
        r"\(strcat\s",  # string operations not allowed
        r"\(concat\s",  # string operations not allowed
        r"\(member\s",  # list operations not allowed
        r"\(implies\s",  # use (when) instead
        r"\(imply\s",  # use (when) instead
        r"'[^']*'",  # single-quoted string literals
        r'"[^"]*"',  # double-quoted string literals
        r"\(\s*\)",  # empty parentheses
        r"\)\s*\(\s*\(",  # malformed )((
        r"\)\(\(",  # malformed )((
        r"\(exists\s",  # quantifiers not allowed in STRIPS
        r"\(forall\s",  # quantifiers not allowed in STRIPS
    ]

    # Invalid types that should be normalized or rejected
    INVALID_TYPES = frozenset(
        [
            "string",
            "boolean",
            "integer",
            "list",
            "command",
            "cmd",
            "_user",
            "_group",
            "_file",
            "_service",
            "_package",
        ]
    )

    def __init__(self, llm: Optional[LLMInterface] = None):
        self.llm = llm
        self.sanitizer = PDDLSanitizer()
        self.validator = PDDLValidator()
        self.unified_types: dict[str, PDDLType] = {}
        self.unified_predicates: dict[str, PDDLPredicate] = {}
        self.unified_actions: list[PDDLAction] = []
        self.merge_log: list[str] = []
        self.all_repairs: list[str] = []
        self.rejected_actions: list[tuple[str, str]] = []  # (name, reason)
        self._pddl_available = self._check_pddl_library()

    def _check_pddl_library(self) -> bool:
        """Check if the pddl library is available."""
        try:
            from pddl import parse_domain

            return True
        except ImportError:
            logger.warning("pddl library not available. Install with: pip install pddl")
            return False

    def merge(self, partial_domains: list[PartialPDDLDomain]) -> str:
        """
        Execute the Reduce phase: merge partial domains.
        Returns the unified PDDL domain as a string.
        """
        logger.info("=" * 60)
        logger.info("REDUCE PHASE: Merging Partial Domains")
        logger.info("=" * 60)

        start_time = time.time()

        # Filter out failed workers
        valid_domains = [d for d in partial_domains if not d.error]
        logger.info(f"Merging {len(valid_domains)} valid partial domains")

        # Step 0: Repair each partial domain's raw PDDL
        logger.info("\n[0/5] Repairing LLM-generated PDDL syntax...")
        for domain in valid_domains:
            if domain.raw_pddl:
                repaired = self.sanitizer.repair(domain.raw_pddl)
                repairs = self.sanitizer.get_repairs_log()
                if repairs:
                    logger.info(f"  {domain.worker_name}: {len(repairs)} repairs")
                    self.all_repairs.extend(
                        [f"{domain.worker_name}: {r}" for r in repairs]
                    )
                domain.raw_pddl = repaired
                self._reparse_domain(domain)

        logger.info(f"  → Total repairs: {len(self.all_repairs)}")

        # Step 1: Initialize with core type hierarchy
        logger.info("\n[1/5] Unifying type definitions...")
        self._initialize_core_types()
        self._unify_types(valid_domains)
        logger.info(f"  → {len(self.unified_types)} unified types")

        # Step 2: Predicate Unification
        logger.info("\n[2/5] Unifying predicates...")
        self._unify_predicates(valid_domains)
        self._extract_predicates_from_actions(valid_domains)
        logger.info(f"  → {len(self.unified_predicates)} unified predicates")

        # Step 3: Action Consolidation
        logger.info("\n[3/5] Consolidating actions...")
        self._consolidate_actions(valid_domains)
        logger.info(f"  → {len(self.unified_actions)} unified actions")

        # --- NEW STEP: Targeted Repair Loop ---
        logger.info("\n[3.5/5] Targeted Neurosymbolic Repair...")
        pre_repair_actions = list(self.unified_actions)  # Backup before repair
        pre_repair_count = len(pre_repair_actions)

        if self._pddl_available and self.llm:
            # This replaces the massive whole-file repair loop
            repaired = self._validate_and_repair_actions()
            logger.info(
                f"  Repair result: {len(repaired)} actions "
                f"(was {pre_repair_count} before repair)"
            )

            # Guard: if repair returned empty/drastically fewer, fall back
            if len(repaired) == 0 and pre_repair_count > 0:
                logger.error(
                    f"  CRITICAL: Repair returned 0 actions but had "
                    f"{pre_repair_count} before repair. Falling back to "
                    f"pre-repair actions."
                )
                self.unified_actions = pre_repair_actions
            elif len(repaired) < pre_repair_count * 0.5:
                logger.warning(
                    f"  WARNING: Repair lost >50% of actions "
                    f"({len(repaired)}/{pre_repair_count}). "
                    f"Falling back to pre-repair actions."
                )
                self.unified_actions = pre_repair_actions
            else:
                self.unified_actions = repaired
        elif not self._pddl_available:
            logger.warning("pddl library missing - cannot perform targeted repair.")
        # --------------------------------------

        # Step 5: Construct Final Domain
        logger.info(
            f"\n[5/5] Constructing unified domain "
            f"({len(self.unified_actions)} actions)..."
        )
        domain_pddl = self._construct_domain()

        # Final sanity check on the constructed domain
        action_count_in_pddl = domain_pddl.count("(:action ")
        if action_count_in_pddl == 0 and len(self.unified_actions) > 0:
            logger.error(
                f"  CRITICAL: _construct_domain produced 0 actions but "
                f"unified_actions has {len(self.unified_actions)}. "
                f"Rebuilding with pre-repair actions..."
            )
            self.unified_actions = pre_repair_actions
            domain_pddl = self._construct_domain()
            action_count_in_pddl = domain_pddl.count("(:action ")
            logger.info(
                f"  Rebuild produced {action_count_in_pddl} actions"
            )

        logger.info(
            f"  Final domain: {action_count_in_pddl} actions, "
            f"{len(domain_pddl.splitlines())} lines"
        )

        return domain_pddl

    def _validate_and_repair_actions(self) -> list[PDDLAction]:
        """
        Iterates through actions one by one.
        If valid -> Keep.
        If invalid -> Ask LLM to fix ONLY that action -> Retest -> Keep/Prune.
        Returns the original unified_actions list on catastrophic failure.
        """
        valid_actions = []
        skipped = 0

        # 1. Build the "Base Domain" (Types + Predicates) for testing
        try:
            base_domain_str = self._build_base_domain_template()
        except Exception as e:
            logger.error(
                f"  Failed to build base domain template: {e}. "
                f"Skipping validation, returning all actions as-is."
            )
            return list(self.unified_actions)

        total = len(self.unified_actions)
        logger.info(f"  Validating {total} actions...")

        for i, action in enumerate(self.unified_actions):
            try:
                # 2. Test the action
                is_valid, error_msg = self._test_single_action(
                    action, base_domain_str
                )

                if is_valid:
                    valid_actions.append(action)
                    continue

                # 3. Validation Failed - Trigger Targeted Repair
                if self.llm:
                    logger.info(
                        f"  [{i + 1}/{total}] Action '{action.name}' "
                        f"failed: {error_msg}"
                    )
                    logger.info(f"    Attempting targeted LLM repair...")

                    repaired_action = self._repair_single_action_with_llm(
                        action, error_msg
                    )

                    # 4. Retest the repaired action
                    is_valid_now, new_error = self._test_single_action(
                        repaired_action, base_domain_str
                    )

                    if is_valid_now:
                        logger.info(
                            f"    Fixed! Action '{action.name}' salvaged."
                        )
                        valid_actions.append(repaired_action)
                    else:
                        logger.warning(
                            f"    Repair failed for '{action.name}': "
                            f"{new_error}. Pruning."
                        )
                        self.rejected_actions.append(
                            (action.name, f"Repair failed: {new_error}")
                        )
                else:
                    # No LLM available - just skip invalid actions
                    self.rejected_actions.append(
                        (action.name, f"Invalid (no LLM): {error_msg}")
                    )

            except (MemoryError, OSError) as e:
                # Critical resource error - stop validation, return what we have
                logger.error(
                    f"  RESOURCE ERROR at action {i + 1}/{total} "
                    f"('{action.name}'): {e}. "
                    f"Stopping validation early with {len(valid_actions)} "
                    f"valid actions collected so far."
                )
                # Include remaining untested actions rather than losing them
                remaining = self.unified_actions[i:]
                logger.info(
                    f"  Preserving {len(remaining)} untested actions."
                )
                valid_actions.extend(remaining)
                break

            except Exception as e:
                # Non-critical error on single action - skip and continue
                skipped += 1
                logger.warning(
                    f"  [{i + 1}/{total}] Unexpected error testing "
                    f"'{action.name}': {e}. Keeping action as-is."
                )
                valid_actions.append(action)  # Keep it rather than lose it

        if skipped > 0:
            logger.info(f"  {skipped} actions had validation errors (kept as-is)")

        logger.info(
            f"Targeted repair complete. Final count: {len(valid_actions)}/{total}"
        )
        return valid_actions

    def _test_single_action(
        self, action: PDDLAction, base_domain: str
    ) -> tuple[bool, str]:
        """Injects a single action into the base domain and parses it."""
        tmp_path = None
        try:
            # Format action as PDDL string
            action_str = self._format_action_pddl(action)

            # Inject into template (insert before last closing paren)
            test_domain = base_domain.rpartition(")")[0] + "\n" + action_str + "\n)"

            # Parse with library - use delete=False for cross-platform safety
            from pddl import parse_domain

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".pddl", delete=False
            ) as tmp:
                tmp_path = tmp.name
                tmp.write(test_domain)
                tmp.flush()

            # Parse after file handle is closed (safer on all platforms)
            parse_domain(tmp_path)

            return True, ""
        except Exception as e:
            # Clean up error message (usually first line is enough)
            return False, str(e).split("\n")[0]
        finally:
            # Always clean up temp file
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    def _repair_single_action_with_llm(
        self, action: PDDLAction, error: str
    ) -> PDDLAction:
        """Sends just ONE action and the specific error to the LLM."""

        action_pddl = self._format_action_pddl(action)

        # Highly specific prompt
        prompt = (
            f"You are a PDDL repair engine. I have a single action that is invalid.\n"
            f"ERROR: {error}\n\n"
            f"INVALID ACTION:\n{action_pddl}\n\n"
            f"=== OFFICIAL SYNTAX RULES ===\n"
            f"{PDDL_SYNTAX_GUIDE}\n"
            f"=============================\n\n"
            f"INSTRUCTIONS:\n"
            f"1. Fix the specific error listed above.\n"
            f"2. Ensure all variables in preconditions/effects are declared in :parameters.\n"
            f"3. Do not use reserved keywords (like 'exists', 'forall', 'call') as names.\n"
            f"4. Do not change the action name.\n\n"
            f"Return ONLY the fixed action PDDL code. No markdown, no comments."
        )

        try:
            # Generate fix
            response = self.llm.generate(
                prompt, temperature=0.0
            )  # Zero temp for determinism
            cleaned_response = self._strip_markdown(response)

            # Parse the text back into a PDDLAction object
            # We can reuse the worker's parsing logic or a simple regex here
            parsed = self._parse_action_from_match(
                action.name, cleaned_response, "repair_agent"
            )

            if parsed:
                # Keep metadata
                parsed.source_utility = action.source_utility
                return parsed

        except Exception as e:
            logger.error(f"LLM call failed: {e}")

        return action  # Return original if repair crashes

    def _build_base_domain_template(self) -> str:
        """Creates the 'Skeleton' domain with all types and predicates."""
        lines = [
            "(define (domain sysadmin-temp)",
            "  (:requirements :strips :typing :negative-preconditions)",
            "  ;; Types",
            generate_types_pddl(),
            "  ;; Predicates",
            "  (:predicates",
        ]

        for pname, pred in sorted(self.unified_predicates.items()):
            if pred.parameters:
                params = " ".join(
                    f"?{p[0]} - {normalize_type(p[1])}" for p in pred.parameters
                )
                lines.append(f"    ({pname} {params})")
            else:
                lines.append(f"    ({pname})")

        # Add critical standard predicates manually to ensure validation passes
        if "network_available" not in self.unified_predicates:
            lines.append("    (network_available)")
        if "can_escalate" not in self.unified_predicates:
            lines.append("    (can_escalate ?u - user)")

        lines.append("  )")
        lines.append("")  # Space for action
        lines.append(")")
        return "\n".join(lines)

    def _format_action_pddl(self, action: PDDLAction) -> str:
        """Helper to convert object back to string."""
        lines = [f"  (:action {action.name}"]
        params = " ".join(
            f"?{p[0]} - {normalize_type(p[1])}" for p in action.parameters
        )
        lines.append(f"    :parameters ({params})")

        lines.append("    :precondition (and")
        for pre in action.preconditions:
            lines.append(f"      {pre}")
        lines.append("    )")

        lines.append("    :effect (and")
        for eff in action.effects:
            lines.append(f"      {eff}")
        lines.append("    )")
        lines.append("  )")
        return "\n".join(lines)

    def _semantic_repair_loop(self, domain_pddl: str) -> str:
        """
        Iteratively validate and repair the domain using the LLM.
        """
        MAX_ATTEMPTS = 3

        for attempt in range(MAX_ATTEMPTS):
            # 1. Validate
            is_valid, errors = self.validator.validate_domain(domain_pddl)

            if is_valid:
                logger.info(f"  ✓ Domain validation passed (Attempt {attempt + 1})")
                return domain_pddl

            logger.warning(
                f"  ⚠ Validation failed (Attempt {attempt + 1}): {len(errors)} errors"
            )
            for e in errors[:3]:  # Log first few errors
                logger.warning(f"    - {e}")

            # 2. Re-prompt LLM with errors
            logger.info("    → Triggering LLM repair...")
            domain_pddl = self._llm_repair(domain_pddl, errors)

        # Final check
        is_valid, final_errors = self.validator.validate_domain(domain_pddl)
        if not is_valid:
            logger.error(f"  ✗ Failed to repair domain after {MAX_ATTEMPTS} attempts.")

        return domain_pddl

    def _llm_repair(self, pddl: str, errors: list[str]) -> str:
        """Send PDDL + Errors to LLM for correction."""

        # Summarize errors to fit context
        error_report = "\n".join(f"{i + 1}. {e}" for i, e in enumerate(errors[:15]))
        if len(errors) > 15:
            error_report += f"\n... and {len(errors) - 15} more errors."

        reserved_kw_list = ", ".join(sorted(list(PDDL_RESERVED_KEYWORDS)))

        prompt = (
            "Fix the PDDL domain below. It has validation errors that must be corrected.\n\n"
            "CRITICAL RULES:\n"
            f"- NEVER use these as parameter names: {reserved_kw_list}, ...\n"
            "- If you see ?when, ?object, ?end, ?start, ?all as parameters, RENAME them\n"
            "- Example: ?when -> ?when_time, ?object -> ?target_obj, ?end -> ?end_point\n\n"
            "VALIDATION ERRORS:\n"
            f"{error_report}\n\n"
            "PDDL TO FIX:\n"
            f"{pddl}\n\n"
            "Return ONLY the corrected PDDL code. No explanations, no markdown, no additional text.\n"
            "Start your response with (define (domain sysadmin)"
        )

        try:
            # Use low temperature for precision
            repaired = self.llm.generate(prompt, temperature=0.1)
            return self._strip_markdown(repaired)
        except Exception as e:
            logger.error(f"LLM repair failed: {e}")
            return pddl

    def _strip_markdown(self, text: str) -> str:
        """Helper to clean LLM output."""
        # Remove markdown code fences
        text = re.sub(r"^```(?:pddl)?\s*\n?", "", text, flags=re.MULTILINE)
        text = re.sub(r"\n?```\s*$", "", text, flags=re.MULTILINE)

        # Remove common LLM preambles and section headers
        text = re.sub(
            r"^.*?Here is.*?:\s*\n", "", text, flags=re.IGNORECASE | re.DOTALL
        )
        text = re.sub(
            r"^.*?corrected.*?:\s*\n", "", text, flags=re.IGNORECASE | re.DOTALL
        )
        text = re.sub(r"^===.*?===\s*\n", "", text, flags=re.MULTILINE)

        # Find the actual PDDL domain definition
        # PDDL domains start with "(define (domain"
        match = re.search(r"\(define\s+\(domain.*", text, re.DOTALL)
        if match:
            text = match.group(0)
        else:
            # Try to find any PDDL-like content starting with types, predicates, or actions
            pddl_match = re.search(
                r"(?:\(:types|\(:predicates|\(:action).*", text, re.DOTALL
            )
            if pddl_match:
                # Wrap in domain definition if missing
                text = f"(define (domain sysadmin)\n  (:requirements :strips :typing :negative-preconditions)\n  {pddl_match.group(0)}\n)"

        return text.strip()

    def _initialize_core_types(self):
        """Initialize with the shared core type hierarchy."""
        for type_name, parent in CORE_TYPE_HIERARCHY.items():
            self.unified_types[type_name] = PDDLType(
                name=type_name, parent=parent, source="core_hierarchy"
            )

    def _unify_types(self, domains: list[PartialPDDLDomain]):
        """Unify type definitions with conflict resolution."""
        for domain in domains:
            for ptype in domain.types:
                # Normalize the type name
                normalized_name = normalize_type(ptype.name)

                if normalized_name not in self.unified_types:
                    # New type - check if parent exists
                    if ptype.parent:
                        normalized_parent = normalize_type(ptype.parent)
                        if normalized_parent not in self.unified_types:
                            self.merge_log.append(
                                f"Type '{ptype.name}' parent '{ptype.parent}' not found, "
                                f"defaulting to 'object'"
                            )
                            normalized_parent = "object"
                        ptype.parent = normalized_parent

                    self.unified_types[normalized_name] = PDDLType(
                        name=normalized_name,
                        parent=ptype.parent or "object",
                        source=domain.worker_name,
                    )
                else:
                    # Type exists - check for conflicts
                    existing = self.unified_types[normalized_name]
                    if ptype.parent and ptype.parent != existing.parent:
                        if existing.source == "core_hierarchy":
                            self.merge_log.append(
                                f"Type '{ptype.name}' parent conflict: "
                                f"keeping core '{existing.parent}' over '{ptype.parent}'"
                            )

    def _unify_predicates(self, domains: list[PartialPDDLDomain]):
        """Unify predicates, detecting semantic duplicates using shared aliases."""
        for domain in domains:
            for pred in domain.predicates:
                # Use shared alias resolution
                canonical_name = get_canonical_predicate_name(pred.name)

                if canonical_name != pred.name:
                    self.merge_log.append(
                        f"Unified predicate alias '{pred.name}' → '{canonical_name}'"
                    )
                    pred.name = canonical_name

                if canonical_name not in self.unified_predicates:
                    self.unified_predicates[canonical_name] = pred
                else:
                    # Check parameter compatibility
                    existing = self.unified_predicates[canonical_name]
                    if len(pred.parameters) != len(existing.parameters):
                        self.merge_log.append(
                            f"Predicate '{canonical_name}' arity mismatch: "
                            f"{len(existing.parameters)} vs {len(pred.parameters)}"
                        )

    def _extract_predicates_from_actions(self, domains: list[PartialPDDLDomain]):
        """Extract predicates that are used in actions but not declared."""
        for domain in domains:
            for action in domain.actions:
                for cond in action.preconditions + action.effects:
                    self._extract_predicate_from_condition(cond, domain.worker_name)

    def _extract_predicate_from_condition(self, condition: str, source: str):
        """Extract a predicate definition from a condition string."""
        cond = condition.strip()
        if cond.startswith("(not"):
            cond = cond[4:].strip().rstrip(")")

        match = re.match(r"\((\w+)((?:\s+\?\w+(?:\s*-\s*\w+)?)*)\)", cond)
        if match:
            pred_name = match.group(1)

            if pred_name in PDDL_RESERVED_KEYWORDS:
                return

            # Use canonical name
            canonical_name = get_canonical_predicate_name(pred_name)

            if canonical_name in self.unified_predicates:
                return

            params_str = match.group(2).strip()
            params = []

            param_pattern = r"\?(\w+)(?:\s*-\s*(\w+))?"
            for pm in re.finditer(param_pattern, params_str):
                var_name = pm.group(1)
                var_type = pm.group(2) if pm.group(2) else "object"
                # Normalize type
                var_type = normalize_type(var_type)
                params.append((var_name, var_type))

            self.unified_predicates[canonical_name] = PDDLPredicate(
                name=canonical_name, parameters=params, source=source
            )
            self.merge_log.append(
                f"Extracted predicate '{canonical_name}' from action body"
            )

    def _validate_action_predicates(self):
        """Ensure all predicates used in actions are declared."""
        for action in self.unified_actions:
            for cond in action.preconditions + action.effects:
                cond_clean = cond.strip()
                if cond_clean.startswith("(not"):
                    cond_clean = cond_clean[4:].strip().rstrip(")")

                match = re.match(r"\((\w+)", cond_clean)
                if match:
                    pred_name = match.group(1)
                    if pred_name not in PDDL_RESERVED_KEYWORDS:
                        canonical = get_canonical_predicate_name(pred_name)
                        if canonical not in self.unified_predicates:
                            self._extract_predicate_from_condition(
                                cond_clean, "validator"
                            )

    def _consolidate_actions(self, domains: list[PartialPDDLDomain]):
        """Consolidate actions, detecting and merging duplicates with strict validation."""
        action_map: dict[str, list[PDDLAction]] = {}

        for domain in domains:
            for action in domain.actions:
                # Validate action before adding to map
                is_valid, reason = self._validate_action(action)
                if not is_valid:
                    self.rejected_actions.append((action.name, reason))
                    self.merge_log.append(f"Rejected action '{action.name}': {reason}")
                    continue

                # Sanitize the action
                sanitized_action = self._sanitize_action(action)
                if sanitized_action is None:
                    self.rejected_actions.append((action.name, "Failed sanitization"))
                    continue

                if sanitized_action.name not in action_map:
                    action_map[sanitized_action.name] = []
                action_map[sanitized_action.name].append(sanitized_action)

        logger.info(f"  Rejected {len(self.rejected_actions)} invalid actions")

        for name, actions in action_map.items():
            if len(actions) == 1:
                self.unified_actions.append(actions[0])
            else:
                # Prefer Phase 1 actions (marked as phase1_reuse)
                phase1_actions = [
                    a
                    for a in actions
                    if getattr(a, "source_worker", "") == "phase1_reuse"
                ]
                if phase1_actions:
                    self.unified_actions.append(phase1_actions[0])
                    self.merge_log.append(
                        f"Action '{name}': preferring Phase 1 version"
                    )
                else:
                    merged = self._merge_actions(actions)
                    self.unified_actions.append(merged)
                    self.merge_log.append(
                        f"Merged {len(actions)} definitions of action '{name}'"
                    )

    def _validate_action(self, action: PDDLAction) -> tuple[bool, str]:
        """
        Validate an action for PDDL correctness.
        Returns (is_valid, reason) tuple.
        """
        if not action or not action.name:
            return False, "Missing action name"

        # Check for invalid patterns in preconditions
        for pre in action.preconditions:
            for pattern in self.INVALID_PATTERNS:
                if re.search(pattern, pre, re.IGNORECASE):
                    return False, f"Invalid pattern in precondition: {pattern}"

        # Check for invalid patterns in effects
        for eff in action.effects:
            for pattern in self.INVALID_PATTERNS:
                if re.search(pattern, eff, re.IGNORECASE):
                    return False, f"Invalid pattern in effect: {pattern}"

        # Check for invalid types in parameters
        for param_name, param_type in action.parameters:
            if param_type in self.INVALID_TYPES:
                # This will be normalized, but log it
                self.merge_log.append(
                    f"Action '{action.name}': normalizing invalid type '{param_type}'"
                )

        # Check that effects are not empty (action must do something)
        if not action.effects:
            return False, "Action has no effects"

        # Check for balanced parentheses in all conditions
        for cond in action.preconditions + action.effects:
            if cond.count("(") != cond.count(")"):
                return False, f"Unbalanced parentheses in: {cond[:50]}"

        # Check that all variables in preconditions/effects are declared
        declared_vars = {f"?{p[0]}" for p in action.parameters}
        for cond in action.preconditions + action.effects:
            var_pattern = r"\?(\w+)"
            found_vars = {f"?{m.group(1)}" for m in re.finditer(var_pattern, cond)}
            undeclared = found_vars - declared_vars
            if undeclared:
                return False, f"Undeclared variables: {undeclared}"

        return True, ""

    def _sanitize_action(self, action: PDDLAction) -> Optional[PDDLAction]:
        """
        Sanitize an action by normalizing types and fixing common issues.
        Returns None if the action cannot be fixed.
        """
        try:
            from common.predicates import sanitize_pddl_name

            # Sanitize action name
            action.name = sanitize_pddl_name(action.name)

            # Normalize parameter types and names
            normalized_params = []
            for param_name, param_type in action.parameters:
                clean_name = re.sub(r"[^a-zA-Z0-9_]", "", param_name)
                normalized_type = normalize_type(param_type)
                normalized_params.append((clean_name, normalized_type))

            # Filter out invalid conditions from preconditions
            valid_preconds = []
            for pre in action.preconditions:
                sanitized = self._sanitize_condition(pre)
                if sanitized:
                    valid_preconds.append(sanitized)

            # Filter out invalid conditions from effects
            valid_effects = []
            for eff in action.effects:
                sanitized = self._sanitize_condition(eff)
                if sanitized:
                    valid_effects.append(sanitized)

            if not valid_effects:
                return None

            return PDDLAction(
                name=action.name,
                parameters=normalized_params,
                preconditions=valid_preconds,
                effects=valid_effects,
                command_template=action.command_template,
                requires_root=action.requires_root,
                source_utility=action.source_utility,
                source_worker=getattr(action, "source_worker", "sanitized"),
            )
        except Exception as e:
            logger.warning(f"Failed to sanitize action '{action.name}': {e}")
            return None

    def _sanitize_condition(self, condition: str) -> Optional[str]:
        """
        Sanitize a single condition/effect.
        Returns None if the condition is invalid and cannot be fixed.
        """
        if not condition or not condition.strip():
            return None

        cond = condition.strip()

        # Check for invalid patterns - reject entirely
        for pattern in self.INVALID_PATTERNS:
            if re.search(pattern, cond, re.IGNORECASE):
                return None

        # Check balanced parentheses
        if cond.count("(") != cond.count(")"):
            return None

        # Must start with '('
        if not cond.startswith("("):
            return None

        # Strip type annotations from conditions/effects.
        # LLMs sometimes write "(pred ?x - type ?y - type)" in conditions
        # but PDDL only allows typed params in :parameters, not in
        # preconditions/effects. Remove " - type_name" after variables.
        cond = re.sub(r"(\?\w+)\s+-\s+\w+", r"\1", cond)

        # Sanitize predicate names inside conditions:
        # Replace hyphens with underscores in identifiers.
        def _fix_pred_name(m):
            return "(" + m.group(1).replace("-", "_")
        cond = re.sub(r"\(([a-zA-Z][a-zA-Z0-9_-]*)", _fix_pred_name, cond)

        # Strip question marks from any remaining identifiers (not ?vars)
        # e.g., "collapsed?" -> "collapsed"
        cond = re.sub(r"([a-zA-Z0-9_])\?(?!\w)", r"\1", cond)

        return cond

    def _merge_actions(self, actions: list[PDDLAction]) -> PDDLAction:
        """Merge multiple action definitions into one."""
        best = max(actions, key=lambda a: len(a.preconditions) + len(a.effects))

        all_preconds = set()
        for a in actions:
            all_preconds.update(a.preconditions)

        all_effects = set()
        for a in actions:
            all_effects.update(a.effects)

        return PDDLAction(
            name=best.name,
            parameters=best.parameters,
            preconditions=list(all_preconds),
            effects=list(all_effects),
            command_template=best.command_template,
            requires_root=any(a.requires_root for a in actions),
            source_utility=best.source_utility,
            source_worker="merged",
        )

    def _construct_domain(self) -> str:
        """Construct the unified PDDL domain string."""
        lines = [
            ";; =============================================================================",
            ";; SYSADMIN PDDL DOMAIN - Ubuntu 25.10 'Questing Quokka'",
            ";; Auto-generated by Phase 2: Parallel Synthesis (Map-Reduce)",
            ";; =============================================================================",
            "",
            "(define (domain sysadmin)",
            "",
            "  (:requirements :strips :typing :negative-preconditions)",
            "",
        ]

        # Types section - use shared type hierarchy generator
        lines.append("  ;; Type Hierarchy (from shared common.type_hierarchy)")
        lines.append(generate_types_pddl())
        lines.append("")

        # Predicates section
        lines.append("  ;; Predicates")
        lines.append("  (:predicates")

        for pname, pred in sorted(self.unified_predicates.items()):
            if pred.parameters:
                params = " ".join(
                    f"?{p[0]} - {normalize_type(p[1])}" for p in pred.parameters
                )
                lines.append(f"    ({pname} {params})")
            else:
                lines.append(f"    ({pname})")

        # Add standard predicates if missing
        standard_preds = ["network_available", "can_escalate"]
        for sp in standard_preds:
            if sp not in self.unified_predicates:
                if sp == "network_available":
                    lines.append(f"    ({sp})")
                elif sp == "can_escalate":
                    lines.append(f"    ({sp} ?u - user)")

        lines.append("  )")
        lines.append("")

        # Actions section
        for action in sorted(self.unified_actions, key=lambda a: a.name):
            lines.append(f"  ;; Action: {action.name}")
            if action.source_utility:
                lines.append(f"  ;; Source: {action.source_utility}")
            if getattr(action, "source_worker", "") == "phase1_reuse":
                lines.append("  ;; Reused from Phase 1")

            lines.append(f"  (:action {action.name}")

            # Parameters - normalize types
            params = " ".join(
                f"?{p[0]} - {normalize_type(p[1])}" for p in action.parameters
            )
            lines.append(f"    :parameters ({params})")

            # Preconditions
            if action.preconditions:
                lines.append("    :precondition (and")
                for pre in action.preconditions:
                    lines.append(f"      {pre}")
                lines.append("    )")
            else:
                lines.append("    :precondition (and)")

            # Effects
            if action.effects:
                lines.append("    :effect (and")
                for eff in action.effects:
                    lines.append(f"      {eff}")
                lines.append("    )")
            else:
                lines.append("    :effect (and)")

            lines.append("  )")
            lines.append("")

        lines.append(")")

        return "\n".join(lines)

    def _reparse_domain(self, domain: PartialPDDLDomain):
        """Re-parse a domain after repairs."""
        raw = domain.raw_pddl

        domain.types = []
        domain.predicates = []
        domain.actions = []

        # Re-extract types
        types_match = re.search(r"\(:types\s*(.*?)\)", raw, re.DOTALL)
        if types_match:
            domain.types = self._parse_types_from_string(
                types_match.group(1), domain.worker_name
            )

        # Re-extract predicates
        pred_match = re.search(
            r"\(:predicates\s*(.*?)\)\s*(?:\(:action|$)", raw, re.DOTALL
        )
        if pred_match:
            domain.predicates = self._parse_predicates_from_string(
                pred_match.group(1), domain.worker_name
            )

        # Re-extract actions
        action_pattern = r"\(:action\s+(\w+)\s*(.*?)(?=\(:action|\Z)"
        for match in re.finditer(action_pattern, raw, re.DOTALL):
            action = self._parse_action_from_match(
                match.group(1), match.group(2), domain.worker_name
            )
            if action:
                domain.actions.append(action)

    def _parse_types_from_string(self, types_str: str, source: str) -> list[PDDLType]:
        """Parse PDDL type definitions from string."""
        types = []
        lines = types_str.strip().split("\n")
        for line in lines:
            line = line.strip()
            if not line or line.startswith(";"):
                continue

            if " - " in line:
                parts = line.split(" - ")
                parent = normalize_type(parts[-1].strip())
                children = parts[0].strip().split()
                for child in children:
                    child = child.strip()
                    if child and child in VALID_TYPES:
                        types.append(PDDLType(name=child, parent=parent, source=source))
        return types

    def _parse_predicates_from_string(
        self, pred_str: str, source: str
    ) -> list[PDDLPredicate]:
        """Parse PDDL predicate definitions from string."""
        predicates = []
        pattern = r"\((\w+)((?:\s+\?\w+\s*-\s*\w+)*)\)"

        for match in re.finditer(pattern, pred_str):
            name = match.group(1)
            params_str = match.group(2).strip()

            params = []
            param_pattern = r"\?(\w+)\s*-\s*(\w+)"
            for pm in re.finditer(param_pattern, params_str):
                params.append((pm.group(1), normalize_type(pm.group(2))))

            predicates.append(
                PDDLPredicate(name=name, parameters=params, source=source)
            )

        return predicates

    def _parse_action_from_match(
        self, name: str, body: str, source: str
    ) -> Optional[PDDLAction]:
        """Parse a single PDDL action."""
        try:
            params_match = re.search(r":parameters\s*\((.*?)\)", body, re.DOTALL)
            params = []
            if params_match:
                param_pattern = r"\?(\w+)\s*-\s*(\w+)"
                for pm in re.finditer(param_pattern, params_match.group(1)):
                    params.append((pm.group(1), normalize_type(pm.group(2))))

            pre_match = re.search(
                r":precondition\s*\(and(.*?)\)\s*:effect", body, re.DOTALL
            )
            preconditions = []
            if pre_match:
                preconditions = self._extract_conditions(pre_match.group(1))

            eff_match = re.search(r":effect\s*\(and(.*?)\)\s*\)?$", body, re.DOTALL)
            effects = []
            if eff_match:
                effects = self._extract_conditions(eff_match.group(1))

            return PDDLAction(
                name=name,
                parameters=params,
                preconditions=preconditions,
                effects=effects,
                source_worker=source,
            )
        except Exception as e:
            logger.warning(f"Failed to parse action {name}: {e}")
            return None

    def _extract_conditions(self, cond_str: str) -> list[str]:
        """Extract individual conditions from an (and ...) block."""
        conditions = []
        cond_str = re.sub(r"^\s*and\s*", "", cond_str.strip())

        depth = 0
        current = ""
        for char in cond_str:
            if char == "(":
                depth += 1
                current += char
            elif char == ")":
                depth -= 1
                current += char
                if depth == 0 and current.strip():
                    stripped = current.strip()
                    if stripped.startswith("(") and stripped.endswith(")"):
                        if not any(
                            x in stripped
                            for x in ["strcat", "concat", "create_process", '""']
                        ):
                            conditions.append(stripped)
                    current = ""
            elif depth > 0:
                current += char

        return conditions

    def _validate_pddl(self, pddl: str) -> tuple[bool, list[str]]:
        """Validate PDDL syntax."""
        errors = []

        if pddl.count("(") != pddl.count(")"):
            errors.append("Unbalanced parentheses")

        if "(define (domain" not in pddl:
            errors.append("Missing domain definition")

        if "(:types" not in pddl:
            errors.append("Missing types section")

        if "(:predicates" not in pddl:
            errors.append("Missing predicates section")

        if self._pddl_available and not errors:
            pddl_errors = self._validate_with_pddl_library(pddl)
            errors.extend(pddl_errors)

        return len(errors) == 0, errors

    def _validate_with_pddl_library(self, pddl: str) -> list[str]:
        """Validate using the pddl library parser."""
        errors = []
        temp_path = None

        try:
            from pddl import parse_domain

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".pddl", delete=False
            ) as f:
                f.write(pddl)
                temp_path = f.name

            try:
                parse_domain(temp_path)
            except Exception as parse_error:
                error_msg = str(parse_error)
                errors.append(f"PDDL Parse Error: {error_msg}")

        except ImportError:
            pass
        finally:
            if temp_path:
                try:
                    Path(temp_path).unlink()
                except Exception:
                    pass

        return errors

    def _repair_pddl(self, pddl: str, errors: list[str]) -> str:
        """Attempt to repair PDDL syntax errors."""
        open_count = pddl.count("(")
        close_count = pddl.count(")")

        if open_count > close_count:
            pddl += ")" * (open_count - close_count)
        elif close_count > open_count:
            while pddl.endswith(")") and pddl.count(")") > pddl.count("("):
                pddl = pddl[:-1]

        return pddl

    def get_merge_log(self) -> list[str]:
        """Return the merge operation log."""
        return self.merge_log

    def get_rejected_actions(self) -> list[tuple[str, str]]:
        """Return list of rejected actions with reasons: [(name, reason), ...]"""
        return self.rejected_actions

    def get_validation_summary(self) -> dict:
        """Return a summary of validation results."""
        return {
            "total_actions_processed": len(self.unified_actions)
            + len(self.rejected_actions),
            "valid_actions": len(self.unified_actions),
            "rejected_actions": len(self.rejected_actions),
            "rejection_reasons": dict(
                (name, reason) for name, reason in self.rejected_actions
            ),
            "total_repairs": len(self.all_repairs),
        }
