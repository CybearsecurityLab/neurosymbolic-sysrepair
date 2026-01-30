"""
phase2/worker.py

Worker agent for generating partial PDDL domains.
Updated to:
- Reuse Phase 1 actions instead of regenerating
- Use known predicates for vocabulary consistency
- Only generate new actions for gaps not covered by Phase 1
- Import PDDL syntax rules to enforce valid generation
"""

import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Optional

# Add parent directory to path for common imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import ActionSchema, PDDLType as PDDLTypeEnum
from common.pddl_rules import PDDL_SYNTAX_GUIDE
from common.type_hierarchy import VALID_TYPES, normalize_type

from phase2.models import PartialPDDLDomain, PDDLPredicate, PDDLAction, PDDLType
from phase2.llm import LLMInterface
from phase2.tools import DocumentationExtractor

logger = logging.getLogger("Phase2.Worker")


class WorkerAgent:
    """
    Worker agent for generating partial PDDL domains.
    Each worker specializes in a utility group.

    Updated to:
    - Start with Phase 1 actions for the utility group
    - Use known predicates in prompts for vocabulary consistency
    - Only ask LLM to fill gaps (actions not covered by Phase 1)
    """

    # Base system prompt - will be extended with PDDL_SYNTAX_GUIDE
    SYSTEM_PROMPT_BASE = """You are a PDDL 2.1 domain expert. Generate STRICTLY VALID PDDL syntax.

ABSOLUTE RULES - VIOLATIONS WILL CAUSE PARSER FAILURE:

1. VALID TYPES ONLY - Use ONLY these types:
   {valid_types_list}

   INVALID TYPES (do NOT use): string, boolean, integer, list, command, _user, _group

2. PREDICATES: Boolean predicates only, NO functions
   - USE EXISTING PREDICATES from the vocabulary provided when applicable
   - Only create new predicates if absolutely necessary
   - Predicate names must NOT be reserved keywords (and, or, not, exists, forall, when)

3. ACTIONS: Every parameter MUST be declared with a valid type
   - Do NOT duplicate actions that already exist
   - All variables in preconditions/effects MUST appear in :parameters

4. FORBIDDEN CONSTRUCTS - These will cause IMMEDIATE REJECTION:
   ❌ (assert ...) - NOT valid PDDL, do not use
   ❌ (equal ?x ?y) - NOT valid PDDL, do not use
   ❌ (create_process ...) - functions are NOT allowed
   ❌ (strcat ...) or (concat ...) - string operations NOT allowed
   ❌ 'string_literal' or "string_literal" - NO string literals
   ❌ (forall ...) or (exists ...) - NO quantifiers (STRIPS only)
   ❌ (implies ...) or (imply ...) - NO implications in effects

5. CORRECT EFFECT PATTERNS:
   ✅ Add fact: (predicate ?var)
   ✅ Delete fact: (not (predicate ?var))
   ✅ Conjunction: (and (pred1 ?x) (pred2 ?y))

6. VARIABLE SCOPE:
   Every ?variable in preconditions/effects MUST be declared in :parameters
   WRONG: :parameters (?p - package) :effect (user_exists ?u)  <- ?u not declared
   RIGHT: :parameters (?p - package ?u - user) :effect (user_exists ?u)

OUTPUT FORMAT - exactly this structure, no markdown:
(:types
  package service - object
)

(:predicates
  (predicate_name ?var - type)
)

(:action action_name
  :parameters (?p - type)
  :precondition (and (pred1 ?p))
  :effect (and (pred2 ?p))
)

Generate ONLY valid PDDL. No markdown code fences, no explanations, no comments."""

    def __init__(
        self,
        group_name: str,
        group_config: dict,
        llm: LLMInterface,
        doc_extractor: DocumentationExtractor,
        osquery_data: Optional[dict] = None,
        phase1_actions: Optional[list[ActionSchema]] = None,
        known_predicates: Optional[list[str]] = None,
        log_dir: str = "pddl_output/llm_logs",
        reuse_phase1_actions: bool = True,
        os_capabilities: dict = None,
    ):
        self.group_name = group_name
        self.config = group_config
        self.llm = llm
        self.doc_extractor = doc_extractor
        self.osquery_data = osquery_data or {}
        self.phase1_actions = phase1_actions or []
        self.known_predicates = known_predicates or []
        self.worker_name = f"{group_name}_agent"
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.reuse_phase1_actions = reuse_phase1_actions
        self.os_capabilities = os_capabilities or {}

    def _build_system_prompt(self) -> str:
        """
        Build the system prompt dynamically, injecting:
        1. Base PDDL syntax rules
        2. Official PDDL BNF-derived rules from common.pddl_rules
        3. OS-specific constraints (sudo-rs/uutils for Ubuntu 25.10)
        """
        # Start with the base syntax rules
        valid_types = sorted([t.value for t in PDDLTypeEnum])
        valid_types_str = ", ".join(valid_types)

        # Inject the dynamic types into the placeholder we created above
        prompt = self.SYSTEM_PROMPT_BASE.format(valid_types_list=valid_types_str)

        # Add the official PDDL syntax guide from common.pddl_rules
        prompt += "\n\n=== OFFICIAL PDDL SYNTAX REFERENCE ===\n"
        prompt += PDDL_SYNTAX_GUIDE

        # Add valid types list for reference
        prompt += "\n\n=== VALID TYPES (use ONLY these) ===\n"
        prompt += ", ".join(sorted(VALID_TYPES))

        # --- NEW: Inject Constraints based on OS Capabilities ---
        constraints = []

        if self.os_capabilities.get("is_sudo_rs"):
            constraints.append(
                "\nCRITICAL CONSTRAINT: This system runs 'sudo-rs' (Rust), NOT standard sudo."
                "\n1. Do NOT generate actions using 'sudo -E' (preserve environment) unless explicitly validated."
                "\n2. Assume wildcards in sudoers are NOT supported."
                "\n3. Check specific exit codes for 'NOEXEC' if mentioned in the docs."
            )

        if self.os_capabilities.get("is_uutils"):
            constraints.append(
                "\nCRITICAL CONSTRAINT: Core utilities (cp, mv, ls, etc.) are 'uutils' (Rust rewrites)."
                "\n1. These tools may lack obscure GNU flags (e.g., specific backup or context flags)."
                "\n2. Only include parameters that appear in the provided --help output."
            )

        if constraints:
            prompt += "\n\n=== OS-SPECIFIC SECURITY CONSTRAINTS ===\n"
            prompt += "\n".join(constraints)
            prompt += "\n\nVIOLATING THESE CONSTRAINTS WILL CAUSE PLANNER FAILURE."

        return prompt

    def generate_partial_domain(self) -> PartialPDDLDomain:
        """
        Generate PDDL using chunked documentation processing.
        """
        start_time = time.time()
        result = PartialPDDLDomain(
            worker_name=self.worker_name,
            group_name=self.group_name,
        )

        try:
            # Step 1: Reuse Phase 1 actions
            existing_actions = set()
            if self.reuse_phase1_actions and self.phase1_actions:
                logger.info(
                    f"[{self.worker_name}] Reusing {len(self.phase1_actions)} Phase 1 actions"
                )
                converted = self._convert_phase1_actions()
                result.actions.extend(converted)
                existing_actions = {a.name for a in converted}

                # Extract types/predicates from reused actions
                result.types.extend(self._extract_types_from_actions(converted))
                result.predicates.extend(
                    self._extract_predicates_from_actions(converted)
                )

            # Step 2: Iterate through Utilities AND Chunks
            utilities = self.config.get("utilities", [])
            system_prompt = self._build_system_prompt()

            for utility in utilities:
                logger.info(f"[{self.worker_name}] Processing utility: {utility}")

                # Use the new chunking method from tools.py
                chunk_generator = self.doc_extractor.get_chunked_docs(utility)

                for i, doc_chunk in enumerate(chunk_generator):
                    logger.debug(
                        f"[{self.worker_name}] Processing chunk {i + 1} for {utility}"
                    )

                    generation_prompt = self._build_chunk_prompt(
                        utility, doc_chunk, existing_actions
                    )

                    # Log prompt
                    log_file = (
                        self.log_dir
                        / f"{self.worker_name}_{utility}_chunk{i}_prompt.txt"
                    )
                    log_file.write_text(
                        f"=== SYS ===\n{system_prompt}\n\n=== USER ===\n{generation_prompt}"
                    )

                    # Call LLM
                    raw_response = self.llm.generate(generation_prompt, system_prompt)

                    # Log response
                    resp_log = (
                        self.log_dir
                        / f"{self.worker_name}_{utility}_chunk{i}_response.txt"
                    )
                    resp_log.write_text(raw_response)

                    # Parse and Merge results
                    self._parse_pddl_output(raw_response, result)

            logger.info(
                f"[{self.worker_name}] Total Generated: {len(result.actions)} actions "
                f"({len(result.predicates)} predicates)"
            )

        except Exception as e:
            logger.error(f"[{self.worker_name}] Generation failed: {e}")
            result.error = str(e)

        result.generation_time = time.time() - start_time
        return result

    def _build_chunk_prompt(
        self, utility: str, doc_chunk: str, existing_actions: set[str]
    ) -> str:
        """Build a prompt for a specific documentation chunk."""
        prompt = (
            f"Analyze this documentation segment for the utility '{utility}'. "
            f"Generate PDDL actions ONLY for the flags/commands found in this specific segment.\n\n"
        )

        prompt += f"=== DOCUMENTATION SEGMENT ({utility}) ===\n{doc_chunk}\n\n"

        # Add context (predicates and existing actions)
        if self.known_predicates:
            prompt += "=== PREFERRED PREDICATES ===\n"
            prompt += "\n".join([f"  {p}" for p in self.known_predicates[:20]])
            prompt += "\n  (use these if applicable)\n\n"

        if existing_actions:
            prompt += "=== EXISTING ACTIONS (DO NOT DUPLICATE) ===\n"
            # Only show relevant actions to save tokens
            relevant = [a for a in existing_actions if utility in a or len(a) < 15]
            prompt += ", ".join(relevant[:30])
            prompt += "\n\n"

        prompt += (
            "TASK:\n"
            "1. Identify new actions described in the documentation segment.\n"
            "2. Generate (:action ...) blocks for them.\n"
            "3. Generate (:predicates ...) used in your actions.\n"
            "4. Do NOT regenerate actions listed above.\n"
            "5. If no actionable commands are in this segment, output nothing.\n"
        )
        return prompt

    def _convert_phase1_actions(self) -> list[PDDLAction]:
        """Convert Phase 1 ActionSchema objects to Phase 2 PDDLAction objects."""
        converted = []

        for action in self.phase1_actions:
            # Convert parameters
            params = []
            for p in action.parameters:
                if hasattr(p, "pddl_type"):
                    type_str = (
                        p.pddl_type if isinstance(p.pddl_type, str) else p.pddl_type
                    )
                else:
                    type_str = "object"
                params.append((p.name, type_str))

            pddl_action = PDDLAction(
                name=action.name,
                parameters=params,
                preconditions=action.preconditions,
                effects=action.effects,
                command_template=action.command_template,
                requires_root=action.requires_root,
                source_utility=action.source_utility,
                source_worker="phase1_reuse",  # Mark as reused
            )
            converted.append(pddl_action)

        return converted

    def _build_generation_prompt(
        self, docs: dict[str, str], existing_actions: set[str]
    ) -> str:
        """
        Build the prompt for PDDL generation.
        Includes known predicates and existing actions to avoid duplication.
        """
        prompt_parts = [
            f"Generate PDDL domain components for: {self.config['description']}",
            f"\nTarget PDDL types: {', '.join(self.config['pddl_focus'])}",
        ]

        # =================================================================
        # Add known predicates for vocabulary consistency
        # =================================================================
        if self.known_predicates:
            prompt_parts.append("\n\n=== EXISTING PREDICATES (use these) ===")
            prompt_parts.append("Use these predicates when applicable:")
            # Show first 50 predicates to avoid context overflow
            for pred in self.known_predicates[:50]:
                prompt_parts.append(f"  {pred}")
            if len(self.known_predicates) > 50:
                prompt_parts.append(f"  ... and {len(self.known_predicates) - 50} more")

        # =================================================================
        # List existing actions to avoid duplication
        # =================================================================
        if existing_actions:
            prompt_parts.append("\n\n=== EXISTING ACTIONS (do NOT duplicate) ===")
            prompt_parts.append("These actions already exist. Generate only NEW ones:")
            for name in sorted(existing_actions):
                prompt_parts.append(f"  - {name}")

        # =================================================================
        # Add documentation context
        # =================================================================
        prompt_parts.append("\n\n=== SYSTEM DOCUMENTATION ===\n")

        for utility, doc in docs.items():
            if doc:
                prompt_parts.append(f"\n--- {utility} ---\n{doc}\n")

        # Add osquery context if available
        if self.osquery_data:
            prompt_parts.append("\n=== CURRENT SYSTEM STATE (osquery) ===\n")
            for table, data in self.osquery_data.items():
                sample = data[:10] if isinstance(data, list) else data
                prompt_parts.append(f"{table}: {json.dumps(sample, indent=2)}\n")

        prompt_parts.append(
            "\n\nGenerate NEW PDDL types, predicates, and actions. "
            "Do NOT duplicate existing actions. "
            "Use existing predicates when possible. "
            "Output ONLY valid PDDL syntax."
        )

        return "".join(prompt_parts)

    def _extract_types_from_actions(self, actions: list[PDDLAction]) -> list[PDDLType]:
        """Extract type definitions from actions."""
        types = set()

        for action in actions:
            for param_name, param_type in action.parameters:
                if param_type and param_type != "object":
                    types.add(param_type)

        return [
            PDDLType(name=t, parent="object", source=self.worker_name) for t in types
        ]

    def _extract_predicates_from_actions(
        self, actions: list[PDDLAction]
    ) -> list[PDDLPredicate]:
        """Extract predicate definitions from action preconditions and effects."""
        predicates = {}

        for action in actions:
            for cond in action.preconditions + action.effects:
                pred = self._parse_predicate_from_condition(cond)
                if pred and pred.name not in predicates:
                    predicates[pred.name] = pred

        return list(predicates.values())

    def _parse_predicate_from_condition(
        self, condition: str
    ) -> Optional[PDDLPredicate]:
        """Parse a predicate definition from a condition string."""
        cond = condition.strip()

        # Remove 'not' wrapper
        if cond.startswith("(not"):
            cond = cond[4:].strip().rstrip(")")

        # Match (predicate_name ?var1 ?var2 ...)
        match = re.match(r"\((\w+)((?:\s+\?\w+(?:\s*-\s*\w+)?)*)\)", cond)
        if not match:
            return None

        pred_name = match.group(1)

        # Skip PDDL keywords
        if pred_name in ["and", "or", "not", "exists", "forall", "when"]:
            return None

        params_str = match.group(2).strip()
        params = []

        param_pattern = r"\?(\w+)(?:\s*-\s*(\w+))?"
        for pm in re.finditer(param_pattern, params_str):
            var_name = pm.group(1)
            var_type = pm.group(2) if pm.group(2) else "object"
            params.append((var_name, var_type))

        return PDDLPredicate(name=pred_name, parameters=params, source=self.worker_name)

    # =========================================================================
    # PDDL Parsing Methods (from original worker)
    # =========================================================================

    def _parse_pddl_output(self, raw: str, result: PartialPDDLDomain):
        """
        Parse LLM output into structured PDDL components.
        Updated to APPEND results (fix for chunking overwrite bug).
        """
        raw = self._strip_markdown(raw)

        # Extract types block
        types_block = self._extract_block(raw, "types")
        if types_block:
            # FIX: Use extend() instead of assignment (=) to keep previous chunks' data
            result.types.extend(self._parse_types(types_block))

        # Extract predicates
        pred_block = self._extract_block(raw, "predicates")
        if pred_block:
            # FIX: Append new predicates only if they don't exist (deduplication)
            new_preds = self._parse_predicates(pred_block)
            existing_names = {p.name for p in result.predicates}

            for p in new_preds:
                if p.name not in existing_names:
                    result.predicates.append(p)
                    existing_names.add(p.name)

        # Extract actions with validation
        action_starts = [
            m.start() for m in re.finditer(r"\(:action\s+", raw, re.IGNORECASE)
        ]
        for start in action_starts:
            action_str = self._extract_sexp_at(raw, start)
            if action_str:
                name_match = re.search(r"\(:action\s+(\w+)", action_str, re.IGNORECASE)
                if name_match:
                    action = self._parse_action(name_match.group(1), action_str)
                    if action:
                        # Validate and normalize the action
                        validated_action = self._validate_and_normalize_action(action)
                        if validated_action:
                            validated_action.source_worker = self.worker_name
                            result.actions.append(validated_action)
                        else:
                            logger.warning(
                                f"[{self.worker_name}] Discarded invalid action: {action.name}"
                            )

    def _strip_markdown(self, text: str) -> str:
        """Remove markdown code fences."""
        text = re.sub(r"^```(?:pddl|lisp|scheme)?\s*\n?", "", text, flags=re.MULTILINE)
        text = re.sub(r"\n?```\s*$", "", text, flags=re.MULTILINE)
        return text.strip()

    def _extract_sexp_at(self, text: str, start: int) -> Optional[str]:
        """Extract a complete S-expression starting at position."""
        if start < 0 or start >= len(text) or text[start] != "(":
            return None

        depth = 0
        end = start

        for i, char in enumerate(text[start:], start=start):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break

        if depth != 0:
            return None

        return text[start:end]

    def _extract_block(self, text: str, block_name: str) -> Optional[str]:
        """Extract content of a PDDL block."""
        pattern = rf"\(:{block_name}\s*"
        match = re.search(pattern, text, re.IGNORECASE)
        if not match:
            return None

        return self._extract_sexp_at(text, match.start())

    def _parse_types(self, types_block: str) -> list[PDDLType]:
        """Parse PDDL type definitions."""
        types = []

        inner = re.sub(r"^\s*\(:types\s*", "", types_block, flags=re.IGNORECASE)
        inner = re.sub(r"\)\s*$", "", inner)

        lines = inner.strip().split("\n")
        for line in lines:
            line = line.strip()
            if not line or line.startswith(";"):
                continue

            if " - " in line:
                parts = line.split(" - ")
                parent = parts[-1].strip()
                children = parts[0].strip().split()
                for child in children:
                    child = child.strip()
                    if child and not child.startswith(";"):
                        types.append(
                            PDDLType(name=child, parent=parent, source=self.worker_name)
                        )

        return types

    def _parse_predicates(self, pred_block: str) -> list[PDDLPredicate]:
        """Parse PDDL predicate definitions."""
        predicates = []

        inner = re.sub(r"^\s*\(:predicates\s*", "", pred_block, flags=re.IGNORECASE)
        inner = re.sub(r"\)\s*$", "", inner)

        i = 0
        while i < len(inner):
            while i < len(inner) and (inner[i].isspace() or inner[i] == ";"):
                if inner[i] == ";":
                    while i < len(inner) and inner[i] != "\n":
                        i += 1
                else:
                    i += 1

            if i >= len(inner):
                break

            if inner[i] == "(":
                sexp = self._extract_sexp_at(inner, i)
                if sexp:
                    pred = self._parse_single_predicate(sexp)
                    if pred:
                        predicates.append(pred)
                    i += len(sexp)
                else:
                    i += 1
            else:
                i += 1

        return predicates

    def _parse_single_predicate(self, sexp: str) -> Optional[PDDLPredicate]:
        """Parse a single predicate definition."""
        inner = sexp.strip()[1:-1].strip()

        if not inner:
            return None

        tokens = inner.split()
        if not tokens:
            return None

        name = tokens[0]

        if name.startswith(":"):
            return None

        params = []
        param_str = " ".join(tokens[1:])
        param_pattern = r"\?(\w+)\s*-\s*(\w+)"
        for pm in re.finditer(param_pattern, param_str):
            params.append((pm.group(1), pm.group(2)))

        return PDDLPredicate(name=name, parameters=params, source=self.worker_name)

    def _parse_action(self, name: str, action_str: str) -> Optional[PDDLAction]:
        """Parse a single PDDL action."""
        try:
            # Extract parameters
            params = []
            params_sexp = self._find_keyword_sexp(action_str, "parameters")
            if params_sexp:
                param_pattern = r"\?(\w+)\s*-\s*(\w+)"
                for pm in re.finditer(param_pattern, params_sexp):
                    params.append((pm.group(1), pm.group(2)))

            # Extract preconditions
            preconditions = []
            pre_sexp = self._find_keyword_sexp(action_str, "precondition")
            if pre_sexp:
                preconditions = self._extract_conditions(pre_sexp)

            # Extract effects
            effects = []
            eff_sexp = self._find_keyword_sexp(action_str, "effect")
            if eff_sexp:
                effects = self._extract_conditions(eff_sexp)

            return PDDLAction(
                name=name,
                parameters=params,
                preconditions=preconditions,
                effects=effects,
            )
        except Exception as e:
            logger.warning(f"Failed to parse action {name}: {e}")
            return None

    def _find_keyword_sexp(self, text: str, keyword: str) -> Optional[str]:
        """Find a keyword and extract the following S-expression."""
        pattern = rf":{keyword}\s*"
        match = re.search(pattern, text, re.IGNORECASE)
        if not match:
            return None

        rest = text[match.end() :]
        paren_pos = rest.find("(")
        if paren_pos == -1:
            return None

        return self._extract_sexp_at(text, match.end() + paren_pos)

    def _extract_conditions(self, cond_sexp: str) -> list[str]:
        """Extract individual conditions from an (and ...) block."""
        conditions = []

        if not cond_sexp:
            return conditions

        inner = cond_sexp.strip()[1:-1].strip()

        if inner.lower().startswith("and"):
            inner = inner[3:].strip()

            i = 0
            while i < len(inner):
                while i < len(inner) and inner[i].isspace():
                    i += 1

                if i >= len(inner):
                    break

                if inner[i] == "(":
                    sexp = self._extract_sexp_at(inner, i)
                    if sexp:
                        # Validate and filter the condition
                        if self._is_valid_condition(sexp):
                            conditions.append(sexp)
                        else:
                            logger.debug(f"Filtered invalid condition: {sexp[:50]}...")
                        i += len(sexp)
                    else:
                        i += 1
                else:
                    i += 1
        else:
            if self._is_valid_condition(cond_sexp):
                conditions.append(cond_sexp)

        return conditions

    # =========================================================================
    # Validation Methods - Filter invalid LLM-generated constructs
    # =========================================================================

    # Patterns that indicate INVALID PDDL constructs
    INVALID_PATTERNS = [
        r"\(assert\s",  # (assert ...) - not valid PDDL
        r"\(equal\s",  # (equal ?x ?y) - not valid PDDL
        r"\(create_process\s",  # functions not allowed
        r"\(strcat\s",  # string operations not allowed
        r"\(concat\s",  # string operations not allowed
        r"\(member\s",  # list operations not allowed
        r"\(implies\s",  # use (when) instead in effects
        r"\(imply\s",  # use (when) instead in effects
        r"'[^']*'",  # single-quoted string literals
        r'"[^"]*"',  # double-quoted string literals
        r"\(\s*\)",  # empty parentheses
        r"\)\s*\(\s*\(",  # malformed )((
        r"\)\(\(",  # malformed )((
    ]

    # Quantifiers - should not be used in STRIPS
    QUANTIFIER_PATTERNS = [
        r"\(exists\s",
        r"\(forall\s",
    ]

    def _is_valid_condition(self, condition: str) -> bool:
        """
        Check if a condition/effect is valid PDDL.
        Rejects constructs that will cause parser failure.
        """
        if not condition or not condition.strip():
            return False

        cond = condition.strip()

        # Check for invalid patterns
        for pattern in self.INVALID_PATTERNS:
            if re.search(pattern, cond, re.IGNORECASE):
                logger.debug(f"Invalid pattern '{pattern}' found in: {cond[:50]}")
                return False

        # Check for quantifiers (not allowed in STRIPS)
        for pattern in self.QUANTIFIER_PATTERNS:
            if re.search(pattern, cond, re.IGNORECASE):
                logger.debug(f"Quantifier found in: {cond[:50]}")
                return False

        # Check for balanced parentheses
        if cond.count("(") != cond.count(")"):
            logger.debug(f"Unbalanced parentheses in: {cond[:50]}")
            return False

        # Check for malformed starts (should start with '(' or be empty after stripping)
        if not cond.startswith("("):
            return False

        return True

    def _validate_and_normalize_action(
        self, action: PDDLAction
    ) -> Optional[PDDLAction]:
        """
        Validate and normalize an action, fixing common LLM errors.
        Returns None if the action is fundamentally broken.
        """
        if not action or not action.name:
            return None

        # Normalize parameter types
        normalized_params = []
        for param_name, param_type in action.parameters:
            normalized_type = normalize_type(param_type)
            normalized_params.append((param_name, normalized_type))
        action.parameters = normalized_params

        # Get declared parameter names
        declared_vars = {f"?{p[0]}" for p in action.parameters}

        # Filter preconditions - remove those with undeclared variables
        valid_preconds = []
        for pre in action.preconditions:
            if self._condition_uses_only_declared_vars(pre, declared_vars):
                valid_preconds.append(pre)
            else:
                logger.debug(f"Filtered precondition with undeclared var: {pre[:50]}")
        action.preconditions = valid_preconds

        # Filter effects - remove those with undeclared variables
        valid_effects = []
        for eff in action.effects:
            if self._condition_uses_only_declared_vars(eff, declared_vars):
                valid_effects.append(eff)
            else:
                logger.debug(f"Filtered effect with undeclared var: {eff[:50]}")
        action.effects = valid_effects

        # Action must have at least one effect to be useful
        if not action.effects:
            logger.warning(f"Action '{action.name}' has no valid effects, discarding")
            return None

        return action

    def _condition_uses_only_declared_vars(
        self, condition: str, declared_vars: set[str]
    ) -> bool:
        """Check that all variables in a condition are declared in parameters."""
        # Find all ?variable references
        var_pattern = r"\?(\w+)"
        found_vars = {f"?{m.group(1)}" for m in re.finditer(var_pattern, condition)}

        # Check if all found vars are declared
        undeclared = found_vars - declared_vars
        if undeclared:
            logger.debug(f"Undeclared variables: {undeclared}")
            return False

        return True
