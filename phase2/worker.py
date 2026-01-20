"""
phase2/worker.py

Worker agent for generating partial PDDL domains.
Updated to:
- Reuse Phase 1 actions instead of regenerating
- Use known predicates for vocabulary consistency
- Only generate new actions for gaps not covered by Phase 1
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

from common.models import ActionSchema

from phase2.models import PartialPDDLDomain, PDDLType, PDDLPredicate, PDDLAction
from phase2.llm import LLMInterface
from phase2.tools import DocumentationExtractor
from phase1.common.config import OSQUERY_MAPPINGS

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

    # Updated system prompt that references known predicates
    SYSTEM_PROMPT = """You are a PDDL 2.1 domain expert. Generate STRICTLY VALID PDDL syntax.

ABSOLUTE RULES - VIOLATIONS WILL CAUSE PARSER FAILURE:

1. TYPES: Only these base types exist: object, package, service, user, group, file, directory, configuration_file, port, interface, firewall_rule, process, repository
   - Do NOT invent new types like "string", "list", "command"

2. PREDICATES: Boolean only, no functions
   - USE EXISTING PREDICATES from the vocabulary provided below when applicable
   - Only invent new predicates if absolutely necessary

3. ACTIONS: Every parameter MUST be declared
   - Do NOT duplicate actions that already exist (listed below)
   - Only generate NEW actions not covered by existing ones

4. NO FUNCTIONS OR EXPRESSIONS IN EFFECTS:
   INVALID: (installed (find_package ?name))
   VALID: (installed ?p)

5. NO STRING LITERALS in preconditions/effects

6. NO NESTED PREDICATES

7. VARIABLE SCOPE:
   Any variable used in preconditions or effects MUST be defined in :parameters.

OUTPUT FORMAT - exactly this structure:
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

Generate ONLY valid PDDL. No markdown, no explanations, no comments."""

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
        Build the system prompt dynamically, injecting OS-specific constraints.
        This forces the LLM to respect Ubuntu 25.10 security boundaries (sudo-rs/uutils).
        """
        # Start with the base syntax rules
        prompt = self.SYSTEM_PROMPT

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

    def _build_generation_prompt(
            self,
            docs: dict[str, str],
            existing_actions: set[str]
    ) -> str:
        """
        Build the prompt for PDDL generation with Deterministic Predicate Glue.
        """
        prompt_parts = [
            f"Generate PDDL domain components for: {self.config['description']}",
            f"\nTarget PDDL types: {', '.join(self.config['pddl_focus'])}",
        ]

        # =================================================================
        # NEW: Inject Deterministic Schema Mappings (The "Glue")
        # =================================================================
        # Filter mappings relevant to this worker's tables
        worker_tables = self.config.get("osquery_tables", [])
        relevant_mappings = [
            m for m in OSQUERY_MAPPINGS
            if m.table in worker_tables
        ]

        if relevant_mappings:
            prompt_parts.append("\n\n=== GROUND TRUTH PREDICATE MAPPINGS (STRICT RULES) ===")
            prompt_parts.append("You MUST use these specific predicates when the system state matches the condition.")
            prompt_parts.append("These map directly to the OS internal state (Osquery):")

            for m in relevant_mappings:
                # Format the deterministic rule
                # e.g. "Table 'systemd_units': When active_state='active' -> Use (service_running ?id)"

                condition_str = m.predicate_condition if m.predicate_condition else "row exists"

                rule = (
                    f"  - Table '{m.table}': "
                    f"When [{condition_str}] "
                    f"-> Use Predicate: ({m.predicate_name} ?{m.name_column})"
                )
                prompt_parts.append(rule)

                # Add negative constraint if possible
                prompt_parts.append(
                    f"    (DO NOT invent aliases like 'is_{m.predicate_name}' or 'status_{m.predicate_name}')")

        # =================================================================
        # [Existing Code] Known Predicates
        # =================================================================
        if self.known_predicates:
            prompt_parts.append("\n\n=== EXISTING PREDICATES (VOCABULARY) ===")
            prompt_parts.append("Use these predicates when applicable:")
            for pred in self.known_predicates[:50]:
                prompt_parts.append(f"  {pred}")
            if len(self.known_predicates) > 50:
                prompt_parts.append(f"  ... and {len(self.known_predicates) - 50} more")

        # =================================================================
        # [Existing Code] Existing Actions
        # =================================================================
        if existing_actions:
            prompt_parts.append("\n\n=== EXISTING ACTIONS (do NOT duplicate) ===")
            for name in sorted(existing_actions):
                prompt_parts.append(f"  - {name}")

        # =================================================================
        # [Existing Code] Documentation & Data
        # =================================================================
        prompt_parts.append("\n\n=== SYSTEM DOCUMENTATION ===\n")

        for utility, doc in docs.items():
            if doc:
                truncated = doc[:2000] + "..." if len(doc) > 2000 else doc
                prompt_parts.append(f"\n--- {utility} ---\n{truncated}\n")

        # Add osquery context if available
        if self.osquery_data:
            prompt_parts.append("\n=== CURRENT SYSTEM STATE (Ground Truth) ===\n")
            for table, data in self.osquery_data.items():
                sample = data[:10] if isinstance(data, list) else data
                prompt_parts.append(f"{table}: {json.dumps(sample, indent=2)}\n")

        prompt_parts.append(
            "\n\nGenerate NEW PDDL types, predicates, and actions. "
            "STRICTLY ADHERE to the Ground Truth Predicate Mappings above."
        )

        return "".join(prompt_parts)

    def _convert_phase1_actions(self) -> list[PDDLAction]:
        """Convert Phase 1 ActionSchema objects to Phase 2 PDDLAction objects."""
        converted = []
        
        for action in self.phase1_actions:
            # Convert parameters
            params = []
            for p in action.parameters:
                if hasattr(p, 'pddl_type'):
                    type_str = p.pddl_type if isinstance(p.pddl_type, str) else p.pddl_type
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
        self, 
        docs: dict[str, str], 
        existing_actions: set[str]
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
                truncated = doc[:2000] + "..." if len(doc) > 2000 else doc
                prompt_parts.append(f"\n--- {utility} ---\n{truncated}\n")

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
            PDDLType(name=t, parent="object", source=self.worker_name)
            for t in types
        ]

    def _extract_predicates_from_actions(
        self, 
        actions: list[PDDLAction]
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
        self, 
        condition: str
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
        
        return PDDLPredicate(
            name=pred_name,
            parameters=params,
            source=self.worker_name
        )

    # =========================================================================
    # PDDL Parsing Methods (from original worker)
    # =========================================================================

    def _parse_pddl_output(self, raw: str, result: PartialPDDLDomain):
        """Parse LLM output into structured PDDL components."""
        raw = self._strip_markdown(raw)

        # Extract types block
        types_block = self._extract_block(raw, "types")
        if types_block:
            result.types = self._parse_types(types_block)

        # Extract predicates
        pred_block = self._extract_block(raw, "predicates")
        if pred_block:
            result.predicates = self._parse_predicates(pred_block)

        # Extract actions
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
                        action.source_worker = self.worker_name
                        result.actions.append(action)

    def _strip_markdown(self, text: str) -> str:
        """Remove markdown code fences."""
        text = re.sub(r"^```(?:pddl|lisp|scheme)?\s*\n?", "", text, flags=re.MULTILINE)
        text = re.sub(r"\n?```\s*$", "", text, flags=re.MULTILINE)
        return text.strip()

    def _extract_sexp_at(self, text: str, start: int) -> Optional[str]:
        """Extract a complete S-expression starting at position."""
        if start < 0 or start >= len(text) or text[start] != '(':
            return None

        depth = 0
        end = start

        for i, char in enumerate(text[start:], start=start):
            if char == '(':
                depth += 1
            elif char == ')':
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
            while i < len(inner) and (inner[i].isspace() or inner[i] == ';'):
                if inner[i] == ';':
                    while i < len(inner) and inner[i] != '\n':
                        i += 1
                else:
                    i += 1

            if i >= len(inner):
                break

            if inner[i] == '(':
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

        if name.startswith(':'):
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

        rest = text[match.end():]
        paren_pos = rest.find('(')
        if paren_pos == -1:
            return None

        return self._extract_sexp_at(text, match.end() + paren_pos)

    def _extract_conditions(self, cond_sexp: str) -> list[str]:
        """Extract individual conditions from an (and ...) block."""
        conditions = []

        if not cond_sexp:
            return conditions

        inner = cond_sexp.strip()[1:-1].strip()

        if inner.lower().startswith('and'):
            inner = inner[3:].strip()

            i = 0
            while i < len(inner):
                while i < len(inner) and inner[i].isspace():
                    i += 1

                if i >= len(inner):
                    break

                if inner[i] == '(':
                    sexp = self._extract_sexp_at(inner, i)
                    if sexp:
                        conditions.append(sexp)
                        i += len(sexp)
                    else:
                        i += 1
                else:
                    i += 1
        else:
            conditions.append(cond_sexp)

        return conditions
