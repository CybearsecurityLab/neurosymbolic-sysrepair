import logging
import json
import subprocess
import time
import re
from pathlib import Path
from typing import Optional
from .models import PartialPDDLDomain, PDDLType, PDDLPredicate, PDDLAction
from .llm import LLMInterface
from .tools import DocumentationExtractor


# =============================================================================
# SECTION 5: Worker Agents (Map Phase)
# =============================================================================


class WorkerAgent:
    """
    Base worker agent for generating partial PDDL domains.
    Each worker specializes in a utility group.
    """

    SYSTEM_PROMPT = """You are a PDDL 2.1 domain expert. Generate STRICTLY VALID PDDL syntax.

ABSOLUTE RULES - VIOLATIONS WILL CAUSE PARSER FAILURE:

1. TYPES: Only these base types exist: object, package, service, user, group, file, directory, configuration_file, port, interface, firewall_rule, process, repository
   - Do NOT invent new types like "string", "list", "command"
   - Subtypes use: child_type - parent_type

2. PREDICATES: Boolean only, no functions
   VALID: (installed ?p - package)
   VALID: (file_exists ?f - file)  
   INVALID: (version ?p - package) - no return values
   INVALID: (name ?x - string) - string is not a type

3. ACTIONS: Every parameter MUST be declared
   VALID:
   (:action install_package
     :parameters (?p - package)
     :precondition (and (available ?p) (not (installed ?p)))
     :effect (and (installed ?p))
   )

   INVALID - unbound variable:
   (:action foo
     :parameters ()
     :precondition (bar ?x)  ; ERROR: ?x not declared
   )

4. NO FUNCTIONS OR EXPRESSIONS IN EFFECTS:
   INVALID: (installed (find_package ?name))
   INVALID: (concat ?a ?b)
   INVALID: (strcat ?x ?y)
   INVALID: (create_process ?cmd)
   VALID: (installed ?p)

5. QUANTIFIERS - use proper syntax:
   VALID: (exists (?x - type) (predicate ?x))
   VALID: (forall (?x - type) (predicate ?x))
   INVALID: (?x :exists (predicate ?x))

6. NO STRING LITERALS in preconditions/effects:
   INVALID: (equal ?chain "filter")
   VALID: (is_filter_chain ?chain)

7. NO NESTED PREDICATES:
   INVALID: (at ?x (get_location ?y))
   VALID: (and (at ?x ?loc) (is_location ?y ?loc))
   Never use a predicate as an argument to another predicate.

8. VARIABLE SCOPE:
   Any variable (e.g., ?r, ?c) used in preconditions or effects MUST be defined in :parameters.

9. USE ONLY DEFINED TYPES:
   You may ONLY use these types: object, package, service, user, group, file, directory, configuration_file, port, interface, firewall_rule, process, repository.
   - DO NOT use: "string", "integer", "Timestamp", "Permission", "Owner", "ACL".
   - If you need a permission, use a string or abstract object, or simplify.

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
            log_dir: str = "pddl_output/llm_logs",
    ):
        self.group_name = group_name
        self.config = group_config
        self.llm = llm
        self.doc_extractor = doc_extractor
        self.osquery_data = osquery_data or {}
        self.worker_name = f"{group_name}_agent"
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def generate_partial_domain(self) -> PartialPDDLDomain:
        """Generate partial PDDL domain for this utility group."""
        start_time = time.time()

        result = PartialPDDLDomain(
            worker_name=self.worker_name, group_name=self.group_name
        )

        try:
            # 1. Fetch documentation for all utilities
            docs = self.doc_extractor.get_utility_docs(self.config["utilities"])

            # 2. Build prompt with documentation context
            prompt = self._build_generation_prompt(docs)

            # 3. Generate PDDL via LLM
            raw_pddl = self.llm.generate(prompt, self.SYSTEM_PROMPT)
            result.raw_pddl = raw_pddl

            # --- LOGGING: Save raw output for inspection ---
            log_file = self.log_dir / f"{self.worker_name}_raw.txt"
            log_file.write_text(raw_pddl, encoding="utf-8")
            logger.info(f"Worker {self.worker_name} raw output saved to {log_file}")
            # -----------------------------------------------

            # 4. Parse the generated PDDL
            self._parse_pddl_output(raw_pddl, result)

            result.generation_time = time.time() - start_time
            logger.info(
                f"Worker {self.worker_name}: Generated {len(result.types)} types, "
                f"{len(result.predicates)} predicates, {len(result.actions)} actions "
                f"in {result.generation_time:.2f}s"
            )

        except Exception as e:
            result.error = str(e)
            logger.error(f"Worker {self.worker_name} failed: {e}")

        return result

    def _build_generation_prompt(self, docs: dict[str, str]) -> str:
        """Build the prompt for PDDL generation."""
        prompt_parts = [
            f"Generate PDDL domain components for: {self.config['description']}",
            f"\nTarget PDDL types to define or use: {', '.join(self.config['pddl_focus'])}",
            "\n\n=== SYSTEM DOCUMENTATION ===\n",
        ]

        # Add documentation (truncated for context limits)
        for utility, doc in docs.items():
            if doc:
                # Truncate each doc to ~2000 chars
                truncated = doc[:2000] + "..." if len(doc) > 2000 else doc
                prompt_parts.append(f"\n--- {utility} ---\n{truncated}\n")

        # Add osquery context if available
        if self.osquery_data:
            prompt_parts.append("\n=== CURRENT SYSTEM STATE (osquery) ===\n")
            for table in self.config.get("osquery_tables", []):
                if table in self.osquery_data:
                    data = self.osquery_data[table]
                    # Show first 10 entries
                    sample = data[:10] if isinstance(data, list) else data
                    prompt_parts.append(f"{table}: {json.dumps(sample, indent=2)}\n")

        prompt_parts.append(
            "\n\nGenerate the PDDL types, predicates, and actions. "
            "Output ONLY valid PDDL syntax."
        )

        return "".join(prompt_parts)

    def _parse_pddl_output(self, raw: str, result: PartialPDDLDomain):
        """Parse LLM output into structured PDDL components."""
        # Extract types
        types_match = re.search(r"\(:types\s*(.*?)\)", raw, re.DOTALL)
        if types_match:
            result.types = self._parse_types(types_match.group(1))

        # Extract predicates
        pred_match = re.search(
            r"\(:predicates\s*(.*?)\)\s*(?:\(:action|$)", raw, re.DOTALL
        )
        if pred_match:
            result.predicates = self._parse_predicates(pred_match.group(1))

        # Extract actions
        action_pattern = r"\(:action\s+(\w+)\s*(.*?)(?=\(:action|\Z)"
        for match in re.finditer(action_pattern, raw, re.DOTALL):
            action = self._parse_action(match.group(1), match.group(2))
            if action:
                action.source_worker = self.worker_name
                result.actions.append(action)

    def _parse_types(self, types_str: str) -> list[PDDLType]:
        """Parse PDDL type definitions."""
        types = []
        # Pattern: type1 type2 - parent_type
        lines = types_str.strip().split("\n")
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
                    if child:
                        types.append(
                            PDDLType(name=child, parent=parent, source=self.worker_name)
                        )
            else:
                for t in line.split():
                    if t.strip():
                        types.append(PDDLType(name=t.strip(), source=self.worker_name))

        return types

    def _parse_predicates(self, pred_str: str) -> list[PDDLPredicate]:
        """Parse PDDL predicate definitions."""
        predicates = []
        # Pattern: (predicate_name ?param1 - type1 ?param2 - type2)
        pattern = r"\((\w+)((?:\s+\?\w+\s*-\s*\w+)*)\)"

        for match in re.finditer(pattern, pred_str):
            name = match.group(1)
            params_str = match.group(2).strip()

            # Parse parameters
            params = []
            param_pattern = r"\?(\w+)\s*-\s*(\w+)"
            for pm in re.finditer(param_pattern, params_str):
                params.append((pm.group(1), pm.group(2)))

            predicates.append(
                PDDLPredicate(name=name, parameters=params, source=self.worker_name)
            )

        return predicates

    def _parse_action(self, name: str, body: str) -> Optional[PDDLAction]:
        """Parse a single PDDL action."""
        try:
            # Extract parameters
            params_match = re.search(r":parameters\s*\((.*?)\)", body, re.DOTALL)
            params = []
            if params_match:
                param_pattern = r"\?(\w+)\s*-\s*(\w+)"
                for pm in re.finditer(param_pattern, params_match.group(1)):
                    params.append((pm.group(1), pm.group(2)))

            # Extract preconditions
            pre_match = re.search(
                r":precondition\s*\((.*?)\)\s*:effect", body, re.DOTALL
            )
            preconditions = []
            if pre_match:
                preconditions = self._extract_conditions(pre_match.group(1))

            # Extract effects
            eff_match = re.search(r":effect\s*\((.*?)\)\s*\)?$", body, re.DOTALL)
            effects = []
            if eff_match:
                effects = self._extract_conditions(eff_match.group(1))

            return PDDLAction(
                name=name,
                parameters=params,
                preconditions=preconditions,
                effects=effects,
            )
        except Exception as e:
            logger.warning(f"Failed to parse action {name}: {e}")
            return None

    def _extract_conditions(self, cond_str: str) -> list[str]:
        """Extract individual conditions from an (and ...) block."""
        conditions = []
        # Remove outer 'and' if present
        cond_str = re.sub(r"^\s*and\s*", "", cond_str.strip())

        # Match individual predicates including (not (...))
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
                    conditions.append(current.strip())
                    current = ""
            elif depth > 0:
                current += char

        return conditions



