import logging
import json
import time
import re
from pathlib import Path
from typing import Optional
from .models import PartialPDDLDomain, PDDLType, PDDLPredicate, PDDLAction
from .llm import LLMInterface
from .tools import DocumentationExtractor

logger = logging.getLogger("Phase2.Worker")

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

    # =========================================================================
    # Parenthesis-Aware S-Expression Parsing
    # =========================================================================

    def _extract_sexp_at(self, text: str, start: int) -> Optional[str]:
        """Extract a complete S-expression starting at position `start`."""
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
            # Unbalanced parens - try to recover by finding where depth returns to 0
            logger.warning(f"Unbalanced parentheses in S-expression at position {start}")
            return None

        return text[start:end]

    def _extract_block(self, text: str, block_name: str) -> Optional[str]:
        """Extract content of a PDDL block like (:predicates ...) handling nested parens."""
        pattern = rf"\(:{block_name}\s*"
        match = re.search(pattern, text, re.IGNORECASE)
        if not match:
            return None

        return self._extract_sexp_at(text, match.start())

    def _find_keyword_sexp(self, text: str, keyword: str) -> Optional[str]:
        """Find a keyword like :precondition and extract the following S-expression."""
        pattern = rf":{keyword}\s*"
        match = re.search(pattern, text, re.IGNORECASE)
        if not match:
            return None

        # Find the opening paren after the keyword
        rest = text[match.end():]
        paren_pos = rest.find('(')
        if paren_pos == -1:
            return None

        return self._extract_sexp_at(text, match.end() + paren_pos)

    # =========================================================================
    # PDDL Parsing Methods
    # =========================================================================

    def _parse_pddl_output(self, raw: str, result: PartialPDDLDomain):
        """Parse LLM output into structured PDDL components."""
        # Strip markdown code fences if present
        raw = self._strip_markdown(raw)

        # Extract types block
        types_block = self._extract_block(raw, "types")
        if types_block:
            result.types = self._parse_types(types_block)

        # Extract predicates using paren-aware extraction
        pred_block = self._extract_block(raw, "predicates")
        if pred_block:
            result.predicates = self._parse_predicates(pred_block)

        # Extract actions using paren-aware extraction
        action_starts = [m.start() for m in re.finditer(r"\(:action\s+", raw, re.IGNORECASE)]
        for start in action_starts:
            action_str = self._extract_sexp_at(raw, start)
            if action_str:
                # Extract action name
                name_match = re.search(r"\(:action\s+(\w+)", action_str, re.IGNORECASE)
                if name_match:
                    action = self._parse_action(name_match.group(1), action_str)
                    if action:
                        action.source_worker = self.worker_name
                        result.actions.append(action)

    def _strip_markdown(self, text: str) -> str:
        """Remove markdown code fences if present."""
        # Remove ```pddl or ```lisp or ``` blocks
        text = re.sub(r"^```(?:pddl|lisp|scheme)?\s*\n?", "", text, flags=re.MULTILINE)
        text = re.sub(r"\n?```\s*$", "", text, flags=re.MULTILINE)
        return text.strip()

    def _parse_types(self, types_block: str) -> list[PDDLType]:
        """Parse PDDL type definitions from a (:types ...) block."""
        types = []

        # Remove outer (:types and )
        inner = re.sub(r"^\s*\(:types\s*", "", types_block, flags=re.IGNORECASE)
        inner = re.sub(r"\)\s*$", "", inner)

        # Pattern: type1 type2 - parent_type
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
            else:
                for t in line.split():
                    t = t.strip()
                    if t and not t.startswith(";"):
                        types.append(PDDLType(name=t, source=self.worker_name))

        return types

    def _parse_predicates(self, pred_block: str) -> list[PDDLPredicate]:
        """Parse PDDL predicate definitions from a (:predicates ...) block."""
        predicates = []

        # Remove the outer (:predicates ... )
        inner = re.sub(r"^\s*\(:predicates\s*", "", pred_block, flags=re.IGNORECASE)
        inner = re.sub(r"\)\s*$", "", inner)

        # Find each predicate definition by extracting s-expressions
        i = 0
        while i < len(inner):
            # Skip whitespace and comments
            while i < len(inner) and (inner[i].isspace() or inner[i] == ';'):
                if inner[i] == ';':
                    # Skip to end of line
                    while i < len(inner) and inner[i] != '\n':
                        i += 1
                else:
                    i += 1

            if i >= len(inner):
                break

            if inner[i] == '(':
                # Extract this predicate s-expression
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
        """Parse a single predicate like (installed ?p - package)."""
        # Remove outer parens
        inner = sexp.strip()[1:-1].strip()

        if not inner:
            return None

        # First token is the predicate name
        tokens = inner.split()
        if not tokens:
            return None

        name = tokens[0]

        # Skip if it looks like a keyword (starts with :)
        if name.startswith(':'):
            return None

        params = []

        # Parse parameters: ?var - type ?var2 - type2
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

    def _extract_conditions(self, cond_sexp: str) -> list[str]:
        """Extract individual conditions from an (and ...) block or single predicate."""
        conditions = []

        if not cond_sexp:
            return conditions

        # Remove outer parens
        inner = cond_sexp.strip()[1:-1].strip()

        # Check if it starts with 'and'
        if inner.lower().startswith('and'):
            inner = inner[3:].strip()

            # Extract each sub-sexp
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
            # Single condition - return the whole thing
            conditions.append(cond_sexp)

        return conditions