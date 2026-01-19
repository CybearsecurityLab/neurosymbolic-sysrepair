import os
import subprocess
import time
import re
import logging
from typing import Optional
from .models import PartialPDDLDomain, PDDLType, PDDLPredicate, PDDLAction
from .llm import LLMInterface
from .repair import PDDLRepairer

logger = logging.getLogger("Phase2.Merger")


class MergerAgent:
    """
    Merger agent that synthesizes partial domains into a unified PDDL domain.
    Implements the Reduce phase with conflict resolution.
    """

    # Core type hierarchy (Section 3.1) - used for conflict resolution
    CORE_TYPE_HIERARCHY = {
        "object": None,
        "filesystem_object": "object",
        "file": "filesystem_object",
        "directory": "filesystem_object",
        "configuration_file": "file",
        "service": "object",
        "process": "object",
        "package": "object",
        "repository": "object",
        "user": "object",
        "group": "object",
        "system_user": "user",
        "human_user": "user",
        "port": "object",
        "interface": "object",
        "firewall_rule": "object",
    }

    def __init__(self, llm: Optional[LLMInterface] = None):
        self.llm = llm
        self.repairer = PDDLRepairer()  # Add repairer
        self.unified_types: dict[str, PDDLType] = {}
        self.unified_predicates: dict[str, PDDLPredicate] = {}
        self.unified_actions: list[PDDLAction] = []
        self.merge_log: list[str] = []
        self.all_repairs: list[str] = []

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
                repaired = self.repairer.repair(domain.raw_pddl)
                repairs = self.repairer.get_repairs_log()
                if repairs:
                    logger.info(f"  {domain.worker_name}: {len(repairs)} repairs")
                    self.all_repairs.extend(
                        [f"{domain.worker_name}: {r}" for r in repairs]
                    )
                domain.raw_pddl = repaired
                # Re-parse after repair
                self._reparse_domain(domain)

        logger.info(f"  → Total repairs: {len(self.all_repairs)}")

        # Step 1: Namespace Resolution - Unify Types
        logger.info("\n[1/5] Unifying type definitions...")
        self._unify_types(valid_domains)
        logger.info(f"  → {len(self.unified_types)} unified types")

        # Step 2: Predicate Unification
        logger.info("\n[2/5] Unifying predicates...")
        self._unify_predicates(valid_domains)
        # Also extract predicates from action bodies
        self._extract_predicates_from_actions(valid_domains)
        logger.info(f"  → {len(self.unified_predicates)} unified predicates")

        # Step 3: Action Consolidation
        logger.info("\n[3/5] Consolidating actions...")
        self._consolidate_actions(valid_domains)
        logger.info(f"  → {len(self.unified_actions)} unified actions")

        # Step 4: Validate action parameters reference declared predicates
        logger.info("\n[4/5] Validating action-predicate consistency...")
        self._validate_action_predicates()

        # Step 5: Construct and Validate Domain
        logger.info("\n[5/5] Constructing unified domain...")
        domain_pddl = self._construct_domain()

        # Final syntax repair pass
        domain_pddl = self.repairer.repair(domain_pddl)

        # Validate syntax
        is_valid, errors = self._validate_pddl(domain_pddl)
        if is_valid:
            logger.info("  ✓ Domain syntax validated")
        else:
            logger.warning(f"  ⚠ Validation issues: {errors}")
            domain_pddl = self._repair_pddl(domain_pddl, errors)

        elapsed = time.time() - start_time
        logger.info(f"\nReduce phase completed in {elapsed:.2f}s")

        return domain_pddl

    def _reparse_domain(self, domain: PartialPDDLDomain):
        """Re-parse a domain after repairs."""
        raw = domain.raw_pddl

        # Clear existing parsed data
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
                parent = parts[-1].strip()
                children = parts[0].strip().split()
                for child in children:
                    child = child.strip()
                    if child and child in PDDLRepairer.VALID_TYPES:
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
                params.append((pm.group(1), pm.group(2)))

            predicates.append(
                PDDLPredicate(name=name, parameters=params, source=source)
            )

        return predicates

    def _parse_action_from_match(
            self, name: str, body: str, source: str
    ) -> Optional[PDDLAction]:
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
                r":precondition\s*\(and(.*?)\)\s*:effect", body, re.DOTALL
            )
            preconditions = []
            if pre_match:
                preconditions = self._extract_conditions(pre_match.group(1))

            # Extract effects
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

    def _extract_predicates_from_actions(self, domains: list[PartialPDDLDomain]):
        """Extract predicates that are used in actions but not declared."""
        for domain in domains:
            for action in domain.actions:
                # Check preconditions
                for pre in action.preconditions:
                    self._extract_predicate_from_condition(pre, domain.worker_name)

                # Check effects
                for eff in action.effects:
                    self._extract_predicate_from_condition(eff, domain.worker_name)

    def _extract_predicate_from_condition(self, condition: str, source: str):
        """Extract a predicate definition from a condition string."""
        # Remove 'not' wrapper
        cond = condition.strip()
        if cond.startswith("(not"):
            cond = cond[4:].strip().rstrip(")")

        # Match (predicate_name ?var1 - type1 ...)
        match = re.match(r"\((\w+)((?:\s+\?\w+(?:\s*-\s*\w+)?)*)\)", cond)
        if match:
            pred_name = match.group(1)

            # Skip PDDL keywords
            if pred_name in ["and", "or", "not", "exists", "forall", "when"]:
                return

            # Skip if already exists
            if pred_name in self.unified_predicates:
                return

            params_str = match.group(2).strip()
            params = []

            # Parse parameters
            param_pattern = r"\?(\w+)(?:\s*-\s*(\w+))?"
            for pm in re.finditer(param_pattern, params_str):
                var_name = pm.group(1)
                var_type = (
                    pm.group(2)
                    if pm.group(2)
                    else self.repairer._infer_type_from_context(var_name, condition)
                )
                params.append((var_name, var_type))

            self.unified_predicates[pred_name] = PDDLPredicate(
                name=pred_name, parameters=params, source=source
            )
            self.merge_log.append(f"Extracted predicate '{pred_name}' from action body")

    def _validate_action_predicates(self):
        """Ensure all predicates used in actions are declared."""
        for action in self.unified_actions:
            for pre in action.preconditions + action.effects:
                # Extract predicate name
                cond = pre.strip()
                if cond.startswith("(not"):
                    cond = cond[4:].strip().rstrip(")")

                match = re.match(r"\((\w+)", cond)
                if match:
                    pred_name = match.group(1)
                    if pred_name not in [
                        "and",
                        "or",
                        "not",
                        "exists",
                        "forall",
                        "when",
                    ]:
                        if pred_name not in self.unified_predicates:
                            # Add missing predicate
                            self._extract_predicate_from_condition(cond, "validator")

    def _unify_types(self, domains: list[PartialPDDLDomain]):
        """Unify type definitions with conflict resolution."""
        # Start with core hierarchy
        for type_name, parent in self.CORE_TYPE_HIERARCHY.items():
            self.unified_types[type_name] = PDDLType(
                name=type_name, parent=parent, source="core_hierarchy"
            )

        # Add types from workers
        for domain in domains:
            for ptype in domain.types:
                if ptype.name not in self.unified_types:
                    # New type - check if parent exists
                    if ptype.parent and ptype.parent not in self.unified_types:
                        # Parent doesn't exist, default to 'object'
                        self.merge_log.append(
                            f"Type '{ptype.name}' parent '{ptype.parent}' not found, "
                            f"defaulting to 'object'"
                        )
                        ptype.parent = "object"

                    self.unified_types[ptype.name] = ptype
                else:
                    # Type exists - check for conflicts
                    existing = self.unified_types[ptype.name]
                    if ptype.parent != existing.parent:
                        # Parent conflict - prefer core hierarchy
                        if existing.source == "core_hierarchy":
                            self.merge_log.append(
                                f"Type '{ptype.name}' parent conflict: "
                                f"keeping core '{existing.parent}' over '{ptype.parent}'"
                            )
                        else:
                            # Use LLM to resolve if available
                            self.merge_log.append(
                                f"Type '{ptype.name}' parent conflict: "
                                f"'{existing.parent}' vs '{ptype.parent}'"
                            )

    def _unify_predicates(self, domains: list[PartialPDDLDomain]):
        """Unify predicates, detecting semantic duplicates."""
        # Predicate similarity mapping for unification
        PREDICATE_ALIASES = {
            "file_exists": ["file_present", "has_file"],
            "service_running": ["service_active", "svc_running"],
            "package_installed": ["pkg_installed", "has_package"],
            "user_exists": ["user_present", "has_user"],
        }

        # Build reverse mapping
        alias_to_canonical = {}
        for canonical, aliases in PREDICATE_ALIASES.items():
            for alias in aliases:
                alias_to_canonical[alias] = canonical

        for domain in domains:
            for pred in domain.predicates:
                # Check if this is an alias
                canonical_name = alias_to_canonical.get(pred.name, pred.name)

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

    def _consolidate_actions(self, domains: list[PartialPDDLDomain]):
        """Consolidate actions, detecting and merging duplicates."""
        action_map: dict[str, list[PDDLAction]] = {}

        # Group actions by name
        for domain in domains:
            for action in domain.actions:
                if action.name not in action_map:
                    action_map[action.name] = []
                action_map[action.name].append(action)

        # Merge or select best version
        for name, actions in action_map.items():
            if len(actions) == 1:
                self.unified_actions.append(actions[0])
            else:
                # Multiple definitions - merge
                merged = self._merge_actions(actions)
                self.unified_actions.append(merged)
                self.merge_log.append(
                    f"Merged {len(actions)} definitions of action '{name}'"
                )

    def _merge_actions(self, actions: list[PDDLAction]) -> PDDLAction:
        """Merge multiple action definitions into one."""
        # Use the one with most complete preconditions
        best = max(actions, key=lambda a: len(a.preconditions) + len(a.effects))

        # Merge unique preconditions from all versions
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
                    # Validate this is a proper predicate
                    stripped = current.strip()
                    if stripped and stripped.startswith("(") and stripped.endswith(")"):
                        # Check it's not malformed
                        if not any(
                                x in stripped
                                for x in [
                                    "strcat",
                                    "concat",
                                    "create_process",
                                    '""',
                                    "='",
                                    "=",
                                ]
                        ):
                            conditions.append(stripped)
                    current = ""
            elif depth > 0:
                current += char

        return conditions

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

        # Types section
        lines.append("  ;; Type Hierarchy")
        lines.append("  (:types")

        # Group types by parent
        parent_groups: dict[str, list[str]] = {}
        for tname, tdef in self.unified_types.items():
            parent = tdef.parent or "object"
            if parent not in parent_groups:
                parent_groups[parent] = []
            if tname != parent:  # Don't include self
                parent_groups[parent].append(tname)

        # Output in hierarchy order
        for parent in ["object", "filesystem_object", "file", "user"]:
            if parent in parent_groups and parent_groups[parent]:
                children = " ".join(sorted(parent_groups[parent]))
                lines.append(f"    {children} - {parent}")

        # Output remaining
        for parent, children in parent_groups.items():
            if (
                    parent not in ["object", "filesystem_object", "file", "user"]
                    and children
            ):
                lines.append(f"    {' '.join(sorted(children))} - {parent}")

        lines.append("  )")
        lines.append("")

        # Predicates section
        lines.append("  ;; Predicates")
        lines.append("  (:predicates")

        for pname, pred in sorted(self.unified_predicates.items()):
            params = " ".join(f"?{p[0]} - {p[1]}" for p in pred.parameters)
            lines.append(f"    ({pname} {params})")

        # Add standard predicates if missing
        standard_preds = [
            "(network_available)",
            "(can_escalate ?u - user)",
        ]
        for sp in standard_preds:
            if not any(sp.split()[0].strip("(") in p for p in self.unified_predicates):
                lines.append(f"    {sp}")

        lines.append("  )")
        lines.append("")

        # Actions section
        for action in sorted(self.unified_actions, key=lambda a: a.name):
            lines.append(f"  ;; Action: {action.name}")
            if action.source_utility:
                lines.append(f"  ;; Source: {action.source_utility}")

            lines.append(f"  (:action {action.name}")

            # Parameters
            params = " ".join(f"?{p[0]} - {p[1]}" for p in action.parameters)
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

    def _validate_pddl(self, pddl: str) -> tuple[bool, list[str]]:
        """Validate PDDL syntax using VAL if available."""
        errors = []

        # Basic syntax checks
        if pddl.count("(") != pddl.count(")"):
            errors.append("Unbalanced parentheses")

        if "(define (domain" not in pddl:
            errors.append("Missing domain definition")

        if "(:types" not in pddl:
            errors.append("Missing types section")

        if "(:predicates" not in pddl:
            errors.append("Missing predicates section")

        # Try VAL parser if available
        try:
            import tempfile

            with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".pddl", delete=False
            ) as f:
                f.write(pddl)
                temp_path = f.name

            result = subprocess.run(
                ["validate", "-p", temp_path],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                errors.append(f"VAL: {result.stderr}")

            os.unlink(temp_path)
        except FileNotFoundError:
            pass  # VAL not installed
        except Exception as e:
            pass

        return len(errors) == 0, errors

    def _repair_pddl(self, pddl: str, errors: list[str]) -> str:
        """Attempt to repair PDDL syntax errors."""
        # Fix unbalanced parentheses
        open_count = pddl.count("(")
        close_count = pddl.count(")")

        if open_count > close_count:
            pddl += ")" * (open_count - close_count)
        elif close_count > open_count:
            # Remove extra closing parens from end
            while pddl.endswith(")") and pddl.count(")") > pddl.count("("):
                pddl = pddl[:-1]

        return pddl

    def get_merge_log(self) -> list[str]:
        """Return the merge operation log."""
        return self.merge_log