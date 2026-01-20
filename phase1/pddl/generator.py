# =============================================================================
# SECTION 5: PDDL Generator
# =============================================================================
import re
from typing import Optional

from common.models import ActionSchema


class PDDLGenerator:
    """
    Generates PDDL domain from extracted system state and actions.

    When using dynamic scoping (Anchor & Propagate), the state is already
    optimally filtered. When using static scoping, legacy limits apply.
    """

    # Legacy limits for static scoping mode only
    STATIC_OBJECT_LIMITS = {
        "package": 100,
        "service": 50,
        "user": 50,
        "group": 50,
        "port": 20,
        "firewall_rule": 20,
        "process": 30,
        "file": 50,
        "configuration_file": 50,
        "directory": 20,
    }

    def __init__(self, domain_name: str = "sysadmin"):
        self.domain_name = domain_name

    def generate_domain(self, state: dict, actions: list[ActionSchema]) -> str:
        """Generate complete PDDL domain file."""
        lines = []

        # Header
        lines.append(f"(define (domain {self.domain_name})")
        lines.append("")

        # Requirements
        lines.append("  (:requirements :strips :typing :negative-preconditions)")
        lines.append("")

        # Types
        lines.append(self._generate_types(state))
        lines.append("")

        # Predicates
        # FIX: Pass 'actions' here so dynamic predicates are generated!
        lines.append(self._generate_predicates(state, actions))
        lines.append("")

        # Deduplicate actions by name (keep first occurrence)
        seen_actions = set()
        unique_actions = []
        for action in actions:
            if action.name not in seen_actions:
                seen_actions.add(action.name)
                unique_actions.append(action)

        # Actions
        for action in unique_actions:
            lines.append(self._generate_action(action))
            lines.append("")

        lines.append(")")

        return "\n".join(lines)

    """
    FIXES FOR phase1.py - PDDL Path Sanitization

    The error occurs because raw file paths like `/var/cache/apt/archives` are being 
    used in PDDL predicates, but `/` is not a valid character in PDDL identifiers.

    Apply these changes to fix the issue:
    """

    # =============================================================================
    # FIX 1: Add this helper method to the PDDLGenerator class (around line 2680)
    # =============================================================================

    # PDDL reserved keywords that cannot be used as predicate names
    # Derived from BNF description of PDDL 3.1 (Kovacs)
    PDDL_RESERVED_KEYWORDS = {
        # Logical operators (Section 1.1 <GD>, <pre-GD>)
        "and", "or", "not", "imply",
        # Quantifiers (requires :existential-preconditions, :universal-preconditions)
        "exists", "forall",
        # Conditional effects
        "when",
        # Domain/Problem structure keywords
        "define", "domain", "problem",
        "requirements", "types", "constants", "predicates", "functions",
        "constraints", "action", "durative-action", "derived",
        # Action body keywords
        "parameters", "precondition", "effect", "duration", "condition",
        # Problem structure
        "objects", "init", "goal", "metric", "length",
        # Type keywords
        "either", "object", "number",
        # Numeric fluent operators (Section 1.1 <assign-op>)
        "assign", "scale-up", "scale-down", "increase", "decrease",
        # Temporal keywords (Section 1.1 <time-specifier>, <interval>)
        "at", "over", "start", "end", "all",
        # Trajectory constraint keywords (Section 1.2 <con-GD>)
        "always", "sometime", "within", "at-most-once",
        "sometime-after", "sometime-before", "always-within",
        "hold-during", "hold-after",
        # Metric keywords
        "minimize", "maximize", "total-time", "total-cost", "is-violated",
        # Preference keyword
        "preference",
        # Object fluent keywords
        "undefined",
    }

    # Map reserved keywords to appropriate predicate replacements
    # Add mappings for keywords commonly misused by LLMs
    KEYWORD_TO_PREDICATE = {
        "exists": "file_exists",  # Most common: LLM uses (exists ?f) meaning file existence
        "start": "is_started",  # LLM might use (start ?svc) for service state
        "end": "is_ended",  # LLM might use (end ?proc) for process state
        "increase": "is_increased",  # LLM might confuse with state predicate
        "decrease": "is_decreased",  # LLM might confuse with state predicate
        "all": "all_of",  # LLM might use as predicate
    }

    def _sanitize_predicate(self, predicate_str: str) -> Optional[str]:
        """
        Sanitize a predicate string to ensure all arguments are valid PDDL identifiers.
        Converts paths like /var/cache/apt to _var_cache_apt.
        Replaces reserved PDDL keywords used as predicate names.
        Rejects malformed constructs like infix operators and malformed quantifiers.
        Returns None if the predicate is irrecoverably malformed.
        """
        if not predicate_str or not isinstance(predicate_str, str):
            return None

        predicate_str = predicate_str.strip()

        # =================================================================
        # EARLY REJECTION: Detect malformed infix operators
        # LLMs sometimes generate "(pred1) or (pred2)" instead of "(or (pred1) (pred2))"
        # =================================================================

        # Pattern: ") or " or ") and " - indicates infix usage (INVALID)
        if re.search(r"\)\s+(or|and)\s+", predicate_str, re.IGNORECASE):
            # Try to extract just the first valid predicate
            match = re.match(r"^(\([^)]+\))", predicate_str)
            if match:
                # Recursively sanitize just the first predicate
                return self._sanitize_predicate(match.group(1))
            return None

        # Pattern: standalone "or" or "and" not at start (malformed)
        # e.g., "file_exists ?item or directory_exists ?item"
        if re.search(r"\s+(or|and)\s+", predicate_str, re.IGNORECASE):
            # Try to extract the first predicate-like segment
            parts = re.split(r"\s+(?:or|and)\s+", predicate_str, flags=re.IGNORECASE)
            if parts and parts[0].strip():
                first_part = parts[0].strip()
                # Ensure it has parentheses
                if not first_part.startswith("("):
                    first_part = f"({first_part})"
                if not first_part.endswith(")"):
                    first_part = f"{first_part})"
                return self._sanitize_predicate(first_part)
            return None

        # =================================================================
        # EARLY REJECTION: Detect malformed quantifier usage
        # LLMs sometimes try to use exists/forall as quantifiers but mangle the syntax
        # Since we use STRIPS (no :existential-preconditions), transform to simple predicate
        # =================================================================

        # Pattern: (exists ?var ...) or (forall ?var ...) - malformed quantifier
        # e.g., "(exists ?f id_- file)" or "(exists ?f)"
        quantifier_match = re.match(r"^\((?:not\s+)?\((exists|forall)\s+(\?\w+)", predicate_str, re.IGNORECASE)
        if quantifier_match:
            quantifier = quantifier_match.group(1).lower()
            var = quantifier_match.group(2)
            is_negated = predicate_str.strip().startswith("(not")

            # Transform to simple predicate: (exists ?f ...) -> (file_exists ?f)
            if quantifier == "exists":
                result = f"(file_exists {var})"
            else:  # forall - just reject, can't meaningfully transform
                return None

            if is_negated:
                result = f"(not {result})"
            return result

        # Also catch: (exists ?var) without proper structure
        simple_quantifier = re.match(r"^\((exists|forall)\s+(\?\w+)(?:\s+.*)?", predicate_str, re.IGNORECASE)
        if simple_quantifier:
            quantifier = simple_quantifier.group(1).lower()
            var = simple_quantifier.group(2)

            if quantifier == "exists":
                return f"(file_exists {var})"
            return None  # forall without body is meaningless

        # Handle negation wrapper
        is_negated = False
        inner = predicate_str
        if predicate_str.startswith("(not"):
            is_negated = True
            # Extract inner predicate: (not (pred args)) -> (pred args)
            match = re.match(r"\(not\s+(\([^)]+\))\s*\)", predicate_str)
            if match:
                inner = match.group(1)
            else:
                # Try simpler pattern
                inner = re.sub(r"^\(not\s+", "(", predicate_str)
                if inner.endswith("))"):
                    inner = inner[:-1]

        # Remove outer parentheses for processing
        inner = inner.strip()
        if inner.startswith("(") and inner.endswith(")"):
            inner = inner[1:-1].strip()

        # Split into predicate name and arguments
        parts = inner.split()
        if not parts:
            return None

        pred_name = parts[0]
        args = parts[1:] if len(parts) > 1 else []

        # Check for reserved PDDL keywords used as predicate names
        pred_name_lower = pred_name.lower()
        if pred_name_lower in self.PDDL_RESERVED_KEYWORDS:
            if pred_name_lower in self.KEYWORD_TO_PREDICATE:
                # Replace with appropriate predicate
                pred_name = self.KEYWORD_TO_PREDICATE[pred_name_lower]
            else:
                # Reject predicates using other reserved keywords
                return None

        # Sanitize predicate name
        pred_name = self._sanitize_pddl_identifier(pred_name)
        if not pred_name:
            return None

        # Reject if predicate name is a variable (starts with ?)
        # Variables can only be arguments, not predicate names
        if pred_name.startswith("?"):
            return None

        # Sanitize each argument
        # In PDDL actions, predicate arguments should be variables (?x) or typed constants
        # Bare words like "command", "dir", "file" are almost always meant to be variables
        sanitized_args = []
        for arg in args:
            # Keep variables as-is (start with ?)
            if arg.startswith("?"):
                sanitized_args.append(arg)
            else:
                # Check if this looks like a variable name missing the ? prefix
                # Common patterns: single words that could be parameter names
                arg_lower = arg.lower().strip()

                # Skip type annotations that got mixed in (e.g., "- file")
                if arg_lower.startswith("-") or arg_lower in [
                    "file", "directory", "package", "service", "user", "group",
                    "port", "process", "interface", "object", "configuration_file"
                ]:
                    # This looks like a type, not a variable - skip it
                    continue

                # If it's a simple word (letters/underscores), assume it should be a variable
                if re.match(r"^[a-zA-Z][a-zA-Z0-9_-]*$", arg):
                    # Convert to variable by prepending ?
                    sanitized_args.append(f"?{arg_lower}")
                else:
                    # Sanitize as identifier (for paths, etc.)
                    sanitized = self._sanitize_pddl_identifier(arg)
                    if sanitized:
                        # Even sanitized literals should probably be variables in actions
                        sanitized_args.append(f"?{sanitized}")
                    # Skip empty/invalid args

        # Reconstruct predicate
        if sanitized_args:
            result = f"({pred_name} {' '.join(sanitized_args)})"
        else:
            result = f"({pred_name})"

        if is_negated:
            result = f"(not {result})"

        return result

    def _sanitize_pddl_identifier(self, name: str) -> str:
        """
        Convert any string to a valid PDDL identifier.
        Handles paths, special characters, etc.
        """
        if not name:
            return ""

        # Replace path separators and other invalid characters with underscores
        sanitized = re.sub(r"[^a-zA-Z0-9_?-]", "_", str(name))

        # Remove leading underscores and collapse multiple underscores
        sanitized = re.sub(r"_+", "_", sanitized).strip("_")

        # Ensure doesn't start with a digit (unless it's a variable)
        if sanitized and not sanitized.startswith("?"):
            if sanitized[0].isdigit() or sanitized[0] == "_":
                sanitized = "obj_" + sanitized.lstrip("_")

        # Ensure it starts with a letter or ?
        if sanitized and not sanitized[0].isalpha() and not sanitized.startswith("?"):
            sanitized = "id_" + sanitized

        return sanitized.lower()

    def generate_problem(
            self,
            state: dict,
            goal_predicates: list[str],
            problem_name: str = "sysadmin-problem",
    ) -> str:
        """Generate PDDL problem file from current state."""
        lines = []

        # Header
        lines.append(f"(define (problem {problem_name})")
        lines.append(f"  (:domain {self.domain_name})")
        lines.append("")

        # Objects
        lines.append(self._generate_objects(state))
        lines.append("")

        # Initial state
        lines.append(self._generate_init(state))
        lines.append("")

        # Goal
        lines.append("  (:goal")
        lines.append("    (and")
        for pred in goal_predicates:
            lines.append(f"      {pred}")
        lines.append("    )")
        lines.append("  )")

        lines.append(")")

        return "\n".join(lines)

    def _generate_types(self, state: dict) -> str:
        """Generate PDDL type hierarchy."""
        lines = ["  (:types"]

        # Base types
        lines.append("    ; Base types")
        # lines.append("    object")
        lines.append("    ")

        # Filesystem hierarchy
        lines.append("    ; Filesystem types")
        lines.append("    filesystem_object - object")
        lines.append("    file directory - filesystem_object")
        lines.append("    configuration_file - file")
        lines.append("    ")

        # Execution types
        lines.append("    ; Execution types")
        lines.append("    service process - object")
        lines.append("    ")

        # Package types
        lines.append("    ; Package management types")
        lines.append("    package repository - object")
        lines.append("    ")

        # Access control types
        lines.append("    ; Access control types")
        lines.append("    user group - object")
        lines.append("    system_user human_user - user")
        lines.append("    ")

        # Network types
        lines.append("    ; Network types")
        lines.append("    port interface firewall_rule - object")

        lines.append("  )")

        return "\n".join(lines)

    def _generate_predicates(
            self, state: dict, actions: list[ActionSchema] = []
    ) -> str:
        """Generate PDDL predicates, avoiding duplicates and fixing arity."""
        lines = ["  (:predicates"]

        # Set to track names of predicates we have already defined
        defined_predicates = set()

        def add_line(text):
            lines.append(f"    {text}")
            match = re.search(r"\(\s*([^\s)]+)", text)
            if match:
                defined_predicates.add(match.group(1))

        # --- 1. Static/Hardcoded Predicates ---
        add_line("; Dynamic state predicates - Packages")
        add_line("(package_installed ?p - package)")
        add_line("(package_outdated ?p - package)")
        add_line("(package_configured ?p - package)")
        add_line("(vulnerable ?p - package)")

        add_line("; Dynamic state predicates - Services")
        add_line("(service_exists ?s - service)")
        add_line("(service_running ?s - service)")
        add_line("(service_enabled ?s - service)")
        add_line("(service_failed ?s - service)")
        add_line("(config_applied ?s - service)")

        add_line("; Dynamic state predicates - Filesystem")
        add_line("(file_exists ?f - filesystem_object)")
        add_line("(file_readable ?f - filesystem_object)")
        add_line("(file_writable ?f - filesystem_object)")
        add_line("(file_critical ?f - filesystem_object)")

        add_line("; Dynamic state predicates - Users")
        add_line("(user_exists ?u - user)")
        add_line("(user_critical ?u - user)")
        add_line("(user_locked ?u - user)")
        add_line("(can_escalate ?u - user)")

        add_line("; Dynamic state predicates - Groups")
        add_line("(group_exists ?g - group)")

        add_line("; Dynamic state predicates - Network")
        add_line("(port_open ?p - port)")
        add_line("(port_allowed ?p - port)")
        add_line("(interface_exists ?i - interface)")
        add_line("(interface_up ?i - interface)")

        add_line("; Dynamic state predicates - Firewall")
        add_line("(firewall_rule_exists ?r - firewall_rule)")
        add_line("(traffic_blocked ?r - firewall_rule)")

        add_line("; Dynamic state predicates - Processes")
        add_line("(process_running ?pr - process)")
        add_line("(executed_as_root ?pr - process)")

        add_line("; Static relationship predicates")
        add_line("(depends_on ?s - service ?p - package)")
        add_line("(configures ?f - configuration_file ?s - service)")
        add_line("(file_owned_by ?f - filesystem_object ?u - user)")
        add_line("(member_of ?u - user ?g - group)")

        add_line("; Environment predicates")
        add_line("(network_available)")
        add_line("(requires_env_preservation ?pr - process)")

        # --- 2. Dynamically Discovered Predicates ---
        lines.append("    ; Dynamically Discovered Predicates")

        # Invalid predicate names to filter out
        INVALID_PREDICATES = {
            "and",
            "or",
            "not",
            "exists",
            "forall",  # PDDL keywords
            "?policy",
            "?user",
            "?password",
            "?gid",
            "?value",
            "?shell",
            "?group",
            "?seuser",
            "",
            "?",
        }

        # Scan actions to determine arity (argument count)
        discovered_signatures = {}  # name -> int (arity)

        for action in actions:
            all_conditions = action.preconditions + action.effects
            for cond in all_conditions:
                # Sanitize the condition first
                sanitized_cond = (
                    self._sanitize_predicate(cond)
                    if hasattr(self, "_sanitize_predicate")
                    else cond
                )
                if not sanitized_cond:
                    continue

                clean = sanitized_cond.strip()
                if clean.startswith("(not"):
                    clean = clean[4:-1].strip()

                clean = clean.strip("()")
                parts = clean.split()
                if not parts:
                    continue

                pred_name = parts[0]

                # Skip invalid predicate names
                if pred_name in INVALID_PREDICATES:
                    continue
                if pred_name.startswith("?"):
                    continue
                if not pred_name or not pred_name[0].isalpha():
                    continue
                if not re.match(r"^[a-zA-Z][a-zA-Z0-9_-]*$", pred_name):
                    continue
                # Skip predicates that look like paths (even partially sanitized)
                if pred_name.startswith("_") or "__" in pred_name:
                    continue

                arity = len(parts) - 1

                if pred_name not in discovered_signatures:
                    discovered_signatures[pred_name] = arity

        # Add only valid predicates that haven't been defined yet
        for name, arity in discovered_signatures.items():
            if name in defined_predicates:
                continue

            # Generate generic arguments
            args = " ".join([f"?x{i} - object" for i in range(arity)])
            if args:
                lines.append(f"    ({name} {args})")
            else:
                lines.append(f"    ({name})")
            defined_predicates.add(name)

        lines.append("  )")
        return "\n".join(lines)

    def _generate_action(self, action: ActionSchema) -> str:
        """Generate PDDL action from schema."""
        lines = [f"  (:action {action.name}"]

        # Build parameters list
        params_list = [f"?{p.name} - {p.pddl_type.value}" for p in action.parameters]

        # Add ?actor parameter for actions requiring privilege
        if action.requires_root:
            params_list.insert(0, "?actor - user")

        params = " ".join(params_list)
        lines.append(f"    :parameters ({params})")

        # Collect valid variable names from parameters
        valid_vars = {f"?{p.name}" for p in action.parameters}
        if action.requires_root:
            valid_vars.add("?actor")

        # Preconditions - sanitize each one
        lines.append("    :precondition (and")
        for pre in action.preconditions:
            sanitized = self._sanitize_predicate(pre)
            if sanitized:
                lines.append(f"      {sanitized}")

        # Add root requirement if needed
        if action.requires_root:
            lines.append("      (can_escalate ?actor)")

        lines.append("    )")

        # Effects - sanitize each effect
        lines.append("    :effect (and")
        valid_effects = []
        for eff in action.effects:
            # First sanitize the predicate (handles paths)
            sanitized = self._sanitize_predicate(eff)
            if sanitized:
                # Then apply the existing effect sanitization
                final = self._sanitize_effect(sanitized)
                if final:
                    valid_effects.append(final)

        # Ensure at least one effect (PDDL requires non-empty effects)
        if not valid_effects:
            valid_effects.append(f"(action_completed_{action.name})")

        for eff in valid_effects:
            lines.append(f"      {eff}")
        lines.append("    )")

        lines.append("  )")

        return "\n".join(lines)

    def _generate_objects(self, state: dict) -> str:
        """Generate PDDL objects from extracted state."""
        lines = ["  (:objects"]

        # Check if using dynamic scoping (no limits needed)
        is_dynamic = (
                state.get("metadata", {}).get("scoping_method") == "anchor_propagate"
        )

        for pddl_type, objects in state.get("objects", {}).items():
            if objects:
                if is_dynamic:
                    # Dynamic scoping: already optimally filtered
                    selected_objects = objects
                else:
                    # Static scoping: apply legacy limits
                    limit = self.STATIC_OBJECT_LIMITS.get(pddl_type, 50)
                    selected_objects = objects[:limit]
                    if len(objects) > limit:
                        lines.append(
                            f"    ; ... truncated {len(objects) - limit} more {pddl_type}s"
                        )

                obj_names = " ".join(obj["name"] for obj in selected_objects)
                lines.append(f"    {obj_names} - {pddl_type}")

        lines.append("  )")

        return "\n".join(lines)

    def _generate_init(self, state: dict) -> str:
        """Generate initial state from extracted predicates."""
        lines = ["  (:init"]

        # Check scoping method
        is_dynamic = (
                state.get("metadata", {}).get("scoping_method") == "anchor_propagate"
        )

        # Build set of included object names
        included_objects = set()
        for pddl_type, objects in state.get("objects", {}).items():
            if is_dynamic:
                selected = objects
            else:
                limit = self.STATIC_OBJECT_LIMITS.get(pddl_type, 50)
                selected = objects[:limit]
            for obj in selected:
                included_objects.add(obj["name"])

        # Add predicates only for included objects
        for pred in state.get("predicates", []):
            if pred.get("value", True):
                args = pred.get("arguments", [])
                if all(arg in included_objects for arg in args):
                    args_str = " ".join(args)
                    lines.append(f"    ({pred['name']} {args_str})")

        # Add relationships (also filtered)
        for rel_type, relations in state.get("relationships", {}).items():
            for rel in relations:  # Reasonable limit for relationships
                if rel_type == "depends_on":
                    svc, pkg = rel.get("service"), rel.get("package")
                    if svc in included_objects and pkg in included_objects:
                        lines.append(f"    (depends_on {svc} {pkg})")
                elif rel_type == "configures":
                    cfg, svc = rel.get("config"), rel.get("service")
                    if cfg in included_objects and svc in included_objects:
                        lines.append(f"    (configures {cfg} {svc})")
                elif rel_type == "can_escalate":
                    user = rel.get("user")
                    if user in included_objects:
                        lines.append(f"    (can_escalate {user})")
                elif rel_type == "member_of":
                    user, group = rel.get("user"), rel.get("group")
                    if user in included_objects and group in included_objects:
                        lines.append(f"    (member_of {user} {group})")

        # Assume network available by default
        lines.append("    (network_available)")

        lines.append("  )")

        return "\n".join(lines)

    def _sanitize_effect(self, effect: str) -> Optional[str]:
        """
        Sanitize an effect string to ensure valid PDDL syntax.
        Returns None if the effect is irrecoverably malformed.
        """
        if not effect or not isinstance(effect, str):
            return None

        effect = effect.strip()

        # Remove invalid constructs that LLMs hallucinate
        # Pattern: "(pred) or (pred2)" or "(pred) and (pred2)"
        if " or " in effect.lower() or " and " in effect.lower():
            # Try to extract just the first valid predicate
            match = re.match(r"^\(([^)]+)\)", effect)
            if match:
                effect = f"({match.group(1)})"
            else:
                return None

        # Remove trailing garbage like "and (package_version ?pkg version)"
        # which is missing proper structure
        if re.search(r"\)\s+and\s+\(", effect, re.IGNORECASE):
            # Take only the first predicate
            match = re.match(r"^(\([^)]+\))", effect)
            if match:
                effect = match.group(1)
            else:
                return None

        # Ensure balanced parentheses
        if effect.count("(") != effect.count(")"):
            return None

        # Ensure it starts and ends with parentheses (or is negated)
        effect = effect.strip()
        if not (effect.startswith("(") and effect.endswith(")")):
            # Try to wrap it
            if not effect.startswith("("):
                effect = f"({effect})"
            if not effect.endswith(")"):
                effect = f"{effect})"

        # Validate predicate name is not a variable
        # Extract predicate name from effect (handle negation)
        if effect.startswith("(not"):
            # Extract inner predicate from (not (pred ...))
            match = re.match(r"\(not\s+\(([^\s)]+)", effect)
            if match:
                pred_name = match.group(1)
            else:
                return None
        else:
            # Extract from (pred ...)
            match = re.match(r"\(([^\s)]+)", effect)
            if match:
                pred_name = match.group(1)
            else:
                return None

        # Reject if predicate name is a variable or reserved keyword
        if pred_name.startswith("?") or pred_name.lower() in self.PDDL_RESERVED_KEYWORDS:
            return None

        return effect