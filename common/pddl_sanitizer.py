"""
common/pddl_sanitizer.py

Unified PDDL sanitization and repair logic shared between Phase 1 and Phase 2.
Combines the best of both phases' sanitization approaches.

This module handles:
- Reserved keyword detection and replacement
- Predicate sanitization (paths, variables, types)
- Effect sanitization
- Full PDDL repair (parenthesis balancing, type fixing, etc.)
"""

import re
from typing import Optional

from common.type_hierarchy import VALID_TYPES, TYPE_MAPPINGS


# =============================================================================
# PDDL Reserved Keywords
# Derived from BNF description of PDDL 3.1 (Daniel L. Kovacs)
# =============================================================================

PDDL_RESERVED_KEYWORDS: frozenset[str] = frozenset({
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
})


# Map reserved keywords to appropriate predicate replacements
KEYWORD_TO_PREDICATE: dict[str, str] = {
    "exists": "file_exists",  # Most common: LLM uses (exists ?f) meaning file existence
    "start": "is_started",
    "end": "is_ended",
    "increase": "is_increased",
    "decrease": "is_decreased",
    "all": "all_of",
}


# =============================================================================
# Identifier Sanitization
# =============================================================================

def sanitize_pddl_identifier(name: str) -> str:
    """
    Convert any string to a valid PDDL identifier.
    Handles paths, special characters, etc.
    
    Args:
        name: The raw identifier string
        
    Returns:
        A valid PDDL identifier
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


def sanitize_pddl_name(name: str) -> str:
    """
    Convert system names (like file paths) to valid PDDL object names.
    
    Args:
        name: System name (e.g., "/etc/passwd")
        
    Returns:
        Valid PDDL name (e.g., "etc_passwd")
    """
    if not name:
        return ""
    
    # Replace invalid characters with underscores
    sanitized = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
    
    # Ensure doesn't start with number
    if sanitized and sanitized[0].isdigit():
        sanitized = "obj_" + sanitized
    
    # Truncate if too long
    return sanitized.lower()[:100]


# =============================================================================
# Predicate Sanitization
# =============================================================================

def sanitize_predicate(predicate_str: str) -> Optional[str]:
    """
    Sanitize a predicate string to ensure valid PDDL syntax.
    
    Handles:
    - Infix operators (converts or removes)
    - Malformed quantifiers
    - Reserved keyword predicate names
    - Raw paths in arguments
    - Missing variable prefixes
    
    Args:
        predicate_str: The raw predicate string
        
    Returns:
        Sanitized predicate string, or None if irrecoverable
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
            return sanitize_predicate(match.group(1))
        return None
    
    # Pattern: standalone "or" or "and" not at start (malformed)
    if re.search(r"\s+(or|and)\s+", predicate_str, re.IGNORECASE):
        parts = re.split(r"\s+(?:or|and)\s+", predicate_str, flags=re.IGNORECASE)
        if parts and parts[0].strip():
            first_part = parts[0].strip()
            if not first_part.startswith("("):
                first_part = f"({first_part})"
            if not first_part.endswith(")"):
                first_part = f"{first_part})"
            return sanitize_predicate(first_part)
        return None
    
    # =================================================================
    # Handle malformed quantifier usage
    # =================================================================
    
    quantifier_match = re.match(
        r"^\((?:not\s+)?\((exists|forall)\s+(\?\w+)", 
        predicate_str, 
        re.IGNORECASE
    )
    if quantifier_match:
        quantifier = quantifier_match.group(1).lower()
        var = quantifier_match.group(2)
        is_negated = predicate_str.strip().startswith("(not")
        
        if quantifier == "exists":
            result = f"(file_exists {var})"
        else:  # forall - can't meaningfully transform
            return None
        
        if is_negated:
            result = f"(not {result})"
        return result
    
    # Simple quantifier pattern: (exists ?var)
    simple_quantifier = re.match(
        r"^\((exists|forall)\s+(\?\w+)(?:\s+.*)?", 
        predicate_str, 
        re.IGNORECASE
    )
    if simple_quantifier:
        quantifier = simple_quantifier.group(1).lower()
        var = simple_quantifier.group(2)
        
        if quantifier == "exists":
            return f"(file_exists {var})"
        return None
    
    # =================================================================
    # Handle negation wrapper
    # =================================================================
    
    is_negated = False
    inner = predicate_str
    
    if predicate_str.startswith("(not"):
        is_negated = True
        match = re.match(r"\(not\s+(\([^)]+\))\s*\)", predicate_str)
        if match:
            inner = match.group(1)
        else:
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
    
    # =================================================================
    # Check for reserved PDDL keywords used as predicate names
    # =================================================================
    
    pred_name_lower = pred_name.lower()
    if pred_name_lower in PDDL_RESERVED_KEYWORDS:
        if pred_name_lower in KEYWORD_TO_PREDICATE:
            pred_name = KEYWORD_TO_PREDICATE[pred_name_lower]
        else:
            return None
    
    # Sanitize predicate name
    pred_name = sanitize_pddl_identifier(pred_name)
    if not pred_name:
        return None
    
    # Reject if predicate name is a variable
    if pred_name.startswith("?"):
        return None
    
    # =================================================================
    # Sanitize arguments
    # =================================================================
    
    sanitized_args = []
    for arg in args:
        if arg.startswith("?"):
            # Keep variables as-is
            sanitized_args.append(arg)
        else:
            arg_lower = arg.lower().strip()
            
            # Skip type annotations that got mixed in
            if arg_lower.startswith("-") or arg_lower in VALID_TYPES:
                continue
            
            # If it's a simple word, assume it should be a variable
            if re.match(r"^[a-zA-Z][a-zA-Z0-9_-]*$", arg):
                sanitized_args.append(f"?{arg_lower}")
            else:
                # Sanitize as identifier
                sanitized = sanitize_pddl_identifier(arg)
                if sanitized:
                    sanitized_args.append(f"?{sanitized}")
    
    # Reconstruct predicate
    if sanitized_args:
        result = f"({pred_name} {' '.join(sanitized_args)})"
    else:
        result = f"({pred_name})"
    
    if is_negated:
        result = f"(not {result})"
    
    return result


def sanitize_effect(effect: str) -> Optional[str]:
    """
    Sanitize an effect string for PDDL validity.
    
    Args:
        effect: The raw effect string
        
    Returns:
        Sanitized effect string, or None if invalid
    """
    if not effect or not isinstance(effect, str):
        return None
    
    effect = effect.strip()
    
    # Remove invalid constructs like "(pred) or (pred2)"
    if " or " in effect.lower() or " and " in effect.lower():
        match = re.match(r"^\(([^)]+)\)", effect)
        if match:
            effect = f"({match.group(1)})"
        else:
            return None
    
    # Remove trailing garbage
    if re.search(r"\)\s+and\s+\(", effect, re.IGNORECASE):
        match = re.match(r"^(\([^)]+\))", effect)
        if match:
            effect = match.group(1)
        else:
            return None
    
    # Ensure balanced parentheses
    if effect.count("(") != effect.count(")"):
        return None
    
    # Ensure starts and ends with parentheses
    effect = effect.strip()
    if not (effect.startswith("(") and effect.endswith(")")):
        if not effect.startswith("("):
            effect = f"({effect})"
        if not effect.endswith(")"):
            effect = f"{effect})"
    
    # Validate predicate name
    if effect.startswith("(not"):
        match = re.match(r"\(not\s+\(([^\s)]+)", effect)
        if match:
            pred_name = match.group(1)
        else:
            return None
    else:
        match = re.match(r"\(([^\s)]+)", effect)
        if match:
            pred_name = match.group(1)
        else:
            return None
    
    # Reject if predicate name is a variable or reserved keyword
    if pred_name.startswith("?") or pred_name.lower() in PDDL_RESERVED_KEYWORDS:
        return None
    
    return effect


# =============================================================================
# Full PDDL Repair
# =============================================================================

class PDDLSanitizer:
    """
    Comprehensive PDDL sanitizer that combines Phase 1 and Phase 2 repair logic.
    """
    
    def __init__(self):
        self.repairs_made: list[str] = []
    
    def repair(self, pddl: str) -> str:
        """
        Apply all repairs to a PDDL string.
        
        Args:
            pddl: The raw PDDL string
            
        Returns:
            Repaired PDDL string
        """
        self.repairs_made = []
        
        # Apply repairs in order
        pddl = self._fix_invalid_types(pddl)
        pddl = self._fix_unbound_variables(pddl)
        pddl = self._fix_invalid_quantifiers(pddl)
        pddl = self._fix_string_literals(pddl)
        pddl = self._fix_function_calls(pddl)
        pddl = self._fix_empty_and_blocks(pddl)
        pddl = self._fix_parentheses(pddl)
        
        return pddl
    
    def _fix_invalid_types(self, pddl: str) -> str:
        """Replace invalid types with valid ones."""
        # Apply explicit mappings
        for bad_type, good_type in TYPE_MAPPINGS.items():
            pattern = rf"(\?[\w-]+\s*-\s*){bad_type}\b"
            if re.search(pattern, pddl):
                pddl = re.sub(pattern, rf"\1{good_type}", pddl)
                self.repairs_made.append(f"Mapped type '{bad_type}' -> '{good_type}'")
        
        # Catch-all: Replace unknown types with 'object'
        def replace_unknown(match):
            prefix = match.group(1)
            t = match.group(2)
            if t not in VALID_TYPES:
                self.repairs_made.append(f"Replaced unknown type '{t}' with 'object'")
                return f"{prefix}object"
            return match.group(0)
        
        pddl = re.sub(r"(\?[\w-]+\s*-\s*)([\w-]+)", replace_unknown, pddl)
        return pddl
    
    def _fix_unbound_variables(self, pddl: str) -> str:
        """Fix actions where variables are used but not declared in parameters."""
        action_pattern = (
            r"\(:action\s+(\w+)\s*(:parameters\s*\((.*?)\))?(.*?)(?=\(:action|\Z)"
        )
        
        def fix_action_params(match):
            action_name = match.group(1)
            existing_params_str = match.group(3) or ""
            body = match.group(4)
            
            # Parse existing parameters
            existing_vars = set()
            if existing_params_str:
                existing_vars = set(re.findall(r"\?(\w+)", existing_params_str))
            
            # Find all variables used in body
            used_vars = set(re.findall(r"\?(\w+)", body))
            
            # Identify missing variables
            missing_vars = used_vars - existing_vars
            
            if missing_vars:
                new_params = []
                for var in sorted(missing_vars):
                    inferred_type = self._infer_type_from_context(var, body)
                    new_params.append(f"?{var} - {inferred_type}")
                    self.repairs_made.append(
                        f"Added unbound var '?{var}' to action '{action_name}'"
                    )
                
                current_params = existing_params_str.strip()
                added_params = " ".join(new_params)
                if current_params:
                    final_params = f"{current_params} {added_params}"
                else:
                    final_params = added_params
                
                return f"(:action {action_name}\n    :parameters ({final_params}){body}"
            
            return match.group(0)
        
        return re.sub(action_pattern, fix_action_params, pddl, flags=re.DOTALL)
    
    def _infer_type_from_context(self, var: str, context: str) -> str:
        """Infer PDDL type from variable name and usage context."""
        var_lower = var.lower()
        
        # Common naming conventions
        type_hints = {
            "p": "package", "pkg": "package", "package": "package",
            "s": "service", "svc": "service", "service": "service",
            "u": "user", "user": "user",
            "g": "group", "group": "group",
            "f": "file", "file": "file", "src": "file", "dst": "file",
            "d": "directory", "dir": "directory", "directory": "directory",
            "r": "repository", "repo": "repository",
            "i": "interface", "iface": "interface", "interface": "interface",
            "port": "port",
            "rule": "firewall_rule", "chain": "firewall_rule",
            "proc": "process", "process": "process", "cmd": "process",
            "cfg": "configuration_file", "config": "configuration_file",
        }
        
        for hint, pddl_type in type_hints.items():
            if var_lower.startswith(hint) or var_lower.endswith(hint):
                return pddl_type
        
        # Check context for predicate usage
        if re.search(rf"installed\s+\?{var}", context):
            return "package"
        if re.search(rf"running\s+\?{var}", context):
            return "service"
        if re.search(rf"exists\s+\?{var}", context):
            return "file"
        
        return "object"
    
    def _fix_invalid_quantifiers(self, pddl: str) -> str:
        """Fix invalid quantifier syntax."""
        pattern = r"\(\s*\?\w+\s*:exists\s*\([^)]+\)\s*\)"
        
        def fix_quantifier(match):
            text = match.group(0)
            var_match = re.search(r"\?(\w+)\s*:exists", text)
            pred_match = re.search(r":exists\s*(\([^)]+\))", text)
            
            if var_match and pred_match:
                var = var_match.group(1)
                pred = pred_match.group(1)
                self.repairs_made.append(f"Fixed quantifier syntax for ?{var}")
                return f"(exists (?{var} - object) {pred})"
            return text
        
        return re.sub(pattern, fix_quantifier, pddl)
    
    def _fix_string_literals(self, pddl: str) -> str:
        """Remove string literal comparisons."""
        pattern = r'\(equal\s+\?\w+\s+"[^"]+"\)'
        
        matches = re.findall(pattern, pddl)
        for match in matches:
            pddl = pddl.replace(match, "")
            self.repairs_made.append(f"Removed invalid string comparison: {match}")
        
        return pddl
    
    def _fix_function_calls(self, pddl: str) -> str:
        """Remove function calls from effects."""
        invalid_patterns = [
            r"\(create_process\s+[^)]+\)",
            r"\(concat\s+[^)]+\)",
            r"\(strcat\s+[^)]+\)",
            r"\(find_newest_version\s+[^)]+\)",
            r"\(name\s+\?\w+\)",
            r"\(version_number\s+[^)]+\)",
            r"\(time_spent_\w+\)",
        ]
        
        for pattern in invalid_patterns:
            matches = re.findall(pattern, pddl)
            for match in matches:
                pddl = pddl.replace(match, "")
                self.repairs_made.append(f"Removed invalid function call: {match[:50]}")
        
        return pddl
    
    def _fix_empty_and_blocks(self, pddl: str) -> str:
        """Fix empty (and) blocks."""
        pddl = re.sub(r":effect\s*\(and\s*\)", ":effect (and)", pddl)
        pddl = re.sub(r":precondition\s*\(and\s*\)", ":precondition (and)", pddl)
        # Remove empty () pairs but preserve :parameters () which is valid PDDL
        pddl = re.sub(r":parameters\s*\(\s*\)", ":parameters (_EMPTY_PARAMS_)", pddl)
        pddl = re.sub(r"\(\s*\)", "", pddl)
        pddl = pddl.replace(":parameters (_EMPTY_PARAMS_)", ":parameters ()")
        pddl = re.sub(r"\(\s*\(and", "(and", pddl)
        return pddl
    
    def _fix_parentheses(self, pddl: str) -> str:
        """Balance parentheses."""
        open_count = pddl.count("(")
        close_count = pddl.count(")")
        
        if open_count > close_count:
            pddl += ")" * (open_count - close_count)
            self.repairs_made.append(
                f"Added {open_count - close_count} closing parentheses"
            )
        elif close_count > open_count:
            excess = close_count - open_count
            for _ in range(excess):
                last_paren = pddl.rfind(")")
                if last_paren > 0:
                    pddl = pddl[:last_paren] + pddl[last_paren + 1:]
            self.repairs_made.append(f"Removed {excess} excess closing parentheses")
        
        return pddl
    
    def get_repairs_log(self) -> list[str]:
        """Get the list of repairs made."""
        return self.repairs_made


# =============================================================================
# Convenience Functions
# =============================================================================

def repair_pddl(pddl: str) -> str:
    """
    Convenience function to repair PDDL without instantiating class.
    
    Args:
        pddl: Raw PDDL string
        
    Returns:
        Repaired PDDL string
    """
    sanitizer = PDDLSanitizer()
    return sanitizer.repair(pddl)
