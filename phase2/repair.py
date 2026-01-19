import re
import tempfile
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("Phase2.Repair")


class PDDLRepairer:
    """
    Repairs common LLM-generated PDDL syntax errors.
    Applied before merge phase to ensure valid input.
    """

    # Valid base types in our domain
    VALID_TYPES = {
        "object",
        "package",
        "service",
        "user",
        "group",
        "file",
        "directory",
        "configuration_file",
        "port",
        "interface",
        "firewall_rule",
        "process",
        "repository",
        "filesystem_object",
        "system_user",
        "human_user",
    }

    # Map hallucinated types to valid ones
    TYPE_MAPPINGS = {
        "FirewallRule": "firewall_rule",
        "Interface": "interface",
        "Port": "port",
        "Repository": "repository",
        "Package": "package",
        "Service": "service",
        "User": "user",
        "Group": "group",
        "File": "file",
        "Directory": "directory",
        "Timestamp": "object",  # Simplify complex types to object
        "Permission": "object",
        "Owner": "user",
        "ACL": "object",
        "boolean": "object",
        "string": "object",
        "_user": "user",
        "_group": "group",
    }

    def __init__(self):
        self.repairs_made: list[str] = []

    def repair(self, pddl: str) -> str:
        """Apply all repairs to PDDL string."""
        self.repairs_made = []

        # Apply repairs in order
        pddl = self._fix_invalid_types(pddl)
        pddl = self._fix_unbound_variables(pddl)  # Renamed for clarity
        pddl = self._fix_invalid_quantifiers(pddl)
        pddl = self._fix_string_literals(pddl)
        pddl = self._fix_function_calls(pddl)
        pddl = self._fix_empty_and_blocks(pddl)
        pddl = self._extract_implicit_predicates(pddl)
        pddl = self._fix_parentheses(pddl)

        return pddl

    def _fix_invalid_types(self, pddl: str) -> str:
        """Replace invalid types like 'string', 'FirewallRule' with valid ones."""

        # 1. Apply explicit mappings
        for bad_type, good_type in self.TYPE_MAPPINGS.items():
            # Regex matches "?param - BadType"
            pattern = rf"(\?[\w-]+\s*-\s*){bad_type}\b"
            if re.search(pattern, pddl):
                pddl = re.sub(pattern, rf"\1{good_type}", pddl)
                self.repairs_made.append(f"Mapped type '{bad_type}' -> '{good_type}'")

        # 2. Catch-all: Replace unknown types with 'object'
        # This prevents the domain from crashing due to any other hallucinations
        def replace_unknown(match):
            prefix = match.group(1)
            t = match.group(2)
            if t not in self.VALID_TYPES:
                self.repairs_made.append(f"Replaced unknown type '{t}' with 'object'")
                return f"{prefix}object"
            return match.group(0)

        pddl = re.sub(r"(\?[\w-]+\s*-\s*)([\w-]+)", replace_unknown, pddl)
        return pddl

    def _fix_unbound_variables(self, pddl: str) -> str:
        """Fix actions where variables are used in effects but not parameters."""
        # Find actions
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

                # Reconstruct parameters string
                current_params = existing_params_str.strip()
                added_params = " ".join(new_params)
                if current_params:
                    final_params = f"{current_params} {added_params}"
                else:
                    final_params = added_params

                return f"(:action {action_name}\n    :parameters ({final_params}){body}"

            return match.group(0)

        return re.sub(action_pattern, fix_action_params, pddl, flags=re.DOTALL)

    def _fix_unbound_parameters(self, pddl: str) -> str:
        """Fix actions with empty parameters but used variables."""
        # Find actions with empty parameters
        action_pattern = (
            r"\(:action\s+(\w+)\s*:parameters\s*\(\s*\)(.*?)(?=\(:action|\Z)"
        )

        def fix_action(match):
            action_name = match.group(1)
            body = match.group(2)

            # Find all variables used in preconditions/effects
            vars_used = set(re.findall(r"\?(\w+)", body))

            if vars_used:
                # Infer types from predicate usage
                params = []
                for var in sorted(vars_used):
                    inferred_type = self._infer_type_from_context(var, body)
                    params.append(f"?{var} - {inferred_type}")

                params_str = " ".join(params)
                self.repairs_made.append(
                    f"Added parameters to action '{action_name}': {params_str}"
                )
                return f"(:action {action_name}\n    :parameters ({params_str}){body}"

            return match.group(0)

        return re.sub(action_pattern, fix_action, pddl, flags=re.DOTALL)

    def _infer_type_from_context(self, var: str, context: str) -> str:
        """Infer PDDL type from variable name and usage context."""
        var_lower = var.lower()

        # Common naming conventions
        type_hints = {
            "p": "package",
            "pkg": "package",
            "package": "package",
            "s": "service",
            "svc": "service",
            "service": "service",
            "u": "user",
            "user": "user",
            "g": "group",
            "group": "group",
            "f": "file",
            "file": "file",
            "src": "file",
            "dst": "file",
            "d": "directory",
            "dir": "directory",
            "directory": "directory",
            "r": "repository",
            "repo": "repository",
            "i": "interface",
            "iface": "interface",
            "interface": "interface",
            "port": "port",
            "rule": "firewall_rule",
            "chain": "firewall_rule",
            "proc": "process",
            "process": "process",
            "cmd": "process",
            "cfg": "configuration_file",
            "config": "configuration_file",
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

        return "object"  # Default fallback

    def _fix_invalid_quantifiers(self, pddl: str) -> str:
        """Fix invalid quantifier syntax like '?p :exists'."""
        # Pattern: (?var :exists (predicate))
        pattern = r"\(\s*\?\w+\s*:exists\s*\([^)]+\)\s*\)"

        def fix_quantifier(match):
            text = match.group(0)
            # Extract variable and predicate
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
        # Pattern: (equal ?var "string")
        pattern = r'\(equal\s+\?\w+\s+"[^"]+"\)'

        matches = re.findall(pattern, pddl)
        for match in matches:
            pddl = pddl.replace(match, "")
            self.repairs_made.append(f"Removed invalid string comparison: {match}")

        return pddl

    def _fix_function_calls(self, pddl: str) -> str:
        """Remove function calls from effects."""
        # Patterns for common invalid constructs
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
        """Fix empty (and) blocks and malformed nested structures."""
        # Remove empty effects/preconditions
        pddl = re.sub(r":effect\s*\(and\s*\)", ":effect (and)", pddl)
        pddl = re.sub(r":precondition\s*\(and\s*\)", ":precondition (and)", pddl)

        # Fix orphaned parentheses from removed content
        # Pattern: (and (valid) () (valid))
        pddl = re.sub(r"\(\s*\)", "", pddl)

        # Fix double (( )) that might result from removals
        pddl = re.sub(r"\(\s*\(and", "(and", pddl)

        return pddl

    def _extract_implicit_predicates(self, pddl: str) -> str:
        """Extract predicates that are used but not declared."""
        # Find all predicate usages in actions
        pred_usage = set()

        # Pattern: (predicate_name ?var ...) but not (:action, :parameters, etc.
        pattern = r"\((\w+)\s+\?[\w\s?-]+\)"

        for match in re.finditer(pattern, pddl):
            pred_name = match.group(1)
            if pred_name not in [
                "and",
                "or",
                "not",
                "exists",
                "forall",
                "action",
                "parameters",
                "precondition",
                "effect",
                "types",
                "predicates",
            ]:
                pred_usage.add(pred_name)

        # Check if predicates section exists
        if "(:predicates" not in pddl:
            # Generate predicates section from usage
            pred_lines = []
            for pred in sorted(pred_usage):
                # Infer arity from usage
                usage_match = re.search(rf"\({pred}\s+([\?\w\s-]+)\)", pddl)
                if usage_match:
                    params = usage_match.group(1).strip()
                    pred_lines.append(f"    ({pred} {params})")

            if pred_lines:
                pred_section = "  (:predicates\n" + "\n".join(pred_lines) + "\n  )\n"
                # Insert after types
                pddl = re.sub(r"(\(:types[^)]+\)\s*)", rf"\1\n{pred_section}", pddl)
                self.repairs_made.append(
                    f"Generated {len(pred_lines)} implicit predicates"
                )

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
            # Remove excess closing parens from end
            excess = close_count - open_count
            for _ in range(excess):
                last_paren = pddl.rfind(")")
                if last_paren > 0:
                    pddl = pddl[:last_paren] + pddl[last_paren + 1:]
            self.repairs_made.append(f"Removed {excess} excess closing parentheses")

        return pddl

    def get_repairs_log(self) -> list[str]:
        return self.repairs_made


class PDDLValidator:
    """
    Validates PDDL syntax and semantic correctness using the pddl library.

    Uses the pddl Python package (https://github.com/AI-Planning/pddl) for parsing
    and validation instead of external tools like VAL.
    """

    def __init__(self):
        self._pddl_available = self._check_pddl_library()

    def _check_pddl_library(self) -> bool:
        """Check if the pddl library is available."""
        try:
            from pddl import parse_domain
            return True
        except ImportError:
            logger.warning(
                "pddl library not available. Install with: pip install pddl"
            )
            return False

    def validate_domain(self, domain_pddl: str) -> tuple[bool, list[str]]:
        """
        Validate a PDDL domain string.

        Returns:
            tuple: (is_valid: bool, messages: list[str])
        """
        errors = []
        warnings = []

        # Basic structural validation (fast checks before parsing)
        structural_errors = self._structural_validation(domain_pddl)
        if structural_errors:
            errors.extend(structural_errors)

        # Check parenthesis balance
        if domain_pddl.count("(") != domain_pddl.count(")"):
            errors.append(
                f"Unbalanced parentheses: {domain_pddl.count('(')} open, "
                f"{domain_pddl.count(')')} close"
            )

        # Check action structure
        action_warnings = self._validate_actions_structure(domain_pddl)
        warnings.extend(action_warnings)

        # Use pddl library for full validation if available and no critical errors
        if self._pddl_available and not errors:
            pddl_errors = self._validate_with_pddl_library(domain_pddl)
            errors.extend(pddl_errors)

        return len(errors) == 0, errors + warnings

    def _structural_validation(self, domain_pddl: str) -> list[str]:
        """Perform basic structural validation."""
        errors = []

        if "(define (domain" not in domain_pddl:
            errors.append("Missing (define (domain ...))")

        # Check required sections
        required = [":types", ":predicates"]
        for req in required:
            if f"({req}" not in domain_pddl:
                errors.append(f"Missing {req} section")

        return errors

    def _validate_actions_structure(self, domain_pddl: str) -> list[str]:
        """Validate action structure and return warnings."""
        warnings = []

        action_pattern = r":action\s+(\w+)"
        actions = re.findall(action_pattern, domain_pddl)

        for action in actions:
            action_text = self._extract_action_text(domain_pddl, action)
            if action_text:
                if ":parameters" not in action_text:
                    warnings.append(f"Action '{action}' missing :parameters")
                if ":precondition" not in action_text:
                    warnings.append(f"Action '{action}' missing :precondition")
                if ":effect" not in action_text:
                    warnings.append(f"Action '{action}' missing :effect")

        return warnings

    def _extract_action_text(self, pddl: str, action_name: str) -> Optional[str]:
        """Extract the text of a specific action."""
        pattern = rf"\(:action\s+{action_name}\s*(.*?)(?=\(:action|\Z)"
        match = re.search(pattern, pddl, re.DOTALL)
        return match.group(1) if match else None

    def _validate_with_pddl_library(self, domain_pddl: str) -> list[str]:
        """
        Validate using the pddl library parser.

        This provides full PDDL 3.1 syntax validation.
        """
        errors = []
        temp_path = None

        try:
            from pddl import parse_domain

            # The pddl library parses from file, so write to temp file
            with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".pddl", delete=False
            ) as f:
                f.write(domain_pddl)
                temp_path = f.name

            # Attempt to parse the domain
            try:
                parsed_domain = parse_domain(temp_path)
                logger.debug(f"Successfully parsed domain: {parsed_domain.name}")

                # Additional semantic checks after successful parse
                semantic_errors = self._semantic_validation(parsed_domain)
                errors.extend(semantic_errors)

            except Exception as parse_error:
                # Extract useful error message from parsing exception
                error_msg = str(parse_error)
                # Clean up the error message for readability
                if "unexpected" in error_msg.lower():
                    errors.append(f"PDDL Parse Error: {error_msg}")
                elif "expected" in error_msg.lower():
                    errors.append(f"PDDL Syntax Error: {error_msg}")
                else:
                    errors.append(f"PDDL Validation Error: {error_msg}")

        except ImportError:
            logger.warning("pddl library not available for validation")
        except Exception as e:
            logger.error(f"Unexpected validation error: {e}")
        finally:
            # Clean up temp file
            if temp_path:
                try:
                    Path(temp_path).unlink()
                except Exception:
                    pass

        return errors

    def _semantic_validation(self, parsed_domain) -> list[str]:
        """
        Perform semantic validation on a successfully parsed domain.

        Args:
            parsed_domain: A pddl.core.Domain object

        Returns:
            list of semantic error/warning messages
        """
        errors = []

        try:
            # Check that all actions have valid parameters
            for action in parsed_domain.actions:
                # Check for duplicate parameter names
                param_names = [str(p.name) for p in action.parameters]
                if len(param_names) != len(set(param_names)):
                    errors.append(
                        f"Action '{action.name}' has duplicate parameter names"
                    )

            # Check for empty predicates section
            if not parsed_domain.predicates:
                errors.append("Domain has no predicates defined")

        except Exception as e:
            logger.debug(f"Semantic validation check failed: {e}")

        return errors

    def validate_problem(self, problem_pddl: str, domain_pddl: str = None) -> tuple[bool, list[str]]:
        """
        Validate a PDDL problem string.

        Args:
            problem_pddl: The problem PDDL string
            domain_pddl: Optional domain PDDL string for cross-validation

        Returns:
            tuple: (is_valid: bool, messages: list[str])
        """
        errors = []
        temp_problem_path = None
        temp_domain_path = None

        # Basic structural checks
        if "(define (problem" not in problem_pddl:
            errors.append("Missing (define (problem ...))")

        if "(:domain" not in problem_pddl:
            errors.append("Missing (:domain ...) reference")

        if "(:init" not in problem_pddl:
            errors.append("Missing (:init ...) section")

        if "(:goal" not in problem_pddl:
            errors.append("Missing (:goal ...) section")

        if not self._pddl_available:
            return len(errors) == 0, errors

        try:
            from pddl import parse_problem, parse_domain

            # Write problem to temp file
            with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".pddl", delete=False
            ) as f:
                f.write(problem_pddl)
                temp_problem_path = f.name

            # Write domain to temp file if provided
            if domain_pddl:
                with tempfile.NamedTemporaryFile(
                        mode="w", suffix=".pddl", delete=False
                ) as f:
                    f.write(domain_pddl)
                    temp_domain_path = f.name

            # Parse and validate
            try:
                parsed_problem = parse_problem(temp_problem_path)
                logger.debug(f"Successfully parsed problem: {parsed_problem.name}")
            except Exception as parse_error:
                errors.append(f"PDDL Problem Parse Error: {parse_error}")

        except ImportError:
            pass
        except Exception as e:
            logger.error(f"Problem validation error: {e}")
        finally:
            # Clean up temp files
            for path in [temp_problem_path, temp_domain_path]:
                if path:
                    try:
                        Path(path).unlink()
                    except Exception:
                        pass

        return len(errors) == 0, errors


class PDDLLibraryHelper:
    """
    Helper class for working with the pddl library programmatically.

    Provides utilities for building and manipulating PDDL domains
    using the pddl library's object model.
    """

    def __init__(self):
        self._available = self._check_availability()

    def _check_availability(self) -> bool:
        """Check if pddl library components are available."""
        try:
            from pddl.core import Domain
            from pddl.logic import Predicate, variables
            from pddl.action import Action
            return True
        except ImportError:
            return False

    @property
    def available(self) -> bool:
        return self._available

    def parse_domain_string(self, pddl_string: str):
        """
        Parse a PDDL domain string and return a Domain object.

        Args:
            pddl_string: PDDL domain as string

        Returns:
            pddl.core.Domain object or None if parsing fails
        """
        if not self._available:
            return None

        temp_path = None
        try:
            from pddl import parse_domain

            with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".pddl", delete=False
            ) as f:
                f.write(pddl_string)
                temp_path = f.name

            return parse_domain(temp_path)

        except Exception as e:
            logger.error(f"Failed to parse domain: {e}")
            return None
        finally:
            if temp_path:
                try:
                    Path(temp_path).unlink()
                except Exception:
                    pass

    def domain_to_string(self, domain) -> str:
        """
        Convert a pddl Domain object back to string representation.

        Args:
            domain: pddl.core.Domain object

        Returns:
            PDDL string representation
        """
        if domain is None:
            return ""
        return str(domain)

    def extract_predicates(self, domain) -> list[tuple[str, list[tuple[str, str]]]]:
        """
        Extract predicate definitions from a parsed domain.

        Returns:
            List of (name, [(param_name, param_type), ...]) tuples
        """
        if domain is None:
            return []

        predicates = []
        try:
            for pred in domain.predicates:
                name = str(pred.name)
                params = []
                for term in pred.terms:
                    param_name = str(term.name) if hasattr(term, 'name') else str(term)
                    param_type = str(term.type_tags[0]) if term.type_tags else "object"
                    params.append((param_name, param_type))
                predicates.append((name, params))
        except Exception as e:
            logger.debug(f"Error extracting predicates: {e}")

        return predicates

    def extract_actions(self, domain) -> list[str]:
        """
        Extract action names from a parsed domain.

        Returns:
            List of action names
        """
        if domain is None:
            return []

        try:
            return [str(action.name) for action in domain.actions]
        except Exception as e:
            logger.debug(f"Error extracting actions: {e}")
            return []

    def extract_types(self, domain) -> dict[str, Optional[str]]:
        """
        Extract type hierarchy from a parsed domain.

        Returns:
            Dict mapping type name to parent type (or None for base types)
        """
        if domain is None:
            return {}

        types = {}
        try:
            for type_name, parent in domain.types.items():
                types[str(type_name)] = str(parent) if parent else None
        except Exception as e:
            logger.debug(f"Error extracting types: {e}")

        return types