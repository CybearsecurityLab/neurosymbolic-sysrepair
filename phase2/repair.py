"""
phase2/repair.py

PDDL validation and repair utilities for Phase 2.
Uses the shared common.pddl_sanitizer for repair logic.
"""

import logging
import tempfile
import re
from pathlib import Path
from typing import Optional
import sys
import os

# Add parent directory to path for common imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.pddl_sanitizer import PDDLSanitizer, PDDL_RESERVED_KEYWORDS
from common.type_hierarchy import VALID_TYPES

logger = logging.getLogger("Phase2.Repair")


class PDDLValidator:
    """
    Validates PDDL syntax and semantics.
    Uses external VAL tool if available, falls back to heuristic checks.
    """

    def __init__(self):
        self._val_available = self._check_val()
        self._pddl_lib_available = self._check_pddl_library()
        self.sanitizer = PDDLSanitizer()

    def _check_val(self) -> bool:
        """Check if VAL parser is available."""
        try:
            import subprocess

            result = subprocess.run(
                ["Parser", "-h"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode in [0, 1]  # VAL returns 1 for -h
        except Exception:
            return False

    def _check_pddl_library(self) -> bool:
        """Check if the pddl Python library is available."""
        try:
            from pddl import parse_domain

            return True
        except ImportError:
            return False

    def is_available(self) -> bool:
        """Check if any validation method is available."""
        return self._val_available or self._pddl_lib_available

    def validate_domain(self, pddl: str) -> tuple[bool, list[str]]:
        """
        Validate a PDDL domain.

        Args:
            pddl: PDDL domain string

        Returns:
            Tuple of (is_valid, list of error messages)
        """
        errors = []

        # Basic structural checks
        structural_errors = self._check_structure(pddl)
        errors.extend(structural_errors)

        # Type checks
        type_errors = self._check_types(pddl)
        errors.extend(type_errors)

        # Predicate checks
        pred_errors = self._check_predicates(pddl)
        errors.extend(pred_errors)

        # Action checks
        action_errors = self._check_actions(pddl)
        errors.extend(action_errors)

        # Use external validator if available
        if self._pddl_lib_available and not errors:
            lib_errors = self._validate_with_pddl_library(pddl)
            errors.extend(lib_errors)
        elif self._val_available and not errors:
            val_errors = self._validate_with_val(pddl)
            errors.extend(val_errors)

        return len(errors) == 0, errors

    def _check_structure(self, pddl: str) -> list[str]:
        """Check basic PDDL structure."""
        errors = []

        # Check parentheses balance
        if pddl.count("(") != pddl.count(")"):
            diff = pddl.count("(") - pddl.count(")")
            if diff > 0:
                errors.append(f"Missing {diff} closing parentheses")
            else:
                errors.append(f"Extra {-diff} closing parentheses")

        # Check for domain definition
        if "(define (domain" not in pddl:
            errors.append("Missing domain definition")

        # Check for required sections
        if "(:requirements" not in pddl:
            errors.append("Missing :requirements section")

        if "(:types" not in pddl:
            errors.append("Missing :types section")

        if "(:predicates" not in pddl:
            errors.append("Missing :predicates section")

        return errors

    def _check_types(self, pddl: str) -> list[str]:
        """Check type definitions."""
        errors = []

        # Extract types section
        types_match = re.search(r"\(:types\s*(.*?)\)", pddl, re.DOTALL)
        if not types_match:
            return errors

        types_content = types_match.group(1)

        # Check for circular inheritance
        type_parents = {}
        for line in types_content.split("\n"):
            if " - " in line:
                parts = line.split(" - ")
                parent = parts[-1].strip()
                children = parts[0].strip().split()
                for child in children:
                    child = child.strip()
                    if child and not child.startswith(";"):
                        type_parents[child] = parent

        # Check for cycles
        for t in type_parents:
            visited = {t}
            current = type_parents.get(t)
            while current:
                if current in visited:
                    errors.append(f"Circular type inheritance detected: {t} -> {current}")
                    break
                visited.add(current)
                current = type_parents.get(current)

        return errors

    def _check_predicates(self, pddl: str) -> list[str]:
        """Check predicate definitions."""
        errors = []

        # Extract predicates section using balanced parenthesis matching
        pred_start = pddl.find("(:predicates")
        if pred_start == -1:
            return errors

        # Find the closing paren for the predicates section
        depth = 0
        pred_end = -1
        for i in range(pred_start, len(pddl)):
            if pddl[i] == '(':
                depth += 1
            elif pddl[i] == ')':
                depth -= 1
                if depth == 0:
                    pred_end = i + 1
                    break

        if pred_end == -1:
            return errors

        pred_section = pddl[pred_start:pred_end]

        # Extract individual predicate definitions
        # Match predicates like: (predicate_name ?arg1 - type1 ?arg2 - type2)
        pred_pattern = r"\(([a-zA-Z_][\w-]*)\s*(?:\?[\w-]+\s*-\s*[\w-]+\s*)*\)"

        for match in re.finditer(pred_pattern, pred_section):
            pred_name = match.group(1)
            # Skip if it's the "predicates" keyword itself
            if pred_name == "predicates":
                continue
            if pred_name in PDDL_RESERVED_KEYWORDS:
                errors.append(
                    f"Predicate '{pred_name}' uses reserved PDDL keyword"
                )

        return errors

    def _check_actions(self, pddl: str) -> list[str]:
        """Check action definitions."""
        errors = []

        # Find all actions
        action_pattern = r"\(:action\s+(\w+)(.*?)(?=\(:action|\)$)"
        for match in re.finditer(action_pattern, pddl, re.DOTALL):
            action_name = match.group(1)
            action_body = match.group(2)

            # Check for parameters section
            if ":parameters" not in action_body:
                errors.append(f"Action '{action_name}' missing :parameters")

            # Check for precondition section
            if ":precondition" not in action_body:
                errors.append(f"Action '{action_name}' missing :precondition")

            # Check for effect section
            if ":effect" not in action_body:
                errors.append(f"Action '{action_name}' missing :effect")

            # Extract declared parameters
            params_match = re.search(r":parameters\s*\((.*?)\)", action_body, re.DOTALL)
            if params_match:
                params_str = params_match.group(1)
                declared_vars = set(re.findall(r"\?(\w+)", params_str))

                # Find used variables in preconditions and effects
                cond_match = re.search(
                    r":precondition\s*\(.*?\)\s*:effect\s*\(.*?\)",
                    action_body,
                    re.DOTALL,
                )
                if cond_match:
                    cond_str = cond_match.group(0)
                    used_vars = set(re.findall(r"\?(\w+)", cond_str))

                    # Check for undeclared variables
                    undeclared = used_vars - declared_vars
                    if undeclared:
                        errors.append(
                            f"Action '{action_name}' uses undeclared variables: "
                            f"{', '.join('?' + v for v in undeclared)}"
                        )

        return errors

    def _validate_with_pddl_library(self, pddl: str) -> list[str]:
        """Validate using the pddl Python library."""
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
            except Exception as e:
                error_msg = str(e)
                # Clean up error message
                if ":" in error_msg:
                    error_msg = error_msg.split(":", 1)[-1].strip()
                errors.append(f"Parse error: {error_msg[:200]}")

        except ImportError:
            pass
        finally:
            if temp_path:
                try:
                    Path(temp_path).unlink()
                except Exception:
                    pass

        return errors

    def _validate_with_val(self, pddl: str) -> list[str]:
        """Validate using VAL parser."""
        errors = []
        temp_path = None

        try:
            import subprocess

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".pddl", delete=False
            ) as f:
                f.write(pddl)
                temp_path = f.name

            result = subprocess.run(
                ["Parser", temp_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                # Parse VAL error output
                error_lines = result.stderr.strip().split("\n")
                for line in error_lines:
                    if "error" in line.lower():
                        errors.append(line.strip()[:200])

        except Exception as e:
            logger.warning(f"VAL validation failed: {e}")
        finally:
            if temp_path:
                try:
                    Path(temp_path).unlink()
                except Exception:
                    pass

        return errors

    def repair_domain(self, pddl: str) -> tuple[str, list[str]]:
        """
        Attempt to repair PDDL syntax errors.

        Args:
            pddl: PDDL domain string

        Returns:
            Tuple of (repaired_pddl, list of repairs made)
        """
        repaired = self.sanitizer.repair(pddl)
        repairs = self.sanitizer.get_repairs_log()
        return repaired, repairs
