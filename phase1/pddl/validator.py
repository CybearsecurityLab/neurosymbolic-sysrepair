"""
phase1/pddl/validator.py

Validates generated PDDL using the 'pddl' Python library.
Checks for syntax errors and domain/problem consistency.
"""

import os
import tempfile
from typing import Tuple


class PDDLValidator:
    """
    Validates generated PDDL using the 'pddl' Python library.
    https://github.com/h2non/pddl-parser (or similar compliant library)
    """

    def __init__(self):
        self._available = self._check_available()

    def _check_available(self) -> bool:
        """Check if the pddl library is installed."""
        try:
            import pddl

            return True
        except ImportError:
            return False

    def is_available(self) -> bool:
        return self._available

    def validate_domain(self, domain_pddl: str) -> Tuple[bool, str]:
        """
        Validate domain syntax by attempting to parse it.
        """
        if not self._available:
            return (
                True,
                "PDDL library not installed (pip install pddl) - skipping validation",
            )

        # Write content to a temporary file because parse_domain expects a file path
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pddl", delete=False) as f:
            f.write(domain_pddl)
            temp_path = f.name

        try:
            from pddl import parse_domain

            # Parse from the file path
            parse_domain(temp_path)

            return True, "Domain syntax is valid."

        except Exception as e:
            return False, f"Domain parsing failed: {str(e)}"
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def validate_problem(self, domain_pddl: str, problem_pddl: str) -> Tuple[bool, str]:
        """
        Validate problem syntax and consistency against the domain.
        """
        if not self._available:
            return True, "PDDL library not installed - skipping validation"

        # Create two temp files
        domain_file = None
        problem_file = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".pddl", delete=False
            ) as df:
                df.write(domain_pddl)
                domain_file = df.name

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".pddl", delete=False
            ) as pf:
                pf.write(problem_pddl)
                problem_file = pf.name

            from pddl import parse_domain, parse_problem

            # 1. Parse using file paths
            domain = parse_domain(domain_file)
            problem = parse_problem(problem_file)

            # 2. Check consistency (problem uses domain name correctly)
            if problem.domain_name != domain.name:
                return False, (
                    f"Consistency Error: Problem defines domain as '{problem.domain_name}', "
                    f"but domain name is '{domain.name}'"
                )

            return True, "Problem is valid and consistent with domain."

        except Exception as e:
            return False, f"Validation failed: {str(e)}"
        finally:
            # Clean up
            if domain_file and os.path.exists(domain_file):
                os.unlink(domain_file)
            if problem_file and os.path.exists(problem_file):
                os.unlink(problem_file)
