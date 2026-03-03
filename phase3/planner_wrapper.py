"""
Fast Downward Planner Wrapper for Phase 3: Random Walk Generation

This module wraps the Fast Downward planner to generate random valid
action sequences (exploration walks) from the PDDL domain.
"""

import os
import re
import logging
import tempfile
import subprocess
import random
from pathlib import Path
from typing import Optional

from .config import PlannerConfig
from .models import PDDLAction, GroundedAction, EnvironmentState

logger = logging.getLogger("Phase3.PlannerWrapper")


class PDDLParser:
    """Simple PDDL parser to extract actions from domain."""

    @staticmethod
    def parse_domain(domain_pddl: str) -> dict:
        """
        Parse PDDL domain and extract key components.

        Uses balanced-parenthesis extraction to find all action blocks,
        including those with deeply nested preconditions/effects that
        simple regex patterns miss.

        Returns dict with: types, predicates, actions
        """
        result = {
            "domain_name": "",
            "requirements": [],
            "types": {},
            "predicates": [],
            "actions": [],
        }

        # Extract domain name
        match = re.search(r'\(define\s+\(domain\s+(\w+)\)', domain_pddl)
        if match:
            result["domain_name"] = match.group(1)

        # Extract actions using balanced-paren matching
        i = 0
        while i < len(domain_pddl):
            action_match = re.search(r'\(:action\s+(\S+)', domain_pddl[i:])
            if not action_match:
                break

            action_start = i + action_match.start()
            action_name = action_match.group(1)

            # Find balanced closing paren for the entire action block
            depth = 0
            action_end = action_start
            for j in range(action_start, len(domain_pddl)):
                if domain_pddl[j] == '(':
                    depth += 1
                elif domain_pddl[j] == ')':
                    depth -= 1
                    if depth == 0:
                        action_end = j + 1
                        break

            action_block = domain_pddl[action_start:action_end]

            # Parse parameters
            parameters = []
            params_match = re.search(r':parameters\s*\(([^)]*)\)', action_block)
            if params_match:
                param_pattern = re.compile(r'\?(\w+)\s*-\s*(\w+)')
                for param_match in param_pattern.finditer(params_match.group(1)):
                    parameters.append((f"?{param_match.group(1)}", param_match.group(2)))

            # Extract precondition section via balanced parens
            precond_str = PDDLParser._extract_section(action_block, ':precondition')
            preconditions = PDDLParser._extract_atoms(precond_str) if precond_str else []

            # Extract effect section via balanced parens
            effect_str = PDDLParser._extract_section(action_block, ':effect')
            effects = PDDLParser._extract_atoms(effect_str) if effect_str else []

            result["actions"].append(PDDLAction(
                name=action_name,
                parameters=parameters,
                preconditions=preconditions,
                effects=effects,
                raw_pddl=action_block,
            ))

            i = action_end

        logger.info(f"Parsed domain '{result['domain_name']}' with {len(result['actions'])} actions")
        return result

    @staticmethod
    def _extract_section(action_block: str, section_keyword: str) -> str:
        """Extract a section (:precondition or :effect) using balanced parens."""
        sec_match = re.search(rf'{section_keyword}\s*\(', action_block)
        if not sec_match:
            return ""

        sdepth = 0
        for j in range(sec_match.end() - 1, len(action_block)):
            if action_block[j] == '(':
                sdepth += 1
            elif action_block[j] == ')':
                sdepth -= 1
                if sdepth == 0:
                    return action_block[sec_match.end() - 1:j + 1]
        return ""

    @staticmethod
    def _extract_atoms(expr: str) -> list[str]:
        """Extract predicate atoms from a PDDL expression."""
        atoms = []
        # Simple extraction - find all (predicate_name args...)
        atom_pattern = re.compile(r'\((\w+(?:\s+\?\w+)*)\)')
        for match in atom_pattern.finditer(expr):
            atom = match.group(1).strip()
            if atom and atom not in ["and", "or", "not", "when", "forall", "exists"]:
                atoms.append(atom)
        return atoms


class RandomWalkGenerator:
    """
    Generates random valid action sequences for exploration walks.

    Uses either Fast Downward for proper planning or a simpler random sampling
    approach for quick testing.
    """

    def __init__(self, config: Optional[PlannerConfig] = None, use_mock: bool = False):
        self.config = config or PlannerConfig()
        self.use_mock = use_mock
        self.domain_pddl: str = ""
        self.problem_pddl: str = ""
        self.parsed_domain: dict = {}
        self._fd_translate_failed: bool = False  # Cache FD translate failures

    def load_domain(self, domain_path: str, problem_path: Optional[str] = None):
        """Load PDDL domain and optionally problem file."""
        with open(domain_path) as f:
            self.domain_pddl = f.read()

        if problem_path and os.path.exists(problem_path):
            with open(problem_path) as f:
                self.problem_pddl = f.read()

        self._fd_translate_failed = False  # Reset cache on new domain
        self.parsed_domain = PDDLParser.parse_domain(self.domain_pddl)
        logger.info(f"Loaded domain with {len(self.parsed_domain['actions'])} actions")

    def load_domain_string(self, domain_pddl: str, problem_pddl: str = ""):
        """Load PDDL domain from string."""
        self.domain_pddl = domain_pddl
        self.problem_pddl = problem_pddl
        self._fd_translate_failed = False  # Reset cache on new domain
        self.parsed_domain = PDDLParser.parse_domain(self.domain_pddl)

    def _validate_pddl_for_fd(self, domain_pddl: str) -> str:
        """
        Validate and clean PDDL domain for Fast Downward translator compatibility.

        The FD translator (exit code 31) fails when actions reference predicates
        or types not declared in the domain header, OR when actions use variables
        not declared in :parameters. This method:
        1. Fixes actions with malformed :parameters blocks
        2. Removes/fixes actions with undefined variables
        3. Extracts declared predicates and types
        4. Scans actions for undeclared predicate references
        5. Forward-declares missing predicates into (:predicates)
        6. Fixes predicate arity mismatches

        Returns:
            Cleaned domain PDDL string safe for FD translator.
        """
        # --- Phase 0: Fix malformed :parameters blocks ---
        domain_pddl = self._fix_malformed_parameters(domain_pddl)

        # --- Phase A: Fix actions with undefined variables ---
        domain_pddl = self._fix_undefined_variables(domain_pddl)

        # Extract declared types (including 'object' which is always implicit)
        declared_types = {"object"}
        types_match = re.search(r'\(:types\s+(.*?)\)', domain_pddl, re.DOTALL)
        if types_match:
            for token in re.findall(r'[a-zA-Z]\w*', types_match.group(1)):
                declared_types.add(token)

        # Extract declared predicate names from (:predicates ...) block
        # Use balanced-paren extraction for robustness on large predicates blocks
        declared_predicates = set()
        pred_match = re.search(r'\(:predicates\s', domain_pddl)
        pred_block_text = None
        if pred_match:
            pd_start = pred_match.start()
            pd_depth = 0
            pd_end = pd_start
            for j in range(pd_start, len(domain_pddl)):
                if domain_pddl[j] == '(':
                    pd_depth += 1
                elif domain_pddl[j] == ')':
                    pd_depth -= 1
                    if pd_depth == 0:
                        pd_end = j + 1
                        break
            pred_block_text = domain_pddl[pd_start:pd_end]
            for pm in re.finditer(r'\((\w+)', pred_block_text):
                pname = pm.group(1)
                if pname != 'predicates':
                    declared_predicates.add(pname)

        if not declared_predicates:
            logger.warning("FD validator: no predicates found in domain, skipping validation")
            return domain_pddl

        # PDDL keywords to skip when scanning for predicate references
        pddl_keywords = {
            'and', 'or', 'not', 'when', 'forall', 'exists', 'imply',
            'increase', 'decrease', 'assign', 'define', 'domain',
        }

        # Scan all action blocks for undeclared predicate references
        missing_predicates = {}  # name -> max arity observed

        # Find each (:action ...) block by balanced parentheses
        action_starts = [m.start() for m in re.finditer(r'\(:action\s+', domain_pddl)]

        for start in action_starts:
            # Find balanced end of this action block
            depth = 0
            end = start
            for j in range(start, len(domain_pddl)):
                if domain_pddl[j] == '(':
                    depth += 1
                elif domain_pddl[j] == ')':
                    depth -= 1
                    if depth == 0:
                        end = j + 1
                        break

            action_block = domain_pddl[start:end]

            # Extract just precondition and effect sections
            for section in [':precondition', ':effect']:
                sec_match = re.search(rf'{section}\s*\(', action_block)
                if not sec_match:
                    continue

                sec_start = sec_match.start() + len(section)
                # Find balanced section text
                sdepth = 0
                sec_text = ""
                for j in range(sec_match.end() - 1, len(action_block)):
                    if action_block[j] == '(':
                        sdepth += 1
                    elif action_block[j] == ')':
                        sdepth -= 1
                        if sdepth == 0:
                            sec_text = action_block[sec_match.end() - 1:j + 1]
                            break

                # Find predicate references: (pred_name ?var1 ?var2 ...)
                for pred_ref in re.finditer(r'\((\w+)((?:\s+\?\w+)*)\s*\)', sec_text):
                    pname = pred_ref.group(1)
                    if pname in pddl_keywords or pname in declared_predicates:
                        continue
                    # Count arguments to infer arity
                    args = re.findall(r'\?\w+', pred_ref.group(2))
                    missing_predicates[pname] = max(
                        missing_predicates.get(pname, 0), len(args)
                    )

        if missing_predicates:
            # Forward-declare missing predicates
            logger.info(
                f"FD validator: forward-declaring {len(missing_predicates)} missing predicates "
                f"(sample: {list(missing_predicates.keys())[:5]})"
            )

            additional_preds = []
            for pred_name, arity in sorted(missing_predicates.items()):
                if arity > 0:
                    params = " ".join(f"?x{i} - object" for i in range(arity))
                    additional_preds.append(f"    ({pred_name} {params})")
                else:
                    additional_preds.append(f"    ({pred_name})")

            # Insert before the closing ) of the (:predicates ...) block
            if pred_block_text is not None:
                # pd_end points one past the closing ), so insert at pd_end - 1
                insert_pos = pred_match.start() + len(pred_block_text) - 1
                additions = (
                    "\n    ; Auto-declared for Fast Downward compatibility\n"
                    + "\n".join(additional_preds)
                    + "\n  "
                )
                domain_pddl = (
                    domain_pddl[:insert_pos]
                    + additions
                    + domain_pddl[insert_pos:]
                )
        else:
            logger.info("FD validator: domain is consistent, no missing predicates")

        # --- Phase C: Fix predicate arity mismatches ---
        # Must run AFTER forward-declaration so newly declared predicates
        # also get their usages checked.
        domain_pddl = self._fix_predicate_arity_mismatches(domain_pddl)

        return domain_pddl

    def _fix_malformed_parameters(self, domain_pddl: str) -> str:
        """
        Fix actions that have :parameters without a proper parenthesized block.

        FD translator fails with 'Parameters is expected to be a block' when
        :parameters is present but not followed by (...).  This can happen when
        the PDDLSanitizer or LLM strips empty parentheses.

        Also adds :parameters () to actions that are missing :parameters entirely.
        """
        fixed_count = 0
        action_starts = [m.start() for m in re.finditer(r'\(:action\s+', domain_pddl)]

        for start in reversed(action_starts):
            depth = 0
            end = start
            for j in range(start, len(domain_pddl)):
                if domain_pddl[j] == '(':
                    depth += 1
                elif domain_pddl[j] == ')':
                    depth -= 1
                    if depth == 0:
                        end = j + 1
                        break

            action_block = domain_pddl[start:end]
            name_match = re.match(r'\(:action\s+(\S+)', action_block)
            action_name = name_match.group(1) if name_match else "?"

            # Case 1: :parameters keyword present but no parenthesized block
            malformed = re.search(
                r':parameters\s+(?=:(?:precondition|effect))',
                action_block
            )
            if malformed:
                fixed_block = action_block[:malformed.start()] + \
                    ':parameters ()' + \
                    action_block[malformed.end():]
                domain_pddl = domain_pddl[:start] + fixed_block + domain_pddl[end:]
                fixed_count += 1
                logger.debug(
                    f"Fixed malformed :parameters in '{action_name}'"
                )
                continue

            # Case 2: :parameters keyword missing entirely
            if ':parameters' not in action_block:
                # Insert :parameters () after action name
                insert_match = re.match(r'(\(:action\s+\S+)', action_block)
                if insert_match:
                    insert_pos = insert_match.end()
                    fixed_block = (
                        action_block[:insert_pos]
                        + '\n    :parameters ()'
                        + action_block[insert_pos:]
                    )
                    domain_pddl = domain_pddl[:start] + fixed_block + domain_pddl[end:]
                    fixed_count += 1
                    logger.debug(
                        f"Added missing :parameters to '{action_name}'"
                    )

        if fixed_count > 0:
            logger.info(
                f"FD validator: fixed malformed/missing :parameters in "
                f"{fixed_count} actions"
            )

        return domain_pddl

    def _fix_predicate_arity_mismatches(self, domain_pddl: str) -> str:
        """
        Fix predicate arity mismatches that cause FD translator to abort.

        When a predicate is declared with N parameters but an action uses it
        with fewer arguments, pad the usage with dummy variables and add them
        to the action's :parameters block.

        Example: (firewall_rule_modified ?chain) where declared arity is 3
        → (firewall_rule_modified ?chain ?_pad_0 ?_pad_1)
        """
        # Step 1: Extract declared predicates with their arities
        # Use balanced-paren extraction for robust parsing of the predicates block
        declared_preds = {}  # name -> arity
        pred_start_match = re.search(r'\(:predicates\s', domain_pddl)
        if not pred_start_match:
            return domain_pddl

        # Find balanced end of predicates block
        pred_block_start = pred_start_match.start()
        depth = 0
        pred_block_end = pred_block_start
        for j in range(pred_block_start, len(domain_pddl)):
            if domain_pddl[j] == '(':
                depth += 1
            elif domain_pddl[j] == ')':
                depth -= 1
                if depth == 0:
                    pred_block_end = j + 1
                    break

        pred_text = domain_pddl[pred_block_start:pred_block_end]
        for pm in re.finditer(r'\((\w+)((?:\s+\?\w+(?:\s*-\s*\w+)?)*)\s*\)', pred_text):
            pname = pm.group(1)
            if pname == 'predicates':
                continue
            args = re.findall(r'\?\w+', pm.group(2))
            declared_preds[pname] = len(args)

        if not declared_preds:
            logger.info("FD validator: no predicates found in predicates block, skipping arity fix")
            return domain_pddl

        logger.info(
            f"FD validator: extracted {len(declared_preds)} declared predicates for arity checking"
        )

        pddl_keywords = {
            'and', 'or', 'not', 'when', 'forall', 'exists', 'imply',
            'increase', 'decrease', 'assign', 'define', 'domain',
        }

        # Step 2: First pass - find max observed arity for each predicate
        # across all actions to detect cases where usage > declaration
        max_observed_arity = {}  # pred_name -> max args seen
        action_starts = [m.start() for m in re.finditer(r'\(:action\s+', domain_pddl)]

        for start in action_starts:
            depth = 0
            end = start
            for j in range(start, len(domain_pddl)):
                if domain_pddl[j] == '(':
                    depth += 1
                elif domain_pddl[j] == ')':
                    depth -= 1
                    if depth == 0:
                        end = j + 1
                        break
            action_block = domain_pddl[start:end]
            for pred_ref in re.finditer(
                r'\((\w+)((?:\s+\?\w+)*)\s*\)', action_block
            ):
                pname = pred_ref.group(1)
                if pname in pddl_keywords or pname not in declared_preds:
                    continue
                args = re.findall(r'\?\w+', pred_ref.group(2))
                max_observed_arity[pname] = max(
                    max_observed_arity.get(pname, 0), len(args)
                )

        # Step 2b: Update predicate declarations where usage > declaration
        preds_upgraded = {}
        for pname, max_arity in max_observed_arity.items():
            if pname in declared_preds and max_arity > declared_preds[pname]:
                preds_upgraded[pname] = (declared_preds[pname], max_arity)

        if preds_upgraded:
            # Update declarations in the predicates block
            pred_text_new = pred_text
            for pname, (old_arity, new_arity) in preds_upgraded.items():
                # Find the predicate declaration in pred_text
                for pm in re.finditer(
                    r'\(' + re.escape(pname) + r'((?:\s+\?\w+(?:\s*-\s*\w+)?)*)\s*\)',
                    pred_text_new
                ):
                    old_decl = pm.group(0)
                    # Build new declaration with extra params
                    existing_args = pm.group(1)
                    extra_params = " ".join(
                        f"?x{i} - object"
                        for i in range(old_arity, new_arity)
                    )
                    if existing_args.strip():
                        new_decl = f"({pname}{existing_args} {extra_params})"
                    else:
                        new_decl = f"({pname} {extra_params})"
                    pred_text_new = pred_text_new.replace(old_decl, new_decl, 1)
                    logger.info(
                        f"FD validator: upgraded predicate '{pname}' declaration "
                        f"from arity {old_arity} to {new_arity}"
                    )
                    declared_preds[pname] = new_arity
                    break

            # Replace the predicates block in the domain
            domain_pddl = (
                domain_pddl[:pred_block_start]
                + pred_text_new
                + domain_pddl[pred_block_end:]
            )
            # Recalculate action_starts since domain changed
            action_starts = [m.start() for m in re.finditer(r'\(:action\s+', domain_pddl)]

        # Step 3: Second pass - pad action usages where usage < declaration
        fixed_count = 0

        for start in reversed(action_starts):
            depth = 0
            end = start
            for j in range(start, len(domain_pddl)):
                if domain_pddl[j] == '(':
                    depth += 1
                elif domain_pddl[j] == ')':
                    depth -= 1
                    if depth == 0:
                        end = j + 1
                        break

            action_block = domain_pddl[start:end]
            name_match = re.match(r'\(:action\s+(\S+)', action_block)
            action_name = name_match.group(1) if name_match else "?"

            # Find arity-mismatched predicate usages in this action
            replacements = []  # (start, end, new_text) within action_block
            pad_vars = []  # dummy vars to add to :parameters
            pad_counter = 0

            for pred_ref in re.finditer(
                r'\((\w+)((?:\s+\?\w+)*)\s*\)', action_block
            ):
                pname = pred_ref.group(1)
                if pname in pddl_keywords or pname not in declared_preds:
                    continue

                args = re.findall(r'\?\w+', pred_ref.group(2))
                declared_arity = declared_preds[pname]

                if len(args) < declared_arity:
                    logger.info(
                        f"FD validator: arity mismatch in '{action_name}': "
                        f"predicate '{pname}' used with {len(args)} args "
                        f"but declared with {declared_arity} → padding"
                    )
                    pad_count = declared_arity - len(args)
                    new_vars = []
                    for _ in range(pad_count):
                        var_name = f"?_pad_{pad_counter}"
                        pad_counter += 1
                        new_vars.append(var_name)
                        pad_vars.append(var_name)

                    all_args = " ".join(args + new_vars)
                    new_text = f"({pname} {all_args})"
                    replacements.append(
                        (pred_ref.start(), pred_ref.end(), new_text)
                    )

            if not replacements:
                continue

            # Apply replacements in reverse order within action_block
            new_action_block = action_block
            for r_start, r_end, r_new in sorted(
                replacements, key=lambda x: x[0], reverse=True
            ):
                new_action_block = (
                    new_action_block[:r_start]
                    + r_new
                    + new_action_block[r_end:]
                )

            # Add dummy vars to :parameters
            if pad_vars:
                params_match = re.search(
                    r':parameters\s*\(([^)]*)\)', new_action_block
                )
                if params_match:
                    additions = " ".join(
                        f"{v} - object" for v in pad_vars
                    )
                    old_params = params_match.group(1).strip()
                    if old_params:
                        new_params = f"{old_params} {additions}"
                    else:
                        new_params = additions
                    new_action_block = (
                        new_action_block[:params_match.start(1)]
                        + new_params
                        + new_action_block[params_match.end(1):]
                    )

            domain_pddl = domain_pddl[:start] + new_action_block + domain_pddl[end:]
            fixed_count += 1
            logger.debug(
                f"Fixed arity mismatch in '{action_name}': "
                f"padded {len(replacements)} predicate usage(s)"
            )

        if fixed_count > 0:
            logger.info(
                f"FD validator: fixed predicate arity mismatches in "
                f"{fixed_count} actions"
            )

        return domain_pddl

    def _fix_undefined_variables(self, domain_pddl: str) -> str:
        """
        Scan each action for variables used in :precondition/:effect that
        are not declared in :parameters. Such actions cause FD translator
        to abort with 'Undefined variable' (exit code 31).

        For each broken action, adds missing variables to :parameters
        with type 'object'. This is preferred over removing the action
        because it preserves domain coverage.

        Returns:
            Domain with broken actions fixed.
        """
        pddl_keywords = {
            'and', 'or', 'not', 'when', 'forall', 'exists', 'imply',
            'increase', 'decrease', 'assign', 'define', 'domain',
        }

        fixed_count = 0
        action_starts = [m.start() for m in re.finditer(r'\(:action\s+', domain_pddl)]

        # Process in reverse order so string indices remain valid after edits
        for start in reversed(action_starts):
            # Find balanced end of this action block
            depth = 0
            end = start
            for j in range(start, len(domain_pddl)):
                if domain_pddl[j] == '(':
                    depth += 1
                elif domain_pddl[j] == ')':
                    depth -= 1
                    if depth == 0:
                        end = j + 1
                        break

            action_block = domain_pddl[start:end]

            # Extract action name
            name_match = re.match(r'\(:action\s+(\S+)', action_block)
            if not name_match:
                continue
            action_name = name_match.group(1)

            # Extract declared parameters
            params_match = re.search(r':parameters\s*\(([^)]*)\)', action_block)
            declared_vars = set()
            if params_match:
                declared_vars = set(re.findall(r'\?\w+', params_match.group(1)))

            # Also collect variables bound by forall/exists quantifiers
            for quant_match in re.finditer(
                r'(?:forall|exists)\s*\(([^)]*)\)', action_block
            ):
                declared_vars.update(re.findall(r'\?\w+', quant_match.group(1)))

            # Find all variables used in preconditions and effects
            used_vars = set()
            for section in [':precondition', ':effect']:
                sec_match = re.search(rf'{section}\s*\(', action_block)
                if not sec_match:
                    continue

                sdepth = 0
                sec_text = ""
                for j in range(sec_match.end() - 1, len(action_block)):
                    if action_block[j] == '(':
                        sdepth += 1
                    elif action_block[j] == ')':
                        sdepth -= 1
                        if sdepth == 0:
                            sec_text = action_block[sec_match.end() - 1:j + 1]
                            break

                used_vars.update(re.findall(r'\?\w+', sec_text))

            # Find undefined variables
            undefined = used_vars - declared_vars
            if not undefined:
                continue

            # Add missing variables to :parameters
            if params_match:
                additions = " ".join(f"{v} - object" for v in sorted(undefined))
                old_params = params_match.group(1).strip()
                if old_params:
                    new_params = f"{old_params} {additions}"
                else:
                    new_params = additions

                fixed_block = (
                    action_block[:params_match.start(1)]
                    + new_params
                    + action_block[params_match.end(1):]
                )

                domain_pddl = domain_pddl[:start] + fixed_block + domain_pddl[end:]
                fixed_count += 1

                logger.debug(
                    f"Fixed undefined vars in '{action_name}': "
                    f"{sorted(undefined)}"
                )

        if fixed_count > 0:
            logger.info(
                f"FD validator: fixed undefined variables in "
                f"{fixed_count} actions"
            )

        return domain_pddl

    def generate_random_walk(
        self,
        depth: int,
        env_state: EnvironmentState
    ) -> list[GroundedAction]:
        """
        Generate a random walk of grounded actions.

        Args:
            depth: Maximum number of actions in the walk
            env_state: Current environment state for grounding

        Returns:
            List of grounded actions
        """
        if self.use_mock:
            return self._mock_random_walk(depth, env_state)

        # Try Fast Downward first, fall back to random sampling
        try:
            return self._fd_random_walk(depth, env_state)
        except Exception as e:
            logger.warning(f"Fast Downward failed, using random sampling: {e}")
            return self._sample_random_walk(depth, env_state)

    def _fd_random_walk(
        self,
        depth: int,
        env_state: EnvironmentState
    ) -> list[GroundedAction]:
        """
        Use Fast Downward to generate a valid plan (random walk).
        """
        # Skip FD entirely if we already know it fails on this domain
        if self._fd_translate_failed:
            return self._sample_random_walk(depth, env_state)

        # Create temporary directory for planning
        with tempfile.TemporaryDirectory() as tmpdir:
            domain_file = Path(tmpdir) / "domain.pddl"
            problem_file = Path(tmpdir) / "problem.pddl"
            plan_file = Path(tmpdir) / "plan.txt"

            # Validate and clean domain for FD translator compatibility
            cleaned_domain = self._validate_pddl_for_fd(self.domain_pddl)
            domain_file.write_text(cleaned_domain)

            # Generate problem file if not provided
            if self.problem_pddl:
                problem_file.write_text(self.problem_pddl)
            else:
                problem_pddl = self._generate_problem(env_state)
                problem_file.write_text(problem_pddl)

            # Run Fast Downward
            fd_time_limit = max(30, self.config.plan_timeout - 10)
            cmd = [
                self.config.fast_downward_path,
                "--overall-time-limit", str(fd_time_limit),
                "--plan-file", str(plan_file),
                str(domain_file),
                str(problem_file),
                "--search", self.config.search_config,
            ]

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.config.plan_timeout,
                )

                if result.returncode == 0 and plan_file.exists():
                    return self._parse_plan(plan_file.read_text(), env_state)
                else:
                    # Exit code 31 = translate error (domain-level, won't change
                    # between walks). Cache to skip FD for remaining walks.
                    if result.returncode == 31:
                        if not self._fd_translate_failed:
                            logger.warning(
                                f"Fast Downward translate failed (exit 31), "
                                f"skipping FD for remaining walks on this domain.\n"
                                f"  STDOUT (last 500): "
                                f"{result.stdout[-500:] if result.stdout else '(empty)'}"
                            )
                            self._fd_translate_failed = True
                    else:
                        logger.warning(
                            f"Fast Downward returned {result.returncode}\n"
                            f"  STDOUT (last 500): {result.stdout[-500:] if result.stdout else '(empty)'}\n"
                            f"  STDERR (last 500): {result.stderr[-500:] if result.stderr else '(empty)'}"
                        )
                    return self._sample_random_walk(depth, env_state)

            except subprocess.TimeoutExpired:
                logger.warning("Fast Downward timed out")
                return self._sample_random_walk(depth, env_state)
            except FileNotFoundError:
                logger.warning("Fast Downward not found")
                return self._sample_random_walk(depth, env_state)

    def _sample_random_walk(
        self,
        depth: int,
        env_state: EnvironmentState
    ) -> list[GroundedAction]:
        """
        Generate random walk by sampling actions and grounding them.

        This is a simpler fallback when Fast Downward isn't available.
        """
        actions = self.parsed_domain.get("actions", [])
        if not actions:
            logger.warning("No actions in domain")
            return []

        walk = []
        for _ in range(depth):
            # Pick random action
            action = random.choice(actions)

            # Try to ground it
            grounded = self._ground_action(action, env_state)
            if grounded:
                walk.append(grounded)

        return walk

    def _ground_action(
        self,
        action: PDDLAction,
        env_state: EnvironmentState
    ) -> Optional[GroundedAction]:
        """
        Ground an action with concrete objects from environment state.
        """
        bindings = {}

        for param_name, param_type in action.parameters:
            objects = env_state.get_objects_by_type(param_type)
            if not objects:
                # Try to find objects from similar types
                objects = self._find_compatible_objects(param_type, env_state)

            if objects:
                bindings[param_name] = random.choice(objects)
            else:
                # Can't ground this parameter
                return None

        return GroundedAction(action=action, bindings=bindings)

    def _find_compatible_objects(
        self,
        type_name: str,
        env_state: EnvironmentState
    ) -> list[str]:
        """Find objects that might be compatible with a type."""
        # Map PDDL types to environment state attributes
        type_mapping = {
            "package": env_state.packages,
            "service": env_state.services,
            "user": env_state.users,
            "system_user": [u for u in env_state.users if int(u.get("uid", 1000)) < 1000],
            "human_user": [u for u in env_state.users if int(u.get("uid", 0)) >= 1000],
            "group": env_state.groups,
            "file": env_state.files,
            "filesystem_object": env_state.files,
            "directory": [f for f in env_state.files if f.get("is_dir")],
        }

        objects = type_mapping.get(type_name, [])
        return [obj.get("name", obj.get("path", "")) for obj in objects if obj]

    def _generate_problem(self, env_state: EnvironmentState) -> str:
        """Generate a PDDL problem file from environment state."""
        domain_name = self.parsed_domain.get("domain_name", "sysadmin")

        # Build objects section
        objects_by_type: dict[str, list[str]] = {}
        for pkg in env_state.packages[:10]:  # Limit for performance
            objects_by_type.setdefault("package", []).append(pkg["name"])
        for svc in env_state.services[:10]:
            objects_by_type.setdefault("service", []).append(svc["name"])
        for usr in env_state.users[:10]:
            objects_by_type.setdefault("user", []).append(usr["name"])
        for grp in env_state.groups[:10]:
            objects_by_type.setdefault("group", []).append(grp["name"])

        objects_str = "\n    ".join(
            f"{' '.join(objs)} - {type_name}"
            for type_name, objs in objects_by_type.items()
        )

        # Build init section
        init_facts = []
        for pkg in env_state.packages:
            if pkg.get("installed"):
                init_facts.append(f"(package_installed {pkg['name']})")
        for svc in env_state.services:
            if svc.get("active"):
                init_facts.append(f"(service_running {svc['name']})")
            if svc.get("enabled"):
                init_facts.append(f"(service_enabled {svc['name']})")
        for usr in env_state.users:
            init_facts.append(f"(user_exists {usr['name']})")
        for grp in env_state.groups:
            init_facts.append(f"(group_exists {grp['name']})")

        init_str = "\n    ".join(init_facts)

        # Simple goal (any valid state is acceptable for exploration)
        goal_str = "(and)"

        return f"""(define (problem exploration-walk)
  (:domain {domain_name})

  (:objects
    {objects_str}
  )

  (:init
    {init_str}
  )

  (:goal {goal_str})
)
"""

    def _parse_plan(self, plan_text: str, env_state: EnvironmentState) -> list[GroundedAction]:
        """Parse a Fast Downward plan output into grounded actions."""
        walk = []
        actions_by_name = {a.name: a for a in self.parsed_domain.get("actions", [])}

        for line in plan_text.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith(";"):
                continue

            # Parse (action_name arg1 arg2 ...)
            match = re.match(r'\((\w+)(?:\s+(.+))?\)', line)
            if match:
                action_name = match.group(1)
                args = match.group(2).split() if match.group(2) else []

                action = actions_by_name.get(action_name)
                if action:
                    # Build bindings from args
                    bindings = {}
                    for i, (param_name, _) in enumerate(action.parameters):
                        if i < len(args):
                            bindings[param_name] = args[i]

                    walk.append(GroundedAction(action=action, bindings=bindings))

        return walk

    def _mock_random_walk(
        self,
        depth: int,
        env_state: EnvironmentState
    ) -> list[GroundedAction]:
        """Generate mock random walk for testing."""
        mock_actions = [
            PDDLAction(
                name="install_package",
                parameters=[("?p", "package")],
                preconditions=["(not (package_installed ?p))"],
                effects=["(package_installed ?p)"],
            ),
            PDDLAction(
                name="start_service",
                parameters=[("?s", "service")],
                preconditions=["(not (service_running ?s))"],
                effects=["(service_running ?s)"],
            ),
            PDDLAction(
                name="create_user",
                parameters=[("?u", "user")],
                preconditions=["(not (user_exists ?u))"],
                effects=["(user_exists ?u)"],
            ),
        ]

        walk = []
        for i in range(min(depth, 3)):
            action = mock_actions[i % len(mock_actions)]
            bindings = {}

            for param_name, param_type in action.parameters:
                objects = env_state.get_objects_by_type(param_type)
                if objects:
                    bindings[param_name] = random.choice(objects)
                else:
                    bindings[param_name] = f"test_{param_type}"

            walk.append(GroundedAction(action=action, bindings=bindings))

        return walk

    def get_applicable_actions(self, env_state: EnvironmentState) -> list[GroundedAction]:
        """
        Get all actions that are potentially applicable in the current state.
        """
        applicable = []

        for action in self.parsed_domain.get("actions", []):
            grounded = self._ground_action(action, env_state)
            if grounded:
                applicable.append(grounded)

        return applicable
