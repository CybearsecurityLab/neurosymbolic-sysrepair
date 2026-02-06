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

        # Extract actions
        action_pattern = re.compile(
            r'\(:action\s+(\w+)\s*'
            r':parameters\s*\(([^)]*)\)\s*'
            r':precondition\s*(\([^)]*(?:\([^)]*\)[^)]*)*\))\s*'
            r':effect\s*(\([^)]*(?:\([^)]*\)[^)]*)*\))',
            re.DOTALL | re.IGNORECASE
        )

        for match in action_pattern.finditer(domain_pddl):
            action_name = match.group(1)
            params_str = match.group(2)
            precond_str = match.group(3)
            effect_str = match.group(4)

            # Parse parameters
            parameters = []
            param_pattern = re.compile(r'\?(\w+)\s*-\s*(\w+)')
            for param_match in param_pattern.finditer(params_str):
                parameters.append((f"?{param_match.group(1)}", param_match.group(2)))

            # Extract preconditions as list
            preconditions = PDDLParser._extract_atoms(precond_str)

            # Extract effects as list
            effects = PDDLParser._extract_atoms(effect_str)

            result["actions"].append(PDDLAction(
                name=action_name,
                parameters=parameters,
                preconditions=preconditions,
                effects=effects,
                raw_pddl=match.group(0),
            ))

        logger.info(f"Parsed domain '{result['domain_name']}' with {len(result['actions'])} actions")
        return result

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

    def load_domain(self, domain_path: str, problem_path: Optional[str] = None):
        """Load PDDL domain and optionally problem file."""
        with open(domain_path) as f:
            self.domain_pddl = f.read()

        if problem_path and os.path.exists(problem_path):
            with open(problem_path) as f:
                self.problem_pddl = f.read()

        self.parsed_domain = PDDLParser.parse_domain(self.domain_pddl)
        logger.info(f"Loaded domain with {len(self.parsed_domain['actions'])} actions")

    def load_domain_string(self, domain_pddl: str, problem_pddl: str = ""):
        """Load PDDL domain from string."""
        self.domain_pddl = domain_pddl
        self.problem_pddl = problem_pddl
        self.parsed_domain = PDDLParser.parse_domain(self.domain_pddl)

    def _validate_pddl_for_fd(self, domain_pddl: str) -> str:
        """
        Validate and clean PDDL domain for Fast Downward translator compatibility.

        The FD translator (exit code 31) fails when actions reference predicates
        or types not declared in the domain header. This method:
        1. Extracts declared predicates and types
        2. Scans actions for undeclared predicate references
        3. Forward-declares missing predicates into (:predicates)

        Returns:
            Cleaned domain PDDL string safe for FD translator.
        """
        # Extract declared types (including 'object' which is always implicit)
        declared_types = {"object"}
        types_match = re.search(r'\(:types\s+(.*?)\)', domain_pddl, re.DOTALL)
        if types_match:
            for token in re.findall(r'[a-zA-Z]\w*', types_match.group(1)):
                declared_types.add(token)

        # Extract declared predicate names from (:predicates ...) block
        declared_predicates = set()
        pred_match = re.search(
            r'\(:predicates\s+(.*?)\)\s*(?=\s*(?:;|\(:action))',
            domain_pddl, re.DOTALL
        )
        if pred_match:
            for pm in re.finditer(r'\((\w+)', pred_match.group(1)):
                declared_predicates.add(pm.group(1))

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

        if not missing_predicates:
            logger.info("FD validator: domain is consistent, no missing predicates")
            return domain_pddl

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
        # Find the last predicate declaration line and insert after it
        if pred_match:
            insert_pos = pred_match.start(1) + len(pred_match.group(1))
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
