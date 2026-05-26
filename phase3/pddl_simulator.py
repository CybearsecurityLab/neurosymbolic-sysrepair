"""
PDDL State Simulator for Phase 3: Paper-Accurate Exploration Walks

Implements the Exploration Walk algorithm from arxiv 2407.12979:
1. Maintain a set of ground facts (PDDL state, closed-world assumption)
2. At each step, find all LEGAL actions (preconditions satisfied)
3. Sample uniformly from legal actions
4. Execute in Docker, apply PDDL effects to update state
5. Docker failure on a PDDL-legal action = discrepancy

Uses STRIPS semantics: only AND and NOT in preconditions/effects.
"""

import re
import random
import logging
from dataclasses import dataclass, field
from typing import Optional

from .models import (
    PDDLAction,
    GroundedAction,
    EnvironmentState,
)

logger = logging.getLogger("Phase3.PDDLSimulator")

# Type aliases
GroundLiteral = tuple[str, ...]  # ("predicate_name", "arg1", "arg2", ...)
State = frozenset[GroundLiteral]


@dataclass
class ParsedAction:
    """Structured PDDL action with separated pos/neg preconditions and add/del effects."""
    name: str
    parameters: list[tuple[str, str]]  # [("?var", "type"), ...]
    pos_preconditions: list[tuple[str, ...]]  # must be true in state
    neg_preconditions: list[tuple[str, ...]]  # must be false in state
    add_effects: list[tuple[str, ...]]  # facts to add
    del_effects: list[tuple[str, ...]]  # facts to remove
    raw_pddl: str = ""

    def to_pddl_action(self) -> PDDLAction:
        """Convert back to PDDLAction for compatibility with concretizer."""
        preconditions = [" ".join(p) for p in self.pos_preconditions]
        preconditions += [f"not {' '.join(p)}" for p in self.neg_preconditions]
        effects = [" ".join(e) for e in self.add_effects]
        effects += [f"not {' '.join(e)}" for e in self.del_effects]
        return PDDLAction(
            name=self.name,
            parameters=self.parameters,
            preconditions=preconditions,
            effects=effects,
            raw_pddl=self.raw_pddl,
        )


class PDDLStateSimulator:
    """
    PDDL state simulator implementing the paper's Exploration Walk algorithm.

    Tracks a set of ground facts, checks action preconditions against state,
    and applies effects to update state after each action.
    """

    def __init__(
        self,
        domain_pddl: str,
        env_state: EnvironmentState,
        problem_pddl: str = "",
    ):
        self.domain_pddl = domain_pddl
        self.problem_pddl = problem_pddl
        self.env_state = env_state

        # Parse actions from domain
        self.actions: list[ParsedAction] = self._parse_actions(domain_pddl)
        logger.info(f"Parsed {len(self.actions)} actions from domain")

        # Build object pools per type
        self.objects: dict[str, list[str]] = self._build_objects(env_state)

        # Build initial state from problem file + environment
        self.state: State = self._build_initial_state(env_state, problem_pddl)
        logger.info(f"Initial state has {len(self.state)} ground facts")

        # Pre-compute predicate index for fast lookup: pred_name -> set of facts
        self._pred_index: dict[str, set[GroundLiteral]] = {}
        self._rebuild_pred_index()

        # Pre-compute which predicates each action needs (for Tier 1 filter)
        self._action_required_preds: list[set[str]] = []
        for action in self.actions:
            preds = {p[0] for p in action.pos_preconditions}
            self._action_required_preds.append(preds)

    # ─── Parsing ─────────────────────────────────────────────────────────

    def _parse_actions(self, domain_pddl: str) -> list[ParsedAction]:
        """Parse all (:action ...) blocks into ParsedAction structs."""
        actions = []
        i = 0
        while i < len(domain_pddl):
            match = re.search(r'\(:action\s+(\S+)', domain_pddl[i:])
            if not match:
                break

            start = i + match.start()
            name = match.group(1)

            # Balanced-paren extraction for the full action block
            end = self._find_balanced_end(domain_pddl, start)
            block = domain_pddl[start:end]

            # Parse parameters
            parameters = self._parse_parameters(block)

            # Parse preconditions
            precond_expr = self._extract_section(block, ":precondition")
            pos_pre, neg_pre = self._parse_condition(precond_expr)

            # Parse effects
            effect_expr = self._extract_section(block, ":effect")
            add_eff, del_eff = self._parse_condition(effect_expr)

            actions.append(ParsedAction(
                name=name,
                parameters=parameters,
                pos_preconditions=pos_pre,
                neg_preconditions=neg_pre,
                add_effects=add_eff,
                del_effects=del_eff,
                raw_pddl=block,
            ))

            i = end

        return actions

    @staticmethod
    def _find_balanced_end(text: str, start: int) -> int:
        """Find the position after the balanced closing paren starting at `start`."""
        depth = 0
        for j in range(start, len(text)):
            if text[j] == '(':
                depth += 1
            elif text[j] == ')':
                depth -= 1
                if depth == 0:
                    return j + 1
        return len(text)

    @staticmethod
    def _extract_section(block: str, keyword: str) -> str:
        """Extract a :precondition or :effect section using balanced parens."""
        match = re.search(rf'{keyword}\s*\(', block)
        if not match:
            return ""
        depth = 0
        for j in range(match.end() - 1, len(block)):
            if block[j] == '(':
                depth += 1
            elif block[j] == ')':
                depth -= 1
                if depth == 0:
                    return block[match.end() - 1:j + 1]
        return ""

    @staticmethod
    def _parse_parameters(block: str) -> list[tuple[str, str]]:
        """Parse :parameters (?var - type ...) into list of (var, type) tuples."""
        match = re.search(r':parameters\s*\(([^)]*)\)', block)
        if not match:
            return []
        params = []
        for pm in re.finditer(r'(\?\w+)\s*-\s*([\w-]+)', match.group(1)):
            params.append((pm.group(1), pm.group(2)))
        return params

    @staticmethod
    def _parse_condition(expr: str) -> tuple[list[tuple[str, ...]], list[tuple[str, ...]]]:
        """
        Parse a PDDL condition/effect expression into positive and negative literals.

        Handles STRIPS: (and (pred ?x) (not (pred ?y)) ...)
        Also handles bare literals: (pred ?x) without wrapping (and ...).

        Returns: (positives, negatives)
          positives: list of tuples like ("pred_name", "?x", "?y")
          negatives: list of tuples like ("pred_name", "?x", "?y")
        """
        if not expr:
            return [], []

        positives = []
        negatives = []

        # Keywords to skip
        keywords = {'and', 'or', 'when', 'forall', 'exists', 'imply',
                     'increase', 'decrease', 'assign'}

        # Walk through top-level sub-expressions
        # First strip outer parens if it's (and ...)
        inner = expr.strip()
        if inner.startswith('(') and inner.endswith(')'):
            inner = inner[1:-1].strip()

        # Check if it starts with 'and' keyword
        if inner.startswith('and') and (len(inner) == 3 or inner[3] in ' \t\n('):
            inner = inner[3:].strip()

        # Now parse each top-level sub-expression
        i = 0
        while i < len(inner):
            if inner[i] == '(':
                # Find balanced end
                depth = 0
                start = i
                for j in range(i, len(inner)):
                    if inner[j] == '(':
                        depth += 1
                    elif inner[j] == ')':
                        depth -= 1
                        if depth == 0:
                            sub_expr = inner[start + 1:j].strip()
                            # Is this a (not ...) ?
                            if sub_expr.startswith('not') and (
                                len(sub_expr) == 3 or sub_expr[3] in ' \t\n('
                            ):
                                # Extract the inner literal
                                not_inner = sub_expr[3:].strip()
                                lit = PDDLStateSimulator._extract_literal(not_inner)
                                if lit:
                                    negatives.append(lit)
                            else:
                                # Check if it's a keyword we skip
                                first_token = sub_expr.split()[0] if sub_expr else ""
                                if first_token not in keywords:
                                    lit = PDDLStateSimulator._extract_literal(
                                        '(' + sub_expr + ')'
                                    )
                                    if lit:
                                        positives.append(lit)
                            i = j + 1
                            break
                else:
                    break  # unbalanced
            else:
                i += 1

        return positives, negatives

    @staticmethod
    def _extract_literal(expr: str) -> Optional[tuple[str, ...]]:
        """
        Extract a single predicate literal from expression like (pred ?x ?y)
        or pred ?x ?y (already stripped of outer parens).

        Returns tuple ("pred", "?x", "?y") or None if not a valid literal.
        """
        s = expr.strip()
        if s.startswith('(') and s.endswith(')'):
            s = s[1:-1].strip()

        if not s:
            return None

        tokens = s.split()
        if not tokens:
            return None

        pred_name = tokens[0]
        # Skip PDDL keywords
        if pred_name in ('and', 'or', 'not', 'when', 'forall', 'exists',
                          'imply', 'increase', 'decrease', 'assign'):
            return None

        return tuple(tokens)

    # ─── State Construction ──────────────────────────────────────────────

    def _build_initial_state(
        self,
        env_state: EnvironmentState,
        problem_pddl: str,
    ) -> State:
        """Build initial state from problem file :init block and environment."""
        facts: set[GroundLiteral] = set()

        # Source 1: Problem file :init block (primary, has richest facts)
        if problem_pddl:
            init_match = re.search(r'\(:init\s', problem_pddl)
            if init_match:
                end = self._find_balanced_end(problem_pddl, init_match.start())
                init_text = problem_pddl[init_match.start():end]
                # Extract all (predicate arg1 arg2 ...) facts
                for m in re.finditer(
                    r'\(([\w-]+)((?:\s+[\w-]+)*)\s*\)', init_text
                ):
                    pred = m.group(1)
                    if pred == 'init':
                        continue
                    args = m.group(2).split() if m.group(2).strip() else []
                    facts.add(tuple([pred] + args))

        # Source 2: Environment state (supplements problem file)
        for u in env_state.users:
            facts.add(("user_exists", u["name"]))
        for g in env_state.groups:
            facts.add(("group_exists", g["name"]))
        for p in env_state.packages:
            if p.get("installed"):
                facts.add(("package_installed", p["name"]))
        for s in env_state.services:
            if s.get("active"):
                facts.add(("service_running", s["name"]))
            if s.get("enabled"):
                facts.add(("service_enabled", s["name"]))

        logger.debug(f"Built initial state with {len(facts)} facts from "
                     f"problem file + environment")
        return frozenset(facts)

    def _build_objects(self, env_state: EnvironmentState) -> dict[str, list[str]]:
        """Build object pools per PDDL type from environment state."""
        objects: dict[str, list[str]] = {}

        # Extract types from domain
        types_match = re.search(r'\(:types\s+(.*?)\)', self.domain_pddl, re.DOTALL)
        all_types = {"object"}
        if types_match:
            for token in re.findall(r'[a-zA-Z][\w-]*', types_match.group(1)):
                all_types.add(token)

        # Get objects for each type
        for t in all_types:
            objs = env_state.get_objects_by_type(t)
            if objs:
                objects[t] = objs

        # Also extract objects from problem file :objects block
        if self.problem_pddl:
            obj_match = re.search(r'\(:objects\s', self.problem_pddl)
            if obj_match:
                end = self._find_balanced_end(self.problem_pddl, obj_match.start())
                obj_text = self.problem_pddl[obj_match.start():end]
                # Parse "name1 name2 - type" groups
                for m in re.finditer(
                    r'((?:[\w-]+\s+)+)-\s+([\w-]+)', obj_text
                ):
                    type_name = m.group(2)
                    names = m.group(1).split()
                    if type_name not in objects:
                        objects[type_name] = []
                    for n in names:
                        if n not in objects[type_name]:
                            objects[type_name].append(n)

        # PDDL inheritance: a parameter declared `?x - subtype` is satisfied
        # by any object of `subtype` OR its subtypes. The previous code
        # propagated child→parent, which produced empty pools for
        # subtypes like `configuration_file - file` because env_state only
        # populates the parent. Walk the declared :types twice:
        #   pass 1 — record (child, parent) edges
        #   pass 2 — for any subtype without its own objects, inherit the
        #            closest non-empty ancestor's pool. Standard typed-PDDL
        #            grounding behavior.
        parent_of: dict[str, str] = {}
        if types_match:
            for m in re.finditer(r'((?:[\w-]+\s+)+)-\s+([\w-]+)', types_match.group(1)):
                parent = m.group(2)
                for child in m.group(1).split():
                    parent_of[child] = parent
        # Resolve ancestors transitively. We deliberately STOP at `object`
        # because `objects["object"]` is the union of every concrete pool,
        # and inheriting from it would re-introduce the same supertype leak
        # we just removed (e.g. a `?x - some_unmodeled_type` declared as
        # `some_unmodeled_type - object` would silently grab every system
        # object). Only inherit from a named intermediate ancestor that
        # already has a concrete pool (e.g. `configuration_file - file`).
        for subtype in list(parent_of.keys()):
            if objects.get(subtype):
                continue
            cur = parent_of.get(subtype)
            visited = {subtype}
            while cur and cur != "object" and cur not in visited:
                visited.add(cur)
                pool = objects.get(cur)
                if pool:
                    objects[subtype] = list(pool)
                    break
                cur = parent_of.get(cur)

        # Deliberately set `objects["object"]` to the EMPTY pool.
        #
        # PDDL treats `object` as the root supertype, but a *parameter*
        # declared `?x - object` means the action's type was never
        # inferred — there is no concrete pool that's semantically
        # right for it. Previously this pool was the union of every
        # concrete pool, which let actions like
        #   (:action set_default_expire_date
        #     :parameters (?expiredate - object) ...)
        # ground `?expiredate` to a username, group name, file path, etc.
        # The resulting concretized command (`passwd --expire tape`) was
        # always going to fail.
        #
        # Empty pool ⇒ such actions are inapplicable in EW, which is the
        # correct PDDL-grounded outcome: the *domain* is under-specified
        # for that action and the refiner should be the one that tightens
        # the parameter type. Standard typed-PDDL behavior.
        objects["object"] = []

        return objects

    # ─── Predicate Index ─────────────────────────────────────────────────

    def _rebuild_pred_index(self):
        """Rebuild the predicate-name → facts index from current state."""
        self._pred_index.clear()
        for fact in self.state:
            pred = fact[0]
            if pred not in self._pred_index:
                self._pred_index[pred] = set()
            self._pred_index[pred].add(fact)

    def _update_pred_index(self, added: set[GroundLiteral], removed: set[GroundLiteral]):
        """Incrementally update predicate index after effect application."""
        for fact in removed:
            pred = fact[0]
            if pred in self._pred_index:
                self._pred_index[pred].discard(fact)
        for fact in added:
            pred = fact[0]
            if pred not in self._pred_index:
                self._pred_index[pred] = set()
            self._pred_index[pred].add(fact)

    # ─── Applicability Checking ──────────────────────────────────────────

    def get_applicable_actions(self, max_per_schema: int = 3) -> list[GroundedAction]:
        """
        Find applicable (grounded) actions using two-level sampling.

        To ensure action diversity (not dominated by schemas with many groundings):
        1. Predicate pre-filter: skip schemas whose required predicates have no facts
        2. For each surviving schema, generate up to `max_per_schema` groundings
        3. Return the combined pool for uniform sampling

        This ensures that all applicable action schemas have roughly equal
        representation in the candidate pool.

        Args:
            max_per_schema: Max groundings to generate per action schema.

        Returns:
            List of GroundedAction objects whose preconditions are satisfied.
        """
        applicable: list[GroundedAction] = []
        schemas_with_groundings = 0

        for idx, action in enumerate(self.actions):
            # Tier 1: Predicate pre-filter
            required_preds = self._action_required_preds[idx]
            if required_preds and not all(
                pred in self._pred_index and self._pred_index[pred]
                for pred in required_preds
            ):
                continue

            # Tier 2: Generate limited groundings per schema
            groundings = self._ground_action_from_state(action, max_per_schema)
            if groundings:
                applicable.extend(groundings)
                schemas_with_groundings += 1

        if applicable:
            logger.debug(
                f"Found {len(applicable)} applicable groundings "
                f"from {schemas_with_groundings} action schemas"
            )

        return applicable

    def _ground_action_from_state(
        self,
        action: ParsedAction,
        max_candidates: int = 100,
    ) -> list[GroundedAction]:
        """
        Ground an action using state facts to constrain variable bindings.

        For each positive precondition (pred ?x ?y), find matching facts in state
        and constrain ?x, ?y to the values that appear. Then check all preconditions.
        """
        if not action.parameters:
            # Parameterless action: just check preconditions directly
            if self._check_preconditions(action, {}):
                pddl_action = action.to_pddl_action()
                return [GroundedAction(action=pddl_action, bindings={})]
            return []

        # Build variable candidates from positive preconditions
        # For each variable, collect the set of possible values
        var_candidates: dict[str, set[str]] = {}

        # Initialize from type-based objects. We deliberately do NOT fall
        # back to the `object` supertype when a declared type has no pool:
        # that fallback let configuration-file paths bind to `?p - port`
        # and produced bogus commands (e.g. `nft add rule ... udp dport
        # /etc/vdpau/wrapper.cfg`) that dominated the EW discrepancy log.
        # Empty typed pool ⇒ no valid grounding, which is correct PDDL.
        for var, ptype in action.parameters:
            type_objs = self.objects.get(ptype, [])
            var_candidates[var] = set(type_objs) if type_objs else set()
            if not type_objs:
                return []

        # Constrain using positive preconditions from state
        for precond in action.pos_preconditions:
            pred_name = precond[0]
            pred_args = precond[1:]  # these are ?var names

            # Get all facts matching this predicate
            matching_facts = self._pred_index.get(pred_name, set())
            if not matching_facts:
                return []  # required predicate has no facts → impossible

            # For each argument position that is a variable, collect possible values
            for i, arg in enumerate(pred_args):
                if arg.startswith('?'):
                    possible = {
                        fact[i + 1]
                        for fact in matching_facts
                        if len(fact) > i + 1
                    }
                    if arg in var_candidates:
                        var_candidates[arg] &= possible
                    else:
                        var_candidates[arg] = possible

                    if not var_candidates.get(arg):
                        return []  # no possible values for this variable

        # Check if any variable has empty candidates
        for var, cands in var_candidates.items():
            if not cands:
                return []

        # Generate grounded candidates via constrained enumeration
        # To avoid combinatorial explosion, limit total candidates
        results: list[GroundedAction] = []
        variables = [(v, list(c)) for v, c in var_candidates.items() if c]

        if not variables:
            return []

        # Estimate total combinations
        total_combos = 1
        for _, cands in variables:
            total_combos *= len(cands)
            if total_combos > 10000:
                break

        if total_combos <= 1000:
            # Enumerate all combinations
            bindings_list = self._enumerate_bindings(variables, 0, {})
        else:
            # Random sampling
            bindings_list = self._sample_bindings(variables, min(1000, max_candidates * 5))

        pddl_action = action.to_pddl_action()

        for bindings in bindings_list:
            if len(results) >= max_candidates:
                break
            if self._check_preconditions(action, bindings):
                results.append(GroundedAction(action=pddl_action, bindings=bindings))

        return results

    def _enumerate_bindings(
        self,
        variables: list[tuple[str, list[str]]],
        idx: int,
        current: dict[str, str],
    ) -> list[dict[str, str]]:
        """Recursively enumerate all variable bindings."""
        if idx == len(variables):
            return [dict(current)]

        var_name, candidates = variables[idx]
        results = []
        for val in candidates:
            current[var_name] = val
            results.extend(self._enumerate_bindings(variables, idx + 1, current))
            if len(results) > 1000:
                break
        if var_name in current and idx < len(variables):
            del current[var_name]
        return results

    def _sample_bindings(
        self,
        variables: list[tuple[str, list[str]]],
        num_samples: int,
    ) -> list[dict[str, str]]:
        """Randomly sample variable bindings."""
        results = []
        seen = set()
        for _ in range(num_samples):
            binding = {}
            for var_name, candidates in variables:
                binding[var_name] = random.choice(candidates)
            key = tuple(sorted(binding.items()))
            if key not in seen:
                seen.add(key)
                results.append(binding)
        return results

    def _check_preconditions(
        self,
        action: ParsedAction,
        bindings: dict[str, str],
    ) -> bool:
        """Check if all preconditions are satisfied in the current state."""
        # Check positive preconditions (must be in state)
        for precond in action.pos_preconditions:
            ground = self._substitute(precond, bindings)
            if ground is None:
                return False  # ungroundable variable
            if ground not in self.state:
                return False

        # Check negative preconditions (must NOT be in state)
        for precond in action.neg_preconditions:
            ground = self._substitute(precond, bindings)
            if ground is None:
                continue  # can't check, assume satisfied
            if ground in self.state:
                return False

        return True

    def _substitute(
        self,
        literal: tuple[str, ...],
        bindings: dict[str, str],
    ) -> Optional[GroundLiteral]:
        """Substitute variable bindings into a literal tuple."""
        result = []
        for token in literal:
            if token.startswith('?'):
                if token in bindings:
                    result.append(bindings[token])
                else:
                    return None  # unbound variable
            else:
                result.append(token)
        return tuple(result)

    # ─── Effect Application ──────────────────────────────────────────────

    def apply_effects(self, action: ParsedAction, bindings: dict[str, str]):
        """Apply action effects to update the current state."""
        to_add: set[GroundLiteral] = set()
        to_del: set[GroundLiteral] = set()

        for eff in action.add_effects:
            ground = self._substitute(eff, bindings)
            if ground is not None:
                to_add.add(ground)

        for eff in action.del_effects:
            ground = self._substitute(eff, bindings)
            if ground is not None:
                to_del.add(ground)

        # STRIPS semantics: delete then add
        self.state = (self.state - to_del) | frozenset(to_add)

        # Update predicate index incrementally
        self._update_pred_index(to_add, to_del)

    # ─── State Reset ─────────────────────────────────────────────────────

    def reset_state(self):
        """Reset state to initial state (for starting a new walk)."""
        self.state = self._build_initial_state(self.env_state, self.problem_pddl)
        self._rebuild_pred_index()
