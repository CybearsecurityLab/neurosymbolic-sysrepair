#!/usr/bin/env python3
"""Find actions in sysadmin.pddl that can't be concretized."""

import re
import sys
import os
import logging

# Suppress warnings from concretizer
logging.disable(logging.WARNING)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phase3.action_concretizer import ActionConcretizer
from phase3.models import GroundedAction, PDDLAction

def extract_actions_with_params(pddl_path):
    """Extract all action names and their parameters from a PDDL domain file."""
    with open(pddl_path) as f:
        content = f.read()

    actions = {}
    for m in re.finditer(r'\(:action\s+(\S+)\s*:parameters\s*\(([^)]*)\)', content):
        name = m.group(1)
        params_str = m.group(2).strip()
        params = {}
        param_list = []
        for pm in re.finditer(r'\?(\w[\w-]*)\s*-\s*(\w+)', params_str):
            param_name = pm.group(1)
            param_type = pm.group(2)
            params[f"?{param_name}"] = f"test_{param_name}"
            param_list.append((f"?{param_name}", param_type))
        # Also catch untyped params
        if not param_list:
            for pm in re.finditer(r'\?(\w[\w-]*)', params_str):
                param_name = pm.group(1)
                params[f"?{param_name}"] = f"test_{param_name}"
                param_list.append((f"?{param_name}", "object"))
        actions[name] = (params, param_list)

    # Also catch actions without parameters section found
    for m in re.finditer(r'\(:action\s+(\S+)', content):
        name = m.group(1)
        if name not in actions:
            actions[name] = ({}, [])

    return actions

def main():
    pddl_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "pddl_output", "phase2", "sysadmin.pddl")

    actions = extract_actions_with_params(pddl_path)
    print(f"Total actions in domain: {len(actions)}")

    concretizer = ActionConcretizer()

    missing = []
    covered = []

    for action_name, (params, param_list) in actions.items():
        pddl_action = PDDLAction(name=action_name, parameters=param_list, preconditions=[], effects=[])
        ga = GroundedAction(action=pddl_action, bindings=params)
        result = concretizer.concretize(ga)
        if result is None:
            missing.append(action_name)
        else:
            covered.append(action_name)

    print(f"Covered: {len(covered)}")
    print(f"Missing: {len(missing)}")
    print()

    # Group missing actions by prefix
    groups = {}
    for name in missing:
        prefix = name.split("_")[0] if "_" in name else name
        groups.setdefault(prefix, []).append(name)

    print("=== MISSING ACTIONS BY PREFIX ===")
    for prefix in sorted(groups.keys()):
        names = groups[prefix]
        print(f"\n--- {prefix} ({len(names)}) ---")
        for n in sorted(names):
            print(f"  {n}")

if __name__ == "__main__":
    main()
