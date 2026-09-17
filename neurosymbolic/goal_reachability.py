"""Why a goal atom may be unreachable, computed before the planner runs.

Diagnostic only. Fast Downward already decides solvability correctly; what it
does not report is WHICH goal atom failed and WHY. Its output for an
unreachable goal is a synthetic task printing "Translator operators: 0", which
was misread in this project as "the type/predicate name clash pruned every
operator" and nearly produced a rename touching all 46 on-disk domains.

Three checks, one per problem-generation defect observed on ccdc:

    no_producer               no action's effect adds the goal predicate.
    untyped_param             a producing action has a parameter whose type has
                              no declared object, so it has zero groundings.
                              (ccdc-15: set_config_directive took ?svc - service
                              against a problem declaring no service object.)
    unestablished_precondition
                              every producer needs a precondition that is
                              neither in :init nor added by any action.
                              (ccdc-05: the only producer of pubkey_auth_enabled
                              requires pubkey_auth_disabled, which nothing
                              establishes.)

Deliberately a relaxed, name-level analysis: it ignores argument identity, so
it can miss a defect but should not invent one. It never raises.
"""

from __future__ import annotations

import re

_ATOM = re.compile(r"\((\w[\w-]*)")
_TYPED_PARAM = re.compile(r"\?[\w-]+\s*-\s*([\w-]+)")
_OBJ_TYPE = re.compile(r"-\s*([\w-]+)")


def _atoms(text: str) -> set[str]:
    return {a for a in _ATOM.findall(text) if a not in ("and", "not", "or")}


def goal_reachability_report(domain_pddl: str, problem_pddl: str) -> dict:
    """Return {'goals': n, 'problems': [...]}; empty problems means nothing found."""
    try:
        goal_m = re.search(r"\(:goal(.*)", problem_pddl, re.S)
        if not goal_m:
            return {"goals": 0, "problems": []}
        goals = sorted(_atoms(goal_m.group(1)))

        init_m = re.search(r"\(:init(.*?)\(:goal", problem_pddl, re.S)
        init = _atoms(init_m.group(1)) if init_m else set()

        obj_m = re.search(r"\(:objects(.*?)\)\s*\(:init", problem_pddl, re.S)
        declared_types = set(_OBJ_TYPE.findall(obj_m.group(1))) if obj_m else set()

        actions: dict[str, dict] = {}
        for m in re.finditer(r"\(:action\s+([\w-]+)(.*?)(?=\(:action|\Z)",
                             domain_pddl, re.S):
            body = m.group(2)
            pm = re.search(r":parameters\s*\((.*?)\)", body, re.S)
            em = re.search(r":effect(.*)", body, re.S)
            prem = re.search(r":precondition(.*?):effect", body, re.S)
            actions[m.group(1)] = {
                "ptypes": set(_TYPED_PARAM.findall(pm.group(1))) if pm else set(),
                "eff": _atoms(em.group(1)) if em else set(),
                "pre": _atoms(prem.group(1)) if prem else set(),
            }
        if not actions:
            return {"goals": len(goals), "problems": [{"why": "no_actions_in_domain"}]}

        # Relaxed reachability by fixpoint, not "some action adds it". The
        # weaker test cannot see circularity: a reload action that both
        # requires and adds (service_running) looks like a producer, so a goal
        # that nothing can actually establish is reported as fine. Iterating
        # from :init and only firing actions whose preconditions are ALREADY
        # reachable is what Fast Downward's own relaxed analysis does.
        groundable_actions = {
            n: a for n, a in actions.items()
            if not (a["ptypes"] - declared_types - {"object"})
        }
        reachable = set(init)
        changed = True
        while changed:
            changed = False
            for a in groundable_actions.values():
                if a["pre"] <= reachable and not a["eff"] <= reachable:
                    reachable |= a["eff"]
                    changed = True
        all_effects = reachable

        problems = []
        for g in goals:
            if g in init:
                continue
            producers = [n for n, a in actions.items() if g in a["eff"]]
            if not producers:
                problems.append({"goal": g, "why": "no_producer"})
                continue
            groundable = [n for n in producers
                          if not (actions[n]["ptypes"] - declared_types - {"object"})]
            if not groundable:
                missing: set[str] = set()
                for n in producers:
                    missing |= actions[n]["ptypes"] - declared_types - {"object"}
                problems.append({
                    "goal": g, "why": "untyped_param",
                    "producers": producers[:3],
                    "missing_object_types": sorted(missing),
                })
                continue
            if g not in reachable:
                problems.append({
                    "goal": g, "why": "unestablished_precondition",
                    "producers": groundable[:3],
                    "unreachable_preconditions": sorted(
                        set().union(*(actions[n]["pre"] for n in groundable))
                        - reachable)[:5],
                })
        return {"goals": len(goals), "problems": problems}
    except Exception as exc:  # a diagnostic must never break a run
        return {"error": f"{type(exc).__name__}: {str(exc)[:80]}"}
