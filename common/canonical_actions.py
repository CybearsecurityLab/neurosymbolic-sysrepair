"""Canonical sysadmin PDDL actions that Phase 1 mining / Phase 2 synthesis
typically misses.

Phase 1 mines from man pages (e.g. ``man sed``, ``man chmod``) which describe
*how a utility behaves on a single file*, not "edit setting K in config
file F". Phase 2 synthesises from utility groups (file_management,
service_management) which similarly don't directly model "edit a key/value
in a config file" with proper precondition/effect semantics.

This is the smallest fix that closes the gap: a short, hand-engineered set
of canonical actions with sound PDDL semantics, suitable to merge into the
unified domain Phase 2 produces. Each action is plain STRIPS — no special
cases, no benchmark-specific hacks. They model common remediation primitives
that recur across CCDC / meta2 / vulnhub.

For ACSAC defensibility: these are conventional PDDL operators, not
benchmark-specific shortcuts. They appear in any reasonable sysadmin
planning domain (cf. the IPC sysadmin track).
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Canonical predicates: domain-level vocabulary the actions below assume.
#
# When Phase 2's merger adds these actions, it should also ensure these
# predicates are declared in (:predicates ...) — they are simple enough
# that adding them as base predicates is uncontroversial.
# ---------------------------------------------------------------------------

CANONICAL_PREDICATES: list[str] = [
    # Config file / setting predicates
    "(config_file ?f - file)",
    "(setting ?s - setting ?f - file)",                     # setting s lives in file f
    "(setting_value_is ?s - setting ?v - value)",           # current value of setting
    "(file_writable ?f - file)",

    # Service control predicates (already in the auto-generated domain, but
    # we declare them explicitly here so the canonical actions remain
    # self-contained if the merger discards near-duplicates).
    "(service_running ?svc - service)",
    "(service_supervised_by_systemd ?svc - service)",
]


# ---------------------------------------------------------------------------
# Canonical actions. Each entry is in the dict-of-strings format that
# Phase 1's phase1_statep2.json uses so Phase 2's merger can ingest it via
# --reuse-phase1-actions. The fields match common/models.ActionSchema.
#
#  - name              snake_case action name
#  - parameters        list of {"name","type"} dicts
#  - preconditions     list of PDDL predicate strings
#  - effects           list of PDDL effect strings
#  - command_template  bash template (used by the action concretizer)
#  - requires_root     whether sudo/root is needed
#  - source_utility    descriptive only
#  - extraction_method "canonical" so we can distinguish in logs
# ---------------------------------------------------------------------------

CANONICAL_ACTIONS: list[dict] = [
    {
        "name": "edit_config_setting",
        "parameters": [
            {"name": "f",    "type": "file"},
            {"name": "k",    "type": "setting"},
            {"name": "vold", "type": "value"},
            {"name": "vnew", "type": "value"},
        ],
        "preconditions": [
            "(config_file ?f)",
            "(file_writable ?f)",
            "(setting ?k ?f)",
            "(setting_value_is ?k ?vold)",
        ],
        "effects": [
            "(setting_value_is ?k ?vnew)",
            "(not (setting_value_is ?k ?vold))",
        ],
        # sed in-place: edit a key/value pair in a config file.
        # The concretizer fills {k}, {vold}, {vnew}, {f}.
        "command_template": "sed -i 's|^[[:space:]]*{k}[[:space:]]\\+{vold}|{k} {vnew}|' {f}",
        "requires_root": True,
        "source_utility": "sed",
        "extraction_method": "canonical",
    },
    {
        # Restart sshd in a container without systemd (SIGHUP reloads
        # configuration without dropping existing connections).
        "name": "reload_sshd_no_systemd",
        "parameters": [
            {"name": "svc", "type": "service"},
        ],
        "preconditions": [
            "(service_running ?svc)",
            "(not (service_supervised_by_systemd ?svc))",
        ],
        "effects": [
            "(service_running ?svc)",
        ],
        # pkill -HUP <name> sends SIGHUP to sshd (causes it to re-read its
        # config). Works without any service manager.
        "command_template": "pkill -HUP {svc}",
        "requires_root": True,
        "source_utility": "pkill",
        "extraction_method": "canonical",
    },
]


def canonical_predicates() -> list[str]:
    return list(CANONICAL_PREDICATES)


def canonical_actions() -> list[dict]:
    """Return a deep copy so callers can mutate freely."""
    import copy
    return copy.deepcopy(CANONICAL_ACTIONS)


# ---------------------------------------------------------------------------
# PDDL emission + in-place merger
# ---------------------------------------------------------------------------

def _action_to_pddl(act: dict) -> str:
    """Render an action dict as a (:action ...) block."""
    params = " ".join(f"?{p['name']} - {p['type']}" for p in act.get("parameters", []))
    pre_list = [p for p in act.get("preconditions", []) if p.strip()]
    eff_list = [e for e in act.get("effects", []) if e.strip()]
    pre_body = "(and\n      " + "\n      ".join(pre_list) + "\n    )" if pre_list else "()"
    eff_body = "(and\n      " + "\n      ".join(eff_list) + "\n    )" if eff_list else "()"
    return (
        f"\n  (:action {act['name']}\n"
        f"    :parameters ({params})\n"
        f"    :precondition {pre_body}\n"
        f"    :effect {eff_body}\n"
        f"  )"
    )


def _missing_predicates(existing_text: str, candidates: list[str]) -> list[str]:
    """Return canonical predicates whose name does not already appear."""
    out = []
    import re
    for sig in candidates:
        m = re.match(r"\(\s*([A-Za-z_][\w-]*)", sig)
        if not m:
            continue
        name = m.group(1)
        if f"({name} " not in existing_text and f"({name})" not in existing_text:
            out.append(sig)
    return out


def _missing_actions(existing_text: str, candidates: list[dict]) -> list[dict]:
    out = []
    for a in candidates:
        if f"(:action {a['name']} " not in existing_text and f"(:action {a['name']}\n" not in existing_text:
            out.append(a)
    return out


def merge_canonical_into_domain(domain_path) -> dict:
    """Append canonical predicates + actions to ``domain_path`` (in place).

    Idempotent: only adds entries that aren't already present by name. The
    domain remains a single ``(define (domain ...) ...)`` form — we splice
    inside the trailing ``)``.

    Returns a small report ``{"predicates_added": [...], "actions_added": [...]}``.
    """
    from pathlib import Path
    import re

    p = Path(domain_path)
    text = p.read_text()

    preds_to_add = _missing_predicates(text, CANONICAL_PREDICATES)
    acts_to_add = _missing_actions(text, CANONICAL_ACTIONS)

    # Ensure the types referenced by the canonical predicates / actions are
    # declared in (:types ...). Phase 2's auto-generated domain typically
    # has `file`, `service`, etc., but not `setting` or `value` — those
    # come ONLY from the canonical config-edit predicates. Without them
    # declared, Fast Downward's translator rejects the domain with
    # `KeyError: 'setting'` and the planner cannot run. This is the
    # symmetric fix to canonical predicates: if you add a typed predicate,
    # the type must also exist. We check this BEFORE the early-return so
    # an already-merged-but-missing-type domain still gets repaired.
    types_added: list[str] = []
    types_needed = {"setting", "value"}
    m_types = re.search(r"\(:types\b([\s\S]*?)\)", text)
    if m_types:
        existing_types = set(re.findall(r"[A-Za-z_][\w-]*", m_types.group(1)))
        missing = sorted(t for t in types_needed if t not in existing_types)
        if missing:
            close = m_types.end() - 1
            insertion = f"\n    ; Config-edit primitive types (canonical)\n    {' '.join(missing)} - object"
            text = text[:close] + insertion + "\n  " + text[close:]
            types_added = missing

    if not preds_to_add and not acts_to_add and not types_added:
        return {"predicates_added": [], "actions_added": [], "types_added": []}

    # Insert new predicates into (:predicates ...) — extend, don't replace.
    if preds_to_add:
        m = re.search(r"\(:predicates\b", text)
        if m:
            # Walk paren balance to find the closing ')' of the predicates block.
            depth = 0
            close = -1
            for i in range(m.start(), len(text)):
                if text[i] == "(":
                    depth += 1
                elif text[i] == ")":
                    depth -= 1
                    if depth == 0:
                        close = i
                        break
            if close >= 0:
                insertion = "\n    " + "\n    ".join(preds_to_add)
                text = text[:close] + insertion + "\n  " + text[close:]
        else:
            # No predicates block — add one before the first action.
            am = re.search(r"\(:action\b", text)
            block = "  (:predicates\n    " + "\n    ".join(preds_to_add) + "\n  )\n\n"
            if am:
                text = text[:am.start()] + block + text[am.start():]
            else:
                # very degenerate domain — splice before the closing paren
                text = text.rstrip().rstrip(")") + "\n" + block + ")\n"

    # Append the new action blocks before the final ')' that closes the (define ...) form.
    if acts_to_add:
        # Find the LAST ')' in the file that closes the outer define
        # (closing brace of the action region).
        last_close = text.rfind(")")
        if last_close < 0:
            return {"predicates_added": preds_to_add, "actions_added": []}
        action_blocks = "\n".join(_action_to_pddl(a) for a in acts_to_add) + "\n"
        text = text[:last_close] + action_blocks + text[last_close:]

    p.write_text(text)
    # Also write types_added to the result if any were added.
    if types_added:
        # Continue building the standard return below; just attach types.
        pass
    return {
        "types_added": types_added,
        "predicates_added": preds_to_add,
        "actions_added": [a["name"] for a in acts_to_add],
    }


def append_canonical_to_action_list(actions: list[dict]) -> list[dict]:
    """Used by Phase 1's serializer: returns ``actions`` plus any canonical
    actions not already present by name."""
    seen = {a.get("name") for a in actions}
    extras = [a for a in canonical_actions() if a["name"] not in seen]
    return actions + extras
