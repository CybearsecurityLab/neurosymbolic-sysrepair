"""Enrich a generated PDDL domain + problem with environment-aware preconditions.

This is the canonical PDDL-engineering answer to "the domain has actions that
reference tools absent from this scenario container":

  * For each action with a known ``command_template``, infer the primary
    command (systemctl, iptables, apt-get, …).
  * If that command maps to a Capability (see ``common.env_capabilities``),
    insert ``(<predicate>)`` into the action's ``:precondition``.
  * Add the corresponding 0-arity predicates to the domain's ``(:predicates …)``
    block.
  * Add the positive capability facts (from a probe of THIS scenario's
    container) to the problem's ``(:init …)`` block.

Net effect: Fast Downward grounding will *not* consider those actions when
their precondition is unsatisfied, so Phase 3 walks no longer generate
"command not found" / "systemctl-no-systemd" discrepancies. EW rises by
removing infeasibility noise; nothing about the auto-scale or refinement
loop changes.

The original files are backed up (``.pre-enrich.pddl``) before rewriting.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Iterable

from .env_capabilities import (
    CAPABILITIES, capability_to_predicate, command_to_capability,
)

logger = logging.getLogger("DomainEnrichment")


# ---------------------------------------------------------------------------
# Action-template inference
# ---------------------------------------------------------------------------

_PREFIX = {"sudo", "env", "timeout", "nohup", "exec", "bash", "/bin/bash"}


def _primary_command(template: str) -> str | None:
    """Return the lowercase first non-prefix token of a bash template."""
    if not template:
        return None
    tokens = template.strip().split()
    i = 0
    while i < len(tokens) and "=" in tokens[i] and not tokens[i].startswith("/"):
        i += 1
    while i < len(tokens) and tokens[i].lower() in _PREFIX:
        i += 1
    if i >= len(tokens):
        return None
    cmd = tokens[i].lower()
    return cmd.rsplit("/", 1)[-1] if "/" in cmd else cmd


def action_capabilities(
    phase1_metadata: Path | str,
    concretizer_cache: Path | str | None = None,
    partial_domains: Path | str | None = None,
) -> dict[str, str]:
    """Returns ``{action_name: capability_key}`` for every action whose
    template's primary command maps to a known Capability.

    Sources, in order of preference:

    * ``phase1_metadata`` — the canonical Phase 1 mined action list.
    * ``partial_domains`` — Phase 2's LLM-synthesised actions, before
      they're merged into the unified domain. Many actions only exist
      here (their ``command_template`` was never round-tripped through
      the concretizer cache), so without this pass the capability
      enrichment misses iptables/systemctl-using LLM-synth actions and
      they leak into the EW walks as ``command not found`` discrepancies.
    * ``concretizer_cache`` — actions whose templates were filled in at
      EW time. Useful for second-and-later pipeline cycles.
    """
    cmd_to_cap = command_to_capability()
    out: dict[str, str] = {}

    def _consider(name: str, template: str) -> None:
        cmd = _primary_command(template)
        if not cmd: return
        cap = cmd_to_cap.get(cmd)
        if cap: out[name] = cap

    p1 = Path(phase1_metadata)
    if p1.exists():
        try:
            for a in json.loads(p1.read_text()).get("actions", []):
                _consider(a.get("name", ""), a.get("command_template", "") or "")
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"could not read {p1}: {e}")

    if partial_domains:
        pd = Path(partial_domains)
        if pd.exists():
            try:
                workers = json.loads(pd.read_text())
                if isinstance(workers, list):
                    for w in workers:
                        for a in w.get("actions", []) or []:
                            _consider(a.get("name", ""),
                                      a.get("command_template", "") or "")
            except (OSError, json.JSONDecodeError) as e:
                logger.warning(f"could not read {pd}: {e}")

    if concretizer_cache:
        c = Path(concretizer_cache)
        if c.exists():
            try:
                cache = json.loads(c.read_text())
                for key, val in cache.items():
                    cmd = val.get("command") if isinstance(val, dict) else val
                    m = re.match(r"^[A-Za-z][A-Za-z0-9_]*", key)
                    if m and cmd:
                        _consider(m.group(0), cmd)
            except (OSError, json.JSONDecodeError) as e:
                logger.warning(f"could not read {c}: {e}")
    return out


# ---------------------------------------------------------------------------
# Domain rewrite
# ---------------------------------------------------------------------------

_PREDICATES_HEAD = re.compile(r"\(:predicates\b")
_ACTION_HEAD = re.compile(r"\(:action\s+([A-Za-z_][\w-]*)\b")
_PRECOND_RE = re.compile(r":precondition\b\s*", re.MULTILINE)


def _balanced_block(text: str, start: int) -> tuple[int, int] | None:
    """Given an opening-paren index, return (start, end_inclusive_of_close)."""
    if text[start] != "(":
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return (start, i)
    return None


def _add_preds_to_predicates_block(text: str, new_preds: Iterable[str]) -> str:
    """Insert ``(<predicate>)`` lines into the (:predicates ...) block.
    If the block doesn't exist, create it before the first (:action ...).
    """
    new_preds = list(new_preds)
    if not new_preds:
        return text
    m = _PREDICATES_HEAD.search(text)
    if not m:
        # Insert a fresh predicates block before the first action.
        am = _ACTION_HEAD.search(text)
        block = "  (:predicates\n    " + "\n    ".join(f"({p})" for p in new_preds) + "\n  )\n\n"
        if am:
            return text[:am.start()] + block + text[am.start():]
        # Or just before the final ')' of the domain.
        return text.rstrip().rstrip(")") + "\n" + block + ")\n"
    block_start = m.start()
    block_end_close = _balanced_block(text, block_start)
    if not block_end_close:
        logger.warning("predicates block did not balance — leaving file unchanged")
        return text
    _, close = block_end_close
    # Skip predicates already present (string match is sufficient for our
    # 0-arity capability predicates).
    existing = text[block_start:close + 1]
    to_add = [p for p in new_preds if f"({p})" not in existing]
    if not to_add:
        return text
    insertion = "\n    " + "\n    ".join(f"({p})" for p in to_add)
    return text[:close] + insertion + "\n  " + text[close:]


def _add_precondition_to_action(text: str, action_name: str, pred: str) -> str:
    """Insert (<pred>) into the named action's :precondition.

    If there's no :precondition keyword, add one with ``(and (<pred>))``.
    If there's a single atomic precondition, wrap into ``(and (orig) (<pred>))``.
    If it's already ``(and ...)``, splice the pred in.
    """
    am = list(re.finditer(rf"\(:action\s+{re.escape(action_name)}\b", text))
    if not am:
        return text
    a_start = am[0].start()
    bounds = _balanced_block(text, a_start)
    if not bounds:
        return text
    _, a_close = bounds
    action_block = text[a_start:a_close + 1]
    if f"({pred})" in action_block:
        return text  # already present

    pre_m = _PRECOND_RE.search(action_block)
    if not pre_m:
        # Insert :precondition (<pred>) before :effect or before the trailing ')'.
        eff = re.search(r":effect\b", action_block)
        insert_at = eff.start() if eff else len(action_block) - 1
        new_block = action_block[:insert_at] + f":precondition ({pred})\n    " + action_block[insert_at:]
        return text[:a_start] + new_block + text[a_close + 1:]

    # Find the precondition formula (next balanced paren after the keyword)
    after = pre_m.end()
    rel_open = action_block.find("(", after)
    if rel_open < 0:
        return text
    rel_close = _balanced_block(action_block, rel_open)
    if not rel_close:
        return text
    _, rel_end = rel_close
    formula = action_block[rel_open:rel_end + 1]
    body = formula[1:-1].strip()

    if body.lower().startswith("and"):
        new_formula = "(and " + body[3:].strip() + f" ({pred}))"
    elif not body:
        new_formula = f"({pred})"
    else:
        new_formula = f"(and {formula} ({pred}))"

    new_block = action_block[:rel_open] + new_formula + action_block[rel_end + 1:]
    return text[:a_start] + new_block + text[a_close + 1:]


def enrich_domain_text(
    domain_text: str,
    action_to_capability: dict[str, str],
) -> tuple[str, set[str]]:
    """Returns (new_domain_text, added_predicates)."""
    cap_to_pred = capability_to_predicate()
    used_preds: set[str] = set()
    new_text = domain_text
    for action, cap in action_to_capability.items():
        pred = cap_to_pred.get(cap)
        if not pred:
            continue
        before = new_text
        new_text = _add_precondition_to_action(new_text, action, pred)
        if new_text != before:
            used_preds.add(pred)
    if used_preds:
        new_text = _add_preds_to_predicates_block(new_text, used_preds)
    return new_text, used_preds


# ---------------------------------------------------------------------------
# Problem rewrite
# ---------------------------------------------------------------------------

_INIT_HEAD = re.compile(r"\(:init\b")


def enrich_problem_text(problem_text: str, init_facts: Iterable[str]) -> str:
    facts = list(init_facts)
    if not facts:
        return problem_text
    m = _INIT_HEAD.search(problem_text)
    if not m:
        # Inject a minimal init before :goal if missing entirely.
        gm = re.search(r"\(:goal\b", problem_text)
        block = "  (:init\n    " + "\n    ".join(facts) + "\n  )\n"
        if gm:
            return problem_text[:gm.start()] + block + problem_text[gm.start():]
        return problem_text.rstrip().rstrip(")") + "\n" + block + ")\n"
    bounds = _balanced_block(problem_text, m.start())
    if not bounds:
        return problem_text
    _, close = bounds
    existing = problem_text[m.start():close + 1]
    to_add = [f for f in facts if f not in existing]
    if not to_add:
        return problem_text
    insertion = "\n    " + "\n    ".join(to_add)
    return problem_text[:close] + insertion + "\n  " + problem_text[close:]


# ---------------------------------------------------------------------------
# Entrypoint used by run_pipeline
# ---------------------------------------------------------------------------

def enrich_in_place(
    domain_path: Path,
    problem_path: Path | None,
    phase1_metadata: Path,
    capabilities: dict[str, bool],
    concretizer_cache: Path | None = None,
    partial_domains: Path | None = None,
    backup_suffix: str = ".pre-enrich.pddl",
) -> dict:
    """Add capability-based preconditions to ``domain_path`` and capability
    facts to ``problem_path``'s :init. Returns a small report dict.
    """
    domain_path = Path(domain_path)
    if not domain_path.exists():
        raise FileNotFoundError(f"domain not found: {domain_path}")

    domain_path.with_suffix(backup_suffix).write_text(domain_path.read_text())

    cap_to_pred = capability_to_predicate()
    act_to_cap = action_capabilities(
        phase1_metadata,
        concretizer_cache=concretizer_cache,
        partial_domains=partial_domains,
    )
    new_domain, added_preds = enrich_domain_text(domain_path.read_text(), act_to_cap)
    domain_path.write_text(new_domain)

    facts_added: list[str] = []
    if problem_path:
        problem_path = Path(problem_path)
        if problem_path.exists():
            problem_path.with_suffix(backup_suffix).write_text(problem_path.read_text())
            facts = [f"({p})" for p in added_preds if capabilities.get(_pred_to_cap(p), False)]
            new_problem = enrich_problem_text(problem_path.read_text(), facts)
            problem_path.write_text(new_problem)
            facts_added = facts

    report = {
        "actions_with_capability_preconds": len(act_to_cap),
        "predicates_added": sorted(added_preds),
        "init_facts_added": facts_added,
    }
    logger.info(
        f"enrich domain: {len(act_to_cap)} actions tagged, "
        f"{len(added_preds)} predicates added, "
        f"{len(facts_added)} init facts written"
    )
    return report


def _pred_to_cap(pred: str) -> str:
    """Inverse of capability_to_predicate(): predicate name -> capability key."""
    for cap in CAPABILITIES:
        if cap.predicate == pred:
            return cap.key
    return ""
