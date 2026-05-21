"""Rule-based precondition synthesis.

Phase 3's refiner repairs actions one at a time via LLM and is capped
at 100 repairs per iteration. With ~1000 actions in the Phase 2 domain,
that's not enough breadth to fix the per-action semantic gaps that
dominate the EW discrepancy log (useradd-on-existing-user,
passwd-on-missing-user, chage-on-missing-user, groupadd-on-existing-group).

This module applies a static rule table — same pattern as
``common.canonical_actions`` — that adds the correct existence guard to
every action whose command_template's primary token matches a known
sysadmin verb. It runs once after Phase 2 enrichment and before the
refiner starts, so the savings come "for free" (no per-action LLM call)
and the refiner can spend its 200-call budget on the harder cases.

This is defensible PDDL engineering: the missing preconditions are
domain knowledge that *every* sysadmin would write by hand
(``useradd`` requires the user to NOT exist; ``passwd`` requires it
TO exist). We are not inventing semantics, only encoding well-known
operator preconditions that the LLM-based mining failed to recover.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

logger = logging.getLogger("PreconditionSynthesis")


# ---------------------------------------------------------------------------
# Rule table
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PrecondRule:
    """Add `clauses` to the :precondition of any action whose
    command_template's primary token matches one of `primary_cmds` AND
    whose action has the named parameter(s) of the matching type.
    """
    primary_cmds: tuple[str, ...]
    # (var, type, predicate, polarity)
    #   var: which PDDL variable to bind to (e.g. "?u")
    #   type: required parameter type (e.g. "user")
    #   predicate: predicate to add (e.g. "user_exists")
    #   polarity: True = (pred ?var); False = (not (pred ?var))
    clauses: tuple[tuple[str, str, str, bool], ...]


_RULES: tuple[PrecondRule, ...] = (
    # ── User existence ──────────────────────────────────────────────
    PrecondRule(
        primary_cmds=("useradd", "newusers"),
        clauses=(("?u", "user", "user_exists", False),),  # must NOT exist
    ),
    PrecondRule(
        primary_cmds=(
            "passwd", "chage", "chfn", "chsh", "usermod", "userdel",
            "gpasswd", "chpasswd",
        ),
        clauses=(("?u", "user", "user_exists", True),),  # must exist
    ),
    # ── Group existence ─────────────────────────────────────────────
    PrecondRule(
        primary_cmds=("groupadd",),
        clauses=(("?g", "group", "group_exists", False),),
    ),
    PrecondRule(
        primary_cmds=("groupdel", "groupmod"),
        clauses=(("?g", "group", "group_exists", True),),
    ),
    # ── File / directory existence ──────────────────────────────────
    PrecondRule(
        primary_cmds=("rm", "cat", "tail", "head", "grep", "chmod",
                      "chown", "chgrp", "stat", "cp", "mv"),
        clauses=(("?f", "file", "file_exists", True),),
    ),
    PrecondRule(
        primary_cmds=("touch", "mkdir"),
        # mkdir-on-existing succeeds with -p, but touch can fail; use
        # the standard "doesn't exist" guard.
        clauses=(("?f", "file", "file_exists", False),),
    ),
    # ── Package state ───────────────────────────────────────────────
    PrecondRule(
        primary_cmds=("apt-get-install", "apt-install"),  # rarely a primary, but if present
        clauses=(("?pkg", "package", "package_installed", False),),
    ),
)


# ---------------------------------------------------------------------------
# PDDL parsing helpers (regex-based, mirroring common.domain_enrichment)
# ---------------------------------------------------------------------------

_ACTION_HEAD = re.compile(r"\(:action\s+([A-Za-z_][\w-]*)\b")
_PARAMETERS = re.compile(r":parameters\s*\(([^)]*)\)", re.DOTALL)
_PRECOND_HEAD = re.compile(r":precondition\s*", re.MULTILINE)
_PREDICATES_HEAD = re.compile(r"\(:predicates\b")


def _balanced_block(text: str, start: int) -> tuple[int, int] | None:
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


def _parse_params(block: str) -> dict[str, str]:
    """Return {var: type} from ':parameters (...)' text."""
    m = _PARAMETERS.search(block)
    if not m:
        return {}
    out: dict[str, str] = {}
    for pm in re.finditer(r"(\?[\w-]+)\s*-\s*([A-Za-z_][\w-]*)", m.group(1)):
        out[pm.group(1)] = pm.group(2)
    return out


def _primary_command(template: str) -> str:
    """Match common.domain_enrichment._primary_command semantics."""
    for tok in template.strip().split():
        if "=" in tok and not tok.startswith("/") and "/" not in tok.split("=", 1)[0]:
            continue
        if tok in ("sudo", "env"):
            continue
        return tok.lstrip("/").split("/")[-1]  # basename
    return ""


def _add_predicate_if_missing(text: str, pred: str) -> str:
    """Inject `(<pred> ?x - <type>)` into (:predicates ...) if not there.

    We need to declare it with a typed parameter; we look at how the
    predicate is *used* and emit a best-guess signature.
    """
    if f"({pred} " in text:
        return text  # already present
    type_guess = {
        "user_exists": "user", "group_exists": "group",
        "file_exists": "file", "directory_exists": "directory",
        "package_installed": "package",
    }.get(pred, "object")
    decl = f"({pred} ?x - {type_guess})"
    m = _PREDICATES_HEAD.search(text)
    if not m:
        return text  # predicates block missing, give up silently
    blk = _balanced_block(text, m.start())
    if not blk:
        return text
    close = blk[1]
    return text[:close] + f"\n    {decl}" + text[close:]


def _rewrite_precondition(action_block: str, vars_by_var: dict[str, str],
                          clauses: Iterable[tuple[str, str, str, bool]]) -> str:
    """Append `clauses` to the action's :precondition `(and ...)`."""
    applicable: list[str] = []
    for var, type_, pred, polarity in clauses:
        # Find a parameter of the required type
        bound_var: str | None = None
        for v, t in vars_by_var.items():
            if t == type_:
                bound_var = v
                break
        if bound_var is None:
            continue
        literal = f"({pred} {bound_var})"
        neg_literal = f"(not {literal})"
        # If either polarity already exists in the action's text, the
        # action author already had an opinion — don't override. Adding
        # the opposite polarity would make the action infeasible.
        if literal in action_block or neg_literal in action_block:
            continue
        if not polarity:
            literal = neg_literal
        applicable.append(literal)
    if not applicable:
        return action_block

    pm = _PRECOND_HEAD.search(action_block)
    if not pm:
        # No precondition block — inject one. Find :parameters block end.
        pdm = _PARAMETERS.search(action_block)
        if not pdm:
            return action_block
        insert_pos = pdm.end()
        clause_block = "\n    :precondition (and " + " ".join(applicable) + ")"
        return action_block[:insert_pos] + clause_block + action_block[insert_pos:]

    # Existing precondition. Find its opening paren and append.
    after_kw = action_block[pm.end():].lstrip()
    paren_off = pm.end() + (len(action_block[pm.end():]) - len(after_kw))
    if paren_off >= len(action_block) or action_block[paren_off] != "(":
        return action_block
    blk = _balanced_block(action_block, paren_off)
    if not blk:
        return action_block
    _, close = blk
    body = action_block[paren_off:close + 1]
    if body.startswith("(and") or body.startswith("( and"):
        # Insert before the closing paren.
        return (action_block[:close] + " " + " ".join(applicable)
                + action_block[close:])
    # Single-clause precondition — wrap in (and ...)
    inner = action_block[paren_off + 1:close]
    wrapped = "(and " + inner + " " + " ".join(applicable) + ")"
    return action_block[:paren_off] + wrapped + action_block[close + 1:]


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def synthesize_in_place(domain_path: Path,
                        action_templates: dict[str, str],
                        backup_suffix: str = ".pre-precond-synth.pddl") -> dict:
    """Add rule-based preconditions to ``domain_path``.

    ``action_templates`` maps action_name → command_template (typically
    the union of phase1 metadata and any prior concretizer cache).
    """
    domain_path = Path(domain_path)
    if not domain_path.exists():
        raise FileNotFoundError(f"domain not found: {domain_path}")
    domain_path.with_suffix(backup_suffix).write_text(domain_path.read_text())

    text = domain_path.read_text()
    preds_added: set[str] = set()

    # Build reverse index: primary_cmd → list[(action_name, clauses)]
    cmd_to_rule: dict[str, PrecondRule] = {}
    for rule in _RULES:
        for cmd in rule.primary_cmds:
            cmd_to_rule[cmd] = rule

    actions_patched = 0

    # Walk actions in order, rewriting each block
    pos = 0
    out_parts: list[str] = []
    for m in _ACTION_HEAD.finditer(text):
        action_name = m.group(1)
        blk = _balanced_block(text, m.start())
        if not blk:
            continue
        start, end = blk
        # emit text up to the action
        out_parts.append(text[pos:start])
        block_text = text[start:end + 1]

        # Find the template for this action
        template = action_templates.get(action_name, "")
        primary = _primary_command(template)
        rule = cmd_to_rule.get(primary)
        if rule is None and primary.startswith(("apt-get", "apt")):
            # heuristic: apt-get install / apt-get remove → use package rules
            if "install" in template:
                rule = PrecondRule(primary_cmds=(primary,),
                                   clauses=(("?pkg", "package",
                                             "package_installed", False),))
            elif any(v in template for v in ("remove", "purge")):
                rule = PrecondRule(primary_cmds=(primary,),
                                   clauses=(("?pkg", "package",
                                             "package_installed", True),))

        if rule is not None:
            params = _parse_params(block_text)
            new_block = _rewrite_precondition(block_text, params, rule.clauses)
            if new_block != block_text:
                actions_patched += 1
                for _, _, p, _ in rule.clauses:
                    preds_added.add(p)
            block_text = new_block

        out_parts.append(block_text)
        pos = end + 1

    out_parts.append(text[pos:])
    new_text = "".join(out_parts)

    # Declare any newly-referenced predicates
    for pred in preds_added:
        new_text = _add_predicate_if_missing(new_text, pred)

    domain_path.write_text(new_text)
    report = {
        "actions_patched": actions_patched,
        "predicates_added": sorted(preds_added),
    }
    logger.info(
        f"precondition synthesis: {actions_patched} actions patched, "
        f"{len(preds_added)} predicates declared"
    )
    return report
