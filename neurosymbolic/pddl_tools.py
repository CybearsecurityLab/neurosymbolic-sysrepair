"""Read-only PDDL inspection tools for an LLM problem-generator agent.

The Phase-2/3 domains can be hundreds of KB and tens of thousands of tokens;
dumping them into every prompt is wasteful and degrades attention. Instead,
expose a small set of search/read tools the LLM can call to navigate the
domain on demand:

    pddl_list_predicates(prefix="")
    pddl_list_actions(prefix="")
    pddl_list_types()
    pddl_show_predicate(name)
    pddl_show_action(name)
    pddl_search(pattern)

The text being navigated is the same PDDL text the planner will receive,
so the LLM cannot make up identifiers that don't exist — every call is
grounded in the actual domain.
"""

from __future__ import annotations

import re
from typing import Iterable

from inspect_ai.tool import Tool, tool


# ---------------------------------------------------------------------------
# Cheap regex-based extractors. The full pddl-library parse is too strict for
# Phase 2/3 domains that have minor lints; we just need to surface names and
# block contents to the LLM.
# ---------------------------------------------------------------------------

_TYPES_BLOCK_RE = re.compile(r"\(:types\b([\s\S]*?)\)\s*(?=\(:predicates|\(:functions|\(:constants|\(:action|\)\s*\Z)")
_PREDS_BLOCK_RE = re.compile(r"\(:predicates\b([\s\S]*?)\)\s*(?=\(:functions|\(:constants|\(:action|\)\s*\Z)")
_ACTION_BLOCK_RE = re.compile(
    r"\(:action\s+([A-Za-z_][\w-]*)\b([\s\S]*?)(?=\(:action\b|\)\s*\Z|\)\s*$)",
    re.MULTILINE,
)
_PRED_NAME_RE = re.compile(r"\(\s*([A-Za-z_][\w-]*)\b")


def _extract_types(domain_text: str) -> list[str]:
    m = _TYPES_BLOCK_RE.search(domain_text)
    if not m:
        return []
    raw = m.group(1)
    # types block may look like "filesystem_object - object\n directory file - filesystem_object"
    # Take only the names (before any "-").
    tokens = re.split(r"-", raw)
    names: list[str] = []
    for chunk in tokens:
        for tok in chunk.split():
            if tok and tok[0].isalpha() and tok not in names:
                names.append(tok)
    return names


def _extract_predicates(domain_text: str) -> list[tuple[str, str]]:
    """Returns list of (predicate_name, raw_signature)."""
    m = _PREDS_BLOCK_RE.search(domain_text)
    if not m:
        return []
    block = m.group(1)
    # Each predicate sits between matched parens.
    preds: list[tuple[str, str]] = []
    depth = 0
    start = -1
    for i, ch in enumerate(block):
        if ch == "(":
            if depth == 0:
                start = i
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and start >= 0:
                sig = block[start:i + 1]
                name_match = _PRED_NAME_RE.match(sig)
                if name_match:
                    preds.append((name_match.group(1), sig))
                start = -1
    return preds


def _extract_actions(domain_text: str) -> dict[str, str]:
    """Returns dict of action_name -> full ``(:action ...)`` block text."""
    out: dict[str, str] = {}
    for m in _ACTION_BLOCK_RE.finditer(domain_text):
        name = m.group(1)
        # Re-find the start of "(:action" to keep the full block intact.
        s = m.start()
        # Walk paren depth to find the matching close.
        depth = 0
        for j in range(s, len(domain_text)):
            ch = domain_text[j]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    out[name] = domain_text[s:j + 1]
                    break
    return out


# ---------------------------------------------------------------------------
# Tool factory — returns inspect_ai @tool callables bound to the domain text.
# ---------------------------------------------------------------------------

def build_pddl_tools(domain_text: str) -> list[Tool]:
    """Construct the read-only PDDL inspection toolset for a specific domain.

    Bound to ``domain_text`` via closure so the LLM sees a fixed view of the
    artifact under planning.
    """
    types = _extract_types(domain_text)
    preds = _extract_predicates(domain_text)
    pred_index: dict[str, str] = {n: s for n, s in preds}
    actions = _extract_actions(domain_text)

    @tool
    def pddl_list_types() -> Tool:
        async def execute() -> str:
            """List every type declared in the PDDL domain."""
            return ", ".join(types) if types else "(no types declared)"
        return execute

    @tool
    def pddl_list_predicates() -> Tool:
        async def execute(prefix: str = "") -> str:
            """List predicate NAMES declared in the domain. Optional prefix filter.

            Args:
                prefix: only return predicates whose name starts with this string.
            """
            names = sorted(pred_index.keys())
            if prefix:
                names = [n for n in names if n.startswith(prefix)]
            if not names:
                return "(no matching predicates)"
            return ", ".join(names[:200]) + ("" if len(names) <= 200 else f"\n…(+{len(names)-200} more)")
        return execute

    @tool
    def pddl_list_actions() -> Tool:
        async def execute(prefix: str = "") -> str:
            """List action NAMES declared in the domain. Optional prefix filter.

            Args:
                prefix: only return actions whose name starts with this string.
            """
            names = sorted(actions.keys())
            if prefix:
                names = [n for n in names if n.startswith(prefix)]
            if not names:
                return "(no matching actions)"
            return ", ".join(names[:200]) + ("" if len(names) <= 200 else f"\n…(+{len(names)-200} more)")
        return execute

    @tool
    def pddl_show_predicate() -> Tool:
        async def execute(name: str) -> str:
            """Return the full signature of a single predicate.

            Args:
                name: the predicate's identifier (no leading paren).
            """
            sig = pred_index.get(name)
            return sig if sig else f"(no predicate named {name!r})"
        return execute

    @tool
    def pddl_show_action() -> Tool:
        async def execute(name: str) -> str:
            """Return the full ``(:action ...)`` block for a single action.

            Args:
                name: the action's identifier.
            """
            block = actions.get(name)
            return block if block else f"(no action named {name!r})"
        return execute

    @tool
    def pddl_search() -> Tool:
        async def execute(pattern: str, kind: str = "any") -> str:
            """Substring search across predicate AND action names.

            Args:
                pattern: case-insensitive substring to search for.
                kind: 'predicate', 'action', or 'any' (default).
            """
            pat = pattern.lower()
            hits: list[str] = []
            if kind in ("any", "predicate"):
                hits.extend(f"pred {n}" for n in pred_index if pat in n.lower())
            if kind in ("any", "action"):
                hits.extend(f"act  {n}" for n in actions if pat in n.lower())
            if not hits:
                return f"(no match for {pattern!r})"
            return "\n".join(hits[:80]) + ("" if len(hits) <= 80 else f"\n…(+{len(hits)-80} more)")
        return execute

    return [
        pddl_list_types(), pddl_list_predicates(), pddl_list_actions(),
        pddl_show_predicate(), pddl_show_action(), pddl_search(),
    ]
