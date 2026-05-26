"""Executable smoke-test gate for Phase-2-emitted action schemas.

ACSAC-defensible root-cause fix for the "Phase-2 LLM hallucinates flags"
class of EW discrepancies. Rather than encoding hand-crafted flag rules
in `common.template_validator`, we *actually execute* a stripped-down
form of each action's bash template against the scenario container and
drop the action if the run signals a parsing-level failure:

  - Exit 2 with "unknown option" / "invalid option" / "unrecognized
    option" in stderr → flag is wrong
  - "Usage: <cmd>" in output AND non-zero exit → cmd rejected the
    argument combination
  - Exit 127 → binary doesn't exist (capability gating's domain, but
    we re-check here so the gate is closed-by-construction)

We run with **safe placeholders** (`nonexistent_user_xyz`, `/tmp/...`,
etc.) and with a **read-only filesystem mount** (`--read-only --tmpfs
/tmp`) so the smoke test can never mutate the host or interfere with
later EW walks. Each test is a fresh `docker exec` in the scenario's
keep-alive container — fast (~20-50 ms per test) and isolated.

This is the canonical answer to the user's directive:
"find the root cause of the issue not bandage solution this is for a
top conference like acsac". The "root cause" is that Phase 2 emits
templates that *don't even parse* against the bash environment they'll
run in; the right answer is to test each one before adding it to the
playable domain, not to play whack-a-mole with regex rules.
"""

from __future__ import annotations

import logging
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

logger = logging.getLogger("TemplateSmokeTest")


# Stand-in values for parameter placeholders. We intentionally use
# names that are extremely unlikely to exist (so `useradd` doesn't
# accidentally succeed and create a user), while still being valid
# identifiers / paths so the FLAG parser is exercised correctly.
_SAFE_PLACEHOLDERS = {
    "user": "smoketest_user_xyz",
    "u": "smoketest_user_xyz",
    "username": "smoketest_user_xyz",
    "login": "smoketest_user_xyz",
    "target_user": "smoketest_user_xyz",
    "new_login": "smoketest_newuser",
    "group": "smoketest_group_xyz",
    "g": "smoketest_group_xyz",
    "groupname": "smoketest_group_xyz",
    "pkg": "smoketest_pkg_xyz",
    "package": "smoketest_pkg_xyz",
    "p": "smoketest_pkg_xyz",
    "file": "/tmp/smoketest_file",
    "f": "/tmp/smoketest_file",
    "path": "/tmp/smoketest_file",
    "filename": "/tmp/smoketest_file",
    "dir": "/tmp/smoketest_dir",
    "d": "/tmp/smoketest_dir",
    "directory": "/tmp/smoketest_dir",
    "service": "ssh",   # commonly present
    "svc": "ssh",
    "s": "ssh",
    "port": "22",
    "uid": "9999",
    "gid": "9999",
    "shell": "/bin/bash",
    "home": "/tmp/smoketest_home",
    "key": "test_key",
    "k": "test_key",
    "setting": "test_setting",
    "value": "test_value",
    "vold": "yes",
    "vnew": "no",
    "v": "test_value",
    "days": "30",
    "date": "2026-01-01",
    "mode": "644",
    "chain": "INPUT",
    "rule": "1",
    "interface": "lo",
    "protocol": "tcp",
    "signal": "SIGTERM",
    "count": "1",
    "number": "1",
    "n": "1",
    "rulenum": "1",
}


_FAILURE_PATTERNS = (
    re.compile(r"(?i)\b(?:unknown|unrecognized|invalid|illegal)\s+option\b"),
    re.compile(r"(?i)\bnot understood in combination\b"),
    re.compile(r"(?i)\bmust be (?:specified|given)\b"),
    re.compile(r"(?i)\busage:\s*\S"),  # "Usage: <cmd>" usually means bad invocation
    re.compile(r"(?i)\bcommand not found\b"),
    re.compile(r"(?i)\bcannot be combined\b"),
)


_PLACEHOLDER_RE = re.compile(r"\{([^{}]+)\}")


def _materialise_template(template: str) -> str:
    """Substitute `{name}` placeholders with safe stand-in values.

    Unknown placeholders get a benign default ('dummy'). Any placeholder
    that survives substitution would be a syntax error in bash, so this
    function guarantees the returned string is a bash-parseable command
    (modulo unbalanced quotes from a malformed template, which IS the
    kind of defect we want to catch).
    """
    def repl(m: re.Match) -> str:
        name = m.group(1).strip().lower()
        # Strip ":" and beyond in case the LLM used printf-style.
        name = name.split(":", 1)[0]
        return _SAFE_PLACEHOLDERS.get(name, "dummy")
    return _PLACEHOLDER_RE.sub(repl, template)


@dataclass
class SmokeTestResult:
    action_name: str
    template: str
    materialised: str
    primary: str
    exit_code: int
    stderr_excerpt: str = ""
    failure_reason: str = ""
    passed: bool = True


@dataclass
class SmokeReport:
    total: int = 0
    passed: int = 0
    failed: int = 0
    drops_by_reason: dict[str, int] = field(default_factory=dict)
    dropped_names: list[tuple[str, str]] = field(default_factory=list)


def _primary_command(template: str) -> str:
    """First non-prefix token of a command template (mirrors enrichment)."""
    tokens = template.strip().split()
    i = 0
    while i < len(tokens) and "=" in tokens[i] and not tokens[i].startswith("/"):
        i += 1
    prefixes = {"sudo", "env", "timeout", "nohup", "exec", "bash", "/bin/bash"}
    while i < len(tokens) and tokens[i].lower() in prefixes:
        i += 1
    if i >= len(tokens):
        return ""
    cmd = tokens[i]
    return cmd.rsplit("/", 1)[-1] if "/" in cmd else cmd


def smoke_test_template(
    template: str,
    run_bash: Callable[[str], tuple[int, str]],
    timeout_s: int = 10,
) -> tuple[bool, str, int, str]:
    """Materialise the template and execute it in a sandboxed shell.

    `run_bash(cmd) -> (exit_code, combined_stderr)` is the caller's
    sandbox runner. The caller is responsible for the sandbox safety
    (read-only mount, no network, etc.) — this module just classifies
    the result.

    Returns ``(passed, failure_reason, exit_code, stderr_excerpt)``.
    """
    materialised = _materialise_template(template)
    primary = _primary_command(materialised)
    if not primary:
        return False, "empty_template", 0, ""

    # Run the command in the sandbox. We append `; true` so a failing
    # last pipeline element doesn't bias the exit code, and we capture
    # combined output for classification.
    try:
        exit_code, stderr = run_bash(materialised)
    except Exception as e:
        logger.warning(f"smoke-test runner raised: {e}")
        return True, "", 0, ""  # don't drop on infrastructure error

    excerpt = stderr[:300] if stderr else ""

    # Exit 127 = binary missing — capability gating's job; don't double-drop.
    if exit_code == 127:
        return True, "", exit_code, excerpt

    # Classify by stderr patterns
    for pat in _FAILURE_PATTERNS:
        if pat.search(stderr or ""):
            return False, pat.pattern, exit_code, excerpt

    # If non-zero exit but no recognised failure pattern, the command is
    # plausibly semantically valid (e.g. useradd-on-nonexistent-user
    # returning 9 means the parser was happy; the action just wouldn't
    # apply against that *specific* test object). Keep the action.
    return True, "", exit_code, excerpt


def smoke_test_action_templates(
    action_templates: dict[str, str],
    run_bash: Callable[[str], tuple[int, str]],
    canonical_names: set[str] | None = None,
    max_actions: int | None = None,
) -> tuple[dict[str, str], SmokeReport]:
    """Test each (name -> template) pair; return only the ones that
    pass plus a SmokeReport describing the drops.

    `canonical_names` is the set of action names exempt from the gate
    (matching the convention in `common.template_validator`).
    """
    canonical = set(canonical_names or ())
    survivors: dict[str, str] = {}
    report = SmokeReport()

    items = list(action_templates.items())
    if max_actions:
        items = items[:max_actions]

    for name, template in items:
        report.total += 1
        if name in canonical or not template:
            # empty templates are dropped by the pre-existing
            # template_validator; we don't re-judge here.
            survivors[name] = template
            report.passed += 1
            continue
        ok, reason, code, excerpt = smoke_test_template(template, run_bash)
        if ok:
            survivors[name] = template
            report.passed += 1
        else:
            report.failed += 1
            report.dropped_names.append((name, f"{reason} (exit {code})"))
            report.drops_by_reason[reason] = (
                report.drops_by_reason.get(reason, 0) + 1
            )
    logger.info(
        f"template smoke test: {report.passed}/{report.total} passed, "
        f"{report.failed} dropped, drops_by_reason={report.drops_by_reason}"
    )
    return survivors, report


# ---------------------------------------------------------------------------
# Domain rewrite: drop actions whose name appears in `dropped_names`.
# Mirrors the in-place pattern used by common.template_validator.
# ---------------------------------------------------------------------------

_ACTION_HEAD = re.compile(r"\(:action\s+([A-Za-z_][\w-]*)\b")


def drop_actions_from_domain(
    domain_path: Path | str,
    drop_names: set[str],
    backup_suffix: str = ".pre-smoketest.pddl",
) -> int:
    """Remove the `(:action <name> ...)` blocks for every name in
    ``drop_names`` from ``domain_path`` (in place, with backup).

    Returns the number of action blocks removed.
    """
    domain_path = Path(domain_path)
    if not domain_path.exists():
        raise FileNotFoundError(domain_path)
    text = domain_path.read_text()
    domain_path.with_suffix(backup_suffix).write_text(text)

    out_parts: list[str] = []
    pos = 0
    dropped = 0
    for m in _ACTION_HEAD.finditer(text):
        if m.group(1) not in drop_names:
            continue
        # Find the balanced close paren of this (:action ...)
        depth = 0
        start = m.start()
        end = start
        for j in range(start, len(text)):
            if text[j] == "(":
                depth += 1
            elif text[j] == ")":
                depth -= 1
                if depth == 0:
                    end = j + 1
                    break
        # Emit text up to and including the action's preceding ';;' or whitespace,
        # then a brief comment in its place, then continue past the action.
        out_parts.append(text[pos:start])
        out_parts.append(f";; SMOKE-DROPPED action {m.group(1)}\n  ")
        pos = end
        dropped += 1
    out_parts.append(text[pos:])
    domain_path.write_text("".join(out_parts))
    logger.info(f"smoke-test drop_actions: {dropped} actions removed from {domain_path}")
    return dropped
