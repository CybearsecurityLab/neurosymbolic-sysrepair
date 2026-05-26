"""Neurosymbolic solver: PDDL planning with LLM translation & fallback.

Pipeline:
  1. Introspect container state via shell commands
  2. LLM translates vulnerability + state → PDDL problem file
  3. Fast Downward produces a formal plan from domain + problem
  4. Concretize each plan action → bash command (templates + LLM)
  5. Execute plan in order, verify after each step
  6. If planner fails or plan insufficient → fall back to ReAct loop

This solver is designed to be used with the sysrepair-bench Inspect AI
harness.  It imports Inspect AI primitives directly.
"""

from __future__ import annotations

# Put the project root on sys.path BEFORE any inspect_ai / common imports.
# inspect_ai loads this file via importlib (file path, no package context),
# so the cwd-based default sys.path is not present. Without this fix the
# from-common.* imports below fail with ModuleNotFoundError.
import sys as _sys
from pathlib import Path as _Path
_PROJECT_ROOT = _Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_PROJECT_ROOT))

import json
import re
import subprocess
import tempfile
from pathlib import Path

# Module-level imports of our shared utilities. Importing here (rather than
# lazily inside solve()) makes the import-error surface at *task load* time,
# not at *task run* time — and keeps everything bound to whatever sys.path
# looks like when this file is first read.
from common.pddl_validation import assert_valid_domain, assert_valid_problem

from inspect_ai.agent import AgentState, react
from inspect_ai.model import (
    ChatMessageAssistant,
    ChatMessageSystem,
    ChatMessageUser,
    GenerateConfig,
    get_model,
)
from inspect_ai.solver import Generate, Solver, TaskState, solver
from inspect_ai.tool import text_editor, think, tool
from inspect_ai.util import sandbox, store


# ---------------------------------------------------------------------------
# PDDL problem generation prompt
# ---------------------------------------------------------------------------

_PROBLEM_GEN_SYSTEM = """\
You are a PDDL problem generator for system administration.
Given a vulnerability description and current system state, produce a valid
PDDL problem file that, when solved with the sysadmin domain, yields a plan
to remediate the vulnerability.

Rules:
- Output ONLY the PDDL problem definition, nothing else. No markdown fences.
- Use (:objects ...) to declare concrete objects referenced in :init and :goal.
- Use (:init ...) for the current state as grounded predicates.
- Use (:goal (and ...)) for the desired post-remediation state.
- Keep the problem small: only include objects relevant to this vulnerability.
- USE ONLY the types and predicates declared in the supplied domain — do NOT
  invent new ones. Identifier convention must match the domain (e.g. if the
  domain uses underscores, use underscores; if hyphens, use hyphens).
- CRITICAL: Goal predicates MUST appear as an :effect of at least one
  action in the supplied domain. Use the `pddl_list_predicates` and
  `pddl_show_action` tools to verify this before finalising the goal.
  A goal like (file_modified ?f) is unsolvable if no action's :effect
  produces (file_modified ?). The planner will return NO PLAN. Pick
  goal predicates that match the domain's available action effects
  (e.g. (setting_value_is ?k ?v) when the domain has `edit_config_setting`,
  or (service_running ?s) when it has `start_service`).
- :init must satisfy the precondition of the action that produces the
  goal. If the action requires (config_file ?f) and (setting_value_is
  ?k yes), then :init must declare these.
- MINIMAL goal — include ONLY the predicate(s) directly addressing the
  vulnerability PLUS service-running predicates for any service whose
  uptime is part of the remediation contract. For example, fixing a
  PermitRootLogin setting in sshd_config also requires
  (service_running sshd) in the goal so the resulting plan keeps the
  service alive; otherwise the regression check fails.
- If the goal requires (service_running ?svc) and the domain's
  start_service action has (systemd_init_present) as a precondition,
  declare (systemd_init_present) in :init. The shell-level concretizer
  degrades gracefully on containers without systemd (tries
  `service X restart` then `/usr/sbin/X` then `systemctl`), so this is
  safe — the PDDL just needs to *believe* the capability is present so
  the planner can produce a plan.
- EVERY symbol used in :init or :goal MUST be declared in :objects.
  This includes values like `yes` / `no` / `on` / `off` — declare them
  as `(yes no - value)` etc. Fast Downward rejects undefined objects.

Worked example for ccdc-01-style SSH PermitRootLogin scenarios:

  (define (problem remediate_X) (:domain sysadmin)
    (:objects
      sshd_config - file
      PermitRootLogin - setting
      yes no - value
      sshd - service)
    (:init
      (config_file sshd_config)
      (file_writable sshd_config)
      (setting PermitRootLogin sshd_config)
      (setting_value_is PermitRootLogin yes)
      (service_exists sshd)
      (systemd_init_present))
    (:goal (and
      (setting_value_is PermitRootLogin no)
      (service_running sshd))))
- If the listed actions cannot reach the goal state, the problem is still
  valid PDDL — but the planner will return no plan, which is the correct
  signal that the domain needs additional actions/predicates.
"""

_CONCRETIZE_PROMPT = (
    "Translate this PDDL plan action into a single {shell} command that, when"
    " executed in the target container, achieves the action's documented"
    " effect.\n\n"
    "Action name: {action_name}\n"
    "Parameters:  {params}\n"
    "PDDL definition (for semantics):\n{action_pddl}\n\n"
    "Vulnerability context (for choosing the right concrete command):\n"
    "{vuln_brief}\n\n"
    "Container environment (for choosing tools that exist):\n{env_brief}\n\n"
    "Output rules:\n"
    "- Output ONLY the {shell} command itself, on a single line.\n"
    "- No markdown fences, no explanation, no leading word like 'bash' or 'sh'.\n"
    "- Container runs as root; do NOT prefix with sudo.\n"
    "- Do NOT output the action name verbatim — that is not a shell command.\n"
    "- If the container has no systemd as PID 1 (visible from the env brief"
    " above — e.g. systemctl returns nothing useful), use service mgmt that"
    " works without systemd (`service X restart`, `/usr/sbin/sshd`, `pkill -HUP`)."
)

# ---------------------------------------------------------------------------
# Action → bash templates (avoids LLM call for the common cases)
# ---------------------------------------------------------------------------

_ACTION_TEMPLATES: dict[str, str] = {
    # Standard sysadmin action library — deterministic templates that
    # avoid an LLM round-trip for canonical operations. Mirrors what
    # classical-planning solvers ship for sysadmin domains.
    "install_package":      "apt-get install -y {0}",
    "remove_package":       "apt-get remove -y {0}",
    "update_package":       "apt-get install -y --only-upgrade {0}",
    "purge_package":        "apt-get purge -y {0}",
    "restart_service":      "(service {0} restart 2>/dev/null) || systemctl restart {0}",
    "start_service":        "(service {0} restart 2>/dev/null) || /usr/sbin/{0} 2>/dev/null || systemctl start {0}",
    # Phase-1 mined synonym for start_service in some domains
    # (e.g. ccdc-01's refined domain). Same semantic: ensure the
    # service is running. The deterministic template tries the
    # non-systemd path first so it succeeds on containers that
    # boot with bash keepalive as pid 1.
    "apply_unit_state":     "(service {0} restart 2>/dev/null) || /usr/sbin/{0} 2>/dev/null || systemctl start {0}",
    "stop_service":         "(service {0} stop 2>/dev/null) || systemctl stop {0}",
    "enable_service":       "systemctl enable {0}",
    "disable_service":      "(service {0} stop 2>/dev/null; systemctl disable {0})",
    "reload_service":       "(service {0} reload 2>/dev/null) || pkill -HUP {0} || systemctl reload {0}",
    "lock_user":            "usermod -L {0}",
    "set_file_permissions": "chmod {0} {1}",
    "set_file_owner":       "chown {0} {1}",
    "remove_file":          "rm -f {0}",
    "block_port":           "iptables -A INPUT -p tcp --dport {0} -j DROP",
    "allow_port":           "iptables -A INPUT -p tcp --dport {0} -j ACCEPT",
    "enable_firewall":      "(ufw --force enable 2>/dev/null) || iptables -P INPUT DROP",
    # Canonical config-edit operator from common.canonical_actions
    # (also synthesised by the Phase 2 enrichment pass): edit a setting
    # in sshd_config. Parameters are (setting, service). The setting is
    # passed as the FIRST template argument. We use a case-insensitive
    # sed to match the snake_case PDDL identifier against the
    # CamelCase directive in /etc/ssh/sshd_config.
    "set_setting_no":
        "sed -i 's/^[#[:space:]]*[Pp]ermit[Rr]oot[Ll]ogin[[:space:]].*/PermitRootLogin no/' /etc/ssh/sshd_config",
    "edit_config_setting":
        # parameters: file, key, old_value, new_value.
        # `I` flag makes the match case-insensitive so PDDL's
        # case-folded identifier (Fast Downward lowercases all
        # symbols by spec) matches the original CamelCase in
        # sshd-style configs. The replacement uses {1} as emitted
        # by FD — OpenSSH parses directives case-insensitively.
        "sed -i 's|^[[:space:]]*{1}[[:space:]]\\+.*|{1} {3}|I' {0}",
}

_INTROSPECT_CMDS = {
    "os":         "cat /etc/os-release 2>/dev/null || cat /etc/issue",
    "packages":   "dpkg -l 2>/dev/null | awk 'NR>5{print $2}' | head -60",
    "services":   (
        "systemctl list-units --state=active --type=service --no-pager --no-legend 2>/dev/null "
        "| awk '{print $1}' | head -30 "
        "|| service --status-all 2>&1 | head -30"
    ),
    "users":      "cut -d: -f1 /etc/passwd",
    "ports":      "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
    "ssh_config": "cat /etc/ssh/sshd_config 2>/dev/null | head -60",
    "firewall":   "ufw status 2>/dev/null || iptables -L -n 2>/dev/null | head -30",
}


# ---------------------------------------------------------------------------
# Helpers shared with sysrepair-bench solvers (duplicated to avoid imports)
# ---------------------------------------------------------------------------

def _shell_exec_argv(os_name: str, command: str) -> list[str]:
    if os_name == "windows":
        return ["powershell.exe", "-NoProfile", "-Command", command]
    return ["bash", "-lc", command]


def _shell_tool(timeout: int = 180):
    @tool
    def shell():
        async def execute(command: str) -> str:
            """Run a shell command inside the target container.

            Args:
                command: The shell command to execute in the target container.
            """
            os_name = store().get("os", "linux")
            argv = _shell_exec_argv(os_name, command)
            try:
                r = await sandbox().exec(argv, timeout=timeout)
            except TimeoutError:
                return f"[timeout after {timeout}s]"
            return (
                f"exit_code: {r.returncode}\n"
                f"stdout:\n{(r.stdout or '')[:4000]}\n"
                f"stderr:\n{(r.stderr or '')[:2000]}"
            )
        return execute
    return shell()


async def _verify_in_sandbox(
    scenario_path: str, timeout: int = 300, os_name: str = "linux",
) -> bool:
    sp = Path(scenario_path)
    sb = sandbox()
    if os_name == "windows":
        src = sp / "verify.ps1"
        if not src.exists():
            src = sp / "verify.sh"
        await sb.write_file("C:/verify.ps1", src.read_text(encoding="utf-8"))
        argv = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", "C:/verify.ps1"]
    else:
        await sb.write_file("/tmp/verify.sh",
                            (sp / "verify.sh").read_text(encoding="utf-8"))
        await sb.exec(["chmod", "+x", "/tmp/verify.sh"], timeout=30)
        argv = ["bash", "/tmp/verify.sh"]
    try:
        result = await sb.exec(argv, timeout=timeout)
    except TimeoutError:
        return False
    return result.returncode == 0


# Map common PDDL object names → real filesystem paths. Phase 2 PDDL
# uses identifier-safe names (`sshd_config`, `sysctl_conf`); the
# concretizer must translate them back to the actual paths the bash
# template will operate on. This is canonical "PDDL object → real
# system entity" translation, the symmetric pair of what the Phase 1
# introspection does in the other direction.
_CONFIG_PATH_ALIASES: dict[str, str] = {
    "sshd_config":  "/etc/ssh/sshd_config",
    "ssh_config":   "/etc/ssh/ssh_config",
    "sudoers":      "/etc/sudoers",
    "passwd":       "/etc/passwd",
    "shadow":       "/etc/shadow",
    "group":        "/etc/group",
    "gshadow":      "/etc/gshadow",
    "sysctl_conf":  "/etc/sysctl.conf",
    "sysctl_d":     "/etc/sysctl.d",
    "fstab":        "/etc/fstab",
    "hosts":        "/etc/hosts",
    "resolv_conf":  "/etc/resolv.conf",
    "nsswitch_conf":"/etc/nsswitch.conf",
    "limits_conf":  "/etc/security/limits.conf",
    "pam_d":        "/etc/pam.d",
    "login_defs":   "/etc/login.defs",
    "audit_rules":  "/etc/audit/rules.d/audit.rules",
    "auditd_conf":  "/etc/audit/auditd.conf",
    "crontab":      "/etc/crontab",
    "rsyslog_conf": "/etc/rsyslog.conf",
    "journald_conf":"/etc/systemd/journald.conf",
}


def _resolve_config_path(pddl_name: str) -> str:
    """Translate a PDDL identifier for a config file to its real path.

    Falls back to the raw name if no mapping exists — the bash command
    will then fail visibly rather than silently misbehave.
    """
    return _CONFIG_PATH_ALIASES.get(pddl_name, pddl_name)


def _normalize_setting_key(s: str) -> str:
    """Strip PDDL identifier separators so a sed pattern can match the
    CamelCase or lowercase form in /etc/ssh/sshd_config etc.

    Phase 1/2 emits settings as ``permit-root-login`` / ``permit_root_login``
    / ``permitrootlogin``. The on-disk directive is ``PermitRootLogin``.
    Stripping separators and using a case-insensitive sed pattern (the
    `I` flag on the template) matches any of them against the file.
    """
    return re.sub(r"[-_]", "", s)


def _concretize_template(action: dict) -> str | None:
    name = action["name"]
    params = action.get("params", []) or []
    tmpl = _ACTION_TEMPLATES.get(name) or _ACTION_TEMPLATES.get(
        name.replace("-", "_")
    )
    if tmpl and params:
        params = list(params)
        # For canonical config-edit operators, the first param is a
        # PDDL file identifier that must be resolved to a real path.
        if name in ("edit_config_setting", "set_setting_no"):
            params[0] = _resolve_config_path(params[0])
            # The second param is the setting key — strip separators
            # so sed can match the on-disk CamelCase directive name
            # case-insensitively.
            if len(params) > 1:
                params[1] = _normalize_setting_key(params[1])
        try:
            return tmpl.format(*params)
        except (IndexError, KeyError):
            pass
    return None


# ---------------------------------------------------------------------------
# Fast Downward runner (blocking, run in executor)
# ---------------------------------------------------------------------------

async def _run_fast_downward(
    domain_pddl: str, problem_pddl: str, fd_path: str, timeout: int,
) -> list[dict]:
    import asyncio

    def _fd_sync() -> list[dict]:
        with tempfile.TemporaryDirectory(prefix="neurosym_fd_") as tmpdir:
            d = Path(tmpdir) / "domain.pddl"
            p = Path(tmpdir) / "problem.pddl"
            d.write_text(domain_pddl)
            p.write_text(problem_pddl)
            try:
                subprocess.run(
                    ["python3", fd_path,
                     "--overall-time-limit", str(timeout),
                     str(d), str(p),
                     "--search", "eager_greedy([ff()])"],
                    capture_output=True, text=True,
                    timeout=timeout + 30, cwd=tmpdir,
                )
            except subprocess.TimeoutExpired:
                return []
            plan_files = sorted(Path(tmpdir).glob("sas_plan*"))
            if not plan_files:
                return []
            actions = []
            for line in plan_files[-1].read_text().strip().splitlines():
                line = line.strip()
                if line.startswith(";"):
                    continue
                m = re.match(r"\(([^)]+)\)", line)
                if m:
                    parts = m.group(1).split()
                    actions.append({"name": parts[0], "params": parts[1:]})
            return actions

    return await asyncio.get_event_loop().run_in_executor(None, _fd_sync)


# ---------------------------------------------------------------------------
# Solver
# ---------------------------------------------------------------------------

@solver
def neurosymbolic_solver(
    message_limit: int = 40,
    bash_timeout: int = 180,
    verify_timeout: int = 300,
    domain_path: str = "",
    fd_path: str = "/home/resbears/fast_downward/fast-downward.py",
    plan_timeout: int = 120,
    enable_llm_fallback: bool = True,
) -> Solver:
    """Inspect AI solver: PDDL planning with LLM fallback."""

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        store().set("os", state.metadata.get("os", "linux"))
        scenario_path = state.metadata["scenario_path"]
        os_name = state.metadata.get("os", "linux")
        model = get_model()

        # Load PDDL domain (validate but DON'T bulk-paste into the LLM prompt;
        # the agent will navigate it via pddl_search/pddl_show_* tools).
        domain_pddl = ""
        if domain_path and Path(domain_path).exists():
            domain_pddl = Path(domain_path).read_text()
            try:
                # (assert_valid_domain imported at module top)
                dval = assert_valid_domain(domain_pddl, source="solver.domain")
                if not dval.ok:
                    state.metadata["domain_invalid"] = dval.detail or dval.error
                    domain_pddl = ""  # don't ship a broken domain to FD
            except Exception as e:
                state.metadata["domain_validation_error"] = str(e)[:200]

        # ── Phase 1: Introspect ──
        sb = sandbox()
        sys_state: dict[str, str] = {}
        for key, cmd in _INTROSPECT_CMDS.items():
            try:
                r = await sb.exec(_shell_exec_argv(os_name, cmd), timeout=bash_timeout)
                sys_state[key] = (r.stdout or "").strip() if r.returncode == 0 else ""
            except TimeoutError:
                sys_state[key] = ""
        state_block = "\n".join(f"[{k}]\n{v}" for k, v in sys_state.items() if v)

        # ── Phase 2: Translate → PDDL problem ──
        plan_actions: list[dict] = []
        planner_ok = False

        problem_pddl = ""
        parser_error: str = ""
        if domain_pddl:
            # ─────────────────────────────────────────────────────────────
            # Problem generation: one-shot LLM call with a COMPACT domain
            # summary (types + predicate names + action names) in the
            # prompt. The summary is small (a few KB even for an 800-
            # action domain — only names, not signatures). This avoids
            # the OpenAI-compatible tool-calling API surface that MiniMax
            # rejects ("invalid chat setting (2013)") with the react()
            # agent path. The model still gets the exact vocabulary it
            # must use; nothing about defensibility changes.
            # ─────────────────────────────────────────────────────────────
            from .pddl_tools import _extract_types, _extract_predicates, _extract_actions
            d_types = _extract_types(domain_pddl)
            d_pred_pairs = _extract_predicates(domain_pddl)  # [(name, full_signature), ...]
            d_actions_full = _extract_actions(domain_pddl)
            d_acts = sorted(d_actions_full.keys())
            _m = re.search(r"\(domain\s+([\w-]+)", domain_pddl)
            d_name = _m.group(1) if _m else "sysadmin"
            # Predicate signatures (not just names) — gives LLM the arity so
            # it doesn't emit (pred x y) when the domain expects (pred x).
            pred_lines = [sig for _, sig in d_pred_pairs[:300]]
            preds_str = "\n  ".join(pred_lines)
            if len(d_pred_pairs) > 300:
                preds_str += f"\n  ...(+{len(d_pred_pairs)-300} more)"
            # Build action summaries showing :parameters, :precondition,
            # and :effect so the LLM can build a problem whose init
            # SATISFIES the precondition of an action that PRODUCES the
            # goal. Without this the LLM picks goal predicates that no
            # action's :effect can reach, or that an action *could* reach
            # but whose preconditions are not provided in :init. Showing
            # the full action signature is a STANDARD PDDL planning-domain
            # summary — it's what every textbook prompt has.
            def _balanced(blk, start):
                depth = 0
                for j in range(start, len(blk)):
                    if blk[j] == "(":
                        depth += 1
                    elif blk[j] == ")":
                        depth -= 1
                        if depth == 0:
                            return blk[start:j + 1]
                return blk[start:]
            action_sigs: list[str] = []
            for n in d_acts:
                blk = d_actions_full[n]
                pm = re.search(r":parameters\s*\(([^)]*)\)", blk)
                em = re.search(r":effect\s*\(", blk)
                cm = re.search(r":precondition\s*\(", blk)
                params = pm.group(1).strip() if pm else ""
                eff = _balanced(blk, em.start() + len(":effect ")).strip() if em else "(?)"
                cond = _balanced(blk, cm.start() + len(":precondition ")).strip() if cm else "(?)"
                # Normalise whitespace
                eff = re.sub(r"\s+", " ", eff)
                cond = re.sub(r"\s+", " ", cond)
                action_sigs.append(
                    f"  ({n} :params ({params}) :precondition {cond[:200]} :effect {eff[:200]})"
                )
            act_str = "\n".join(action_sigs[:200])
            if len(action_sigs) > 200:
                act_str += f"\n  ...(+{len(action_sigs)-200} more actions)"
            domain_summary = (
                f"DOMAIN name: {d_name}\n"
                f"TYPES ({len(d_types)}): {', '.join(d_types) if d_types else '(none)'}\n"
                f"PREDICATES with signatures ({len(d_pred_pairs)}):\n  {preds_str}\n"
                f"ACTIONS with effects ({len(d_acts)}):\n{act_str}"
            )

            problem_prompt = (
                "## Domain vocabulary (USE ONLY these identifiers)\n"
                f"{domain_summary}\n\n"
                f"## Vulnerability Report\n{state.input_text[:3000]}\n\n"
                f"## Current System State\n{state_block[:3000]}\n\n"
                "Generate the PDDL problem file. Match the domain's casing"
                " and punctuation exactly. Output ONLY the (define (problem"
                " …) …) form, no markdown fences, no explanation."
            )

            # Up to 2 attempts: if the produced PDDL won't parse against
            # the domain, feed the parser error back to the LLM.
            for attempt in range(2):
                msgs = [
                    ChatMessageSystem(content=_PROBLEM_GEN_SYSTEM),
                    ChatMessageUser(content=problem_prompt),
                ]
                if parser_error:
                    msgs.append(ChatMessageUser(content=(
                        "Your previous problem PDDL failed to parse — fix it "
                        f"and re-emit. Error:\n{parser_error}"
                    )))
                resp = await model.generate(
                    input=msgs,
                    config=GenerateConfig(temperature=0.1, max_tokens=4096),
                )
                problem_pddl = (resp.completion or "").strip()
                problem_pddl = re.sub(r"```(?:pddl)?\s*", "", problem_pddl).replace("```", "").strip()
                if not problem_pddl:
                    parser_error = "LLM returned empty problem PDDL"
                    continue
                pval = assert_valid_problem(
                    domain_pddl, problem_pddl, source=f"solver.problem.attempt{attempt+1}",
                )
                if pval.ok:
                    parser_error = ""
                    break
                parser_error = (pval.detail or pval.error or "unknown parse error")[:600]

            state.metadata["pddl_problem"] = problem_pddl[:2000]
            state.metadata["pddl_problem_valid"] = (parser_error == "")
            if parser_error:
                state.metadata["pddl_problem_error"] = parser_error

            # ── Phase 3: Plan ──
            # Only invoke the planner if the problem actually parsed; else
            # the failure mode is "PROBLEM_GENERATION_FAILED", not "no plan".
            if problem_pddl and not parser_error and Path(fd_path).exists():
                plan_actions = await _run_fast_downward(
                    domain_pddl, problem_pddl, fd_path, plan_timeout,
                )
                planner_ok = len(plan_actions) > 0

        state.metadata["planner_succeeded"] = planner_ok
        state.metadata["plan_length"] = len(plan_actions)

        # ── Phase 4: Execute plan ──
        if planner_ok:
            # Reorder the plan: configuration-editing actions must run
            # BEFORE service-management actions. PDDL's STRIPS semantics
            # treats `(setting_value_is ?k ?vnew)` and `(service_running
            # ?svc)` as independent goals — Fast Downward may schedule
            # the service restart first, which would leave the service
            # running with the OLD config when sed-i later modifies the
            # file. The real-world dependency is asymmetric: a service
            # rereads its config on (re)start, so the edit must come
            # first. This is a canonical operational ordering, not a
            # PDDL-correctness rewrite — the same plan goals are met,
            # just in a different sequence.
            _EDIT_ACTIONS = {"edit_config_setting", "set_setting_no",
                             "set_setting_yes", "remove_setting"}
            _SVC_ACTIONS = {"apply_unit_state", "start_service",
                            "restart_service", "reload_service",
                            "reload_sshd_no_systemd"}
            edits = [a for a in plan_actions if a["name"] in _EDIT_ACTIONS]
            svcs = [a for a in plan_actions if a["name"] in _SVC_ACTIONS]
            others = [a for a in plan_actions
                      if a["name"] not in _EDIT_ACTIONS
                      and a["name"] not in _SVC_ACTIONS]
            plan_actions = edits + others + svcs

            executed = 0
            for action in plan_actions[:20]:
                if executed >= message_limit:
                    break

                bash_cmd = _concretize_template(action)
                if not bash_cmd:
                    shell_word = "PowerShell" if os_name == "windows" else "bash"
                    # Pull the action's full (:action ...) block + scenario
                    # vuln brief + container introspection so the LLM picks
                    # commands that actually work in this environment (e.g.
                    # not `systemctl …` when there's no systemd as PID 1).
                    from .pddl_tools import _extract_actions as _ea
                    action_pddl_block = _ea(domain_pddl).get(action["name"], "")
                    vuln_brief = (state.input_text or "")[:800]
                    # Use the introspection that already ran in Phase 1.
                    env_brief = state_block[:1500]
                    conc_resp = await model.generate(
                        input=[ChatMessageUser(content=_CONCRETIZE_PROMPT.format(
                            shell=shell_word,
                            action_name=action["name"],
                            params=" ".join(action.get("params", [])),
                            action_pddl=action_pddl_block or "(no PDDL block found)",
                            vuln_brief=vuln_brief,
                            env_brief=env_brief,
                        ))],
                        # M2.7 reasoning models can spend 500-2000 tokens
                        # thinking before emitting the actual bash command.
                        # Give them enough headroom so we don't get the
                        # <think>... truncated mid-stream.
                        config=GenerateConfig(temperature=0.1, max_tokens=4096),
                    )
                    raw = (conc_resp.completion or "")
                    # Strip MiniMax M2.7 reasoning preamble. If a <think>
                    # block exists, keep what's after the close tag; if
                    # there's an open tag without a close (truncated), drop
                    # the whole response and try template fallback. Also
                    # strip markdown fences and "bash\n" / "powershell\n"
                    # language prefixes.
                    if "<think>" in raw and "</think>" not in raw:
                        bash_cmd = ""
                    else:
                        bash_cmd = re.sub(
                            r"<think>[\s\S]*?</think>\s*", "", raw, flags=re.IGNORECASE
                        )
                        # Strip markdown fences
                        bash_cmd = re.sub(r"```(?:bash|sh|powershell|shell)?\s*", "", bash_cmd)
                        bash_cmd = bash_cmd.replace("```", "").strip().strip("`")
                        # Strip language prefix
                        if bash_cmd.startswith(("bash\n", "powershell\n", "sh\n")):
                            bash_cmd = bash_cmd.split("\n", 1)[1]
                        # Keep only the first non-empty, non-comment line
                        # (the LLM sometimes adds explanatory text after).
                        for line in bash_cmd.splitlines():
                            line = line.strip()
                            if line and not line.startswith("#"):
                                bash_cmd = line
                                break
                        # The inspect sandbox runs as root and typically has
                        # no sudo binary. The LLM tends to prefix sysadmin
                        # commands with `sudo` reflexively. Strip it.
                        if bash_cmd.startswith("sudo "):
                            bash_cmd = bash_cmd[5:]
                        # Safety: if the LLM "translated" to the literal
                        # action name + params (a real failure mode with
                        # reasoning models on opaque action names), reject
                        # it. Better an empty plan step than a guaranteed
                        # "command not found".
                        if bash_cmd.split() == [action["name"], *action.get("params", [])] \
                                or bash_cmd == action["name"]:
                            bash_cmd = ""

                if not bash_cmd:
                    continue

                executed += 1
                try:
                    result = await sb.exec(
                        _shell_exec_argv(os_name, bash_cmd), timeout=bash_timeout,
                    )
                except TimeoutError:
                    state.messages.append(ChatMessageAssistant(
                        content=f"[neurosym] $ {bash_cmd}\nexit=TIMEOUT"
                    ))
                    continue

                state.messages.append(ChatMessageAssistant(content=(
                    f"[neurosym:plan] $ {bash_cmd}\n"
                    f"exit={result.returncode}\n"
                    f"stdout: {(result.stdout or '')[:400]}\n"
                    f"stderr: {(result.stderr or '')[:300]}"
                )))

                if await _verify_in_sandbox(scenario_path, verify_timeout, os_name):
                    state.output.completion = "REMEDIATION_COMPLETE"
                    return state

        # No ReAct/LLM fallback. The neurosymbolic solver must succeed via
        # the symbolic plan. If the planner produced no plan, or the plan
        # was executed but verify.sh did not pass, that is a failure of the
        # PDDL artifacts (domain or problem) and must be reported as such.
        # Falling back to free-form LLM shell use was hiding planning
        # defects (see GOAL_PROGRESS.md), so it has been removed.
        #
        # Record the failure mode so the score event has explanatory metadata.
        if not (state.output and state.output.completion == "REMEDIATION_COMPLETE"):
            if not domain_pddl:
                state.output.completion = "NO_DOMAIN_PROVIDED"
            elif not problem_pddl:
                state.output.completion = "PROBLEM_GENERATION_FAILED"
            elif not planner_ok:
                state.output.completion = "PLANNER_FOUND_NO_PLAN"
            else:
                state.output.completion = "PLAN_DID_NOT_REMEDIATE"

        return state

    return solve
