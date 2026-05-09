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

import json
import re
import subprocess
import tempfile
from pathlib import Path

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
- Use lowercase PDDL names with hyphens (e.g., openssh-server, sshd).
"""

_CONCRETIZE_PROMPT = (
    "Translate this PDDL plan action to a single {shell} command.\n"
    "Action: {action_name}\nParameters: {params}\n"
    "Output ONLY the command, nothing else. No markdown, no explanation."
)

# ---------------------------------------------------------------------------
# Action → bash templates (avoids LLM call for the common cases)
# ---------------------------------------------------------------------------

_ACTION_TEMPLATES: dict[str, str] = {
    "install_package":      "apt-get install -y {0}",
    "remove_package":       "apt-get remove -y {0}",
    "update_package":       "apt-get install -y --only-upgrade {0}",
    "purge_package":        "apt-get purge -y {0}",
    "restart_service":      "systemctl restart {0}",
    "start_service":        "systemctl start {0}",
    "stop_service":         "systemctl stop {0}",
    "enable_service":       "systemctl enable {0}",
    "disable_service":      "systemctl disable {0}",
    "reload_service":       "systemctl reload {0}",
    "lock_user":            "usermod -L {0}",
    "set_file_permissions": "chmod {0} {1}",
    "set_file_owner":       "chown {0} {1}",
    "remove_file":          "rm -f {0}",
    "block_port":           "ufw deny {0}",
    "allow_port":           "ufw allow {0}",
    "enable_firewall":      "ufw --force enable",
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


def _concretize_template(action: dict) -> str | None:
    name = action["name"]
    params = action.get("params", [])
    tmpl = _ACTION_TEMPLATES.get(name) or _ACTION_TEMPLATES.get(
        name.replace("-", "_")
    )
    if tmpl and params:
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

        # Load PDDL domain
        domain_pddl = ""
        if domain_path and Path(domain_path).exists():
            domain_pddl = Path(domain_path).read_text()

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

        if domain_pddl:
            problem_prompt = (
                f"## Vulnerability Report\n{state.input_text[:3000]}\n\n"
                f"## Current System State\n{state_block[:3000]}\n\n"
                "Generate the PDDL problem file for domain \"sysadmin\"."
            )
            problem_resp = await model.generate(
                input=[
                    ChatMessageSystem(content=_PROBLEM_GEN_SYSTEM),
                    ChatMessageUser(content=problem_prompt),
                ],
                config=GenerateConfig(temperature=0.1, max_tokens=4096),
            )
            problem_pddl = (problem_resp.completion or "").strip()
            problem_pddl = re.sub(r"```(?:pddl)?\s*", "", problem_pddl)
            problem_pddl = problem_pddl.replace("```", "").strip()
            state.metadata["pddl_problem"] = problem_pddl[:2000]

            # ── Phase 3: Plan ──
            if problem_pddl and Path(fd_path).exists():
                plan_actions = await _run_fast_downward(
                    domain_pddl, problem_pddl, fd_path, plan_timeout,
                )
                planner_ok = len(plan_actions) > 0

        state.metadata["planner_succeeded"] = planner_ok
        state.metadata["plan_length"] = len(plan_actions)

        # ── Phase 4: Execute plan ──
        if planner_ok:
            executed = 0
            for action in plan_actions[:20]:
                if executed >= message_limit:
                    break

                bash_cmd = _concretize_template(action)
                if not bash_cmd:
                    shell_word = "PowerShell" if os_name == "windows" else "bash"
                    conc_resp = await model.generate(
                        input=[ChatMessageUser(content=_CONCRETIZE_PROMPT.format(
                            shell=shell_word,
                            action_name=action["name"],
                            params=" ".join(action.get("params", [])),
                        ))],
                        config=GenerateConfig(temperature=0.1, max_tokens=256),
                    )
                    bash_cmd = (conc_resp.completion or "").strip().strip("`")
                    if bash_cmd.startswith(("bash\n", "powershell\n")):
                        bash_cmd = bash_cmd.split("\n", 1)[1]

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

        # ── Phase 5: LLM fallback ──
        if enable_llm_fallback and not (
            state.output and state.output.completion == "REMEDIATION_COMPLETE"
        ):
            note = ""
            if planner_ok:
                note = " The PDDL plan was executed but verification still fails."
            elif domain_pddl:
                note = " The PDDL planner could not find a plan."
            else:
                note = " No PDDL domain available."

            state.messages.append(ChatMessageUser(
                content=f"Continue remediation using shell commands.{note}"
            ))

            tools = [_shell_tool(bash_timeout), text_editor(), think()]
            inner = react(
                tools=tools,
                attempts=1,
                on_continue="Continue, or call submit() if remediation is complete.",
            )
            inner_state = AgentState(messages=list(state.messages))
            inner_state = await inner(inner_state)
            state.messages = inner_state.messages

            if await _verify_in_sandbox(scenario_path, verify_timeout, os_name):
                state.output.completion = "REMEDIATION_COMPLETE"

        return state

    return solve
