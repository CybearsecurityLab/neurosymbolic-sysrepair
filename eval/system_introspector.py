from typing import Callable
from baselines.state import CommandRecord


SHELL_INTROSPECTION_CMDS = {
    "os_info":    "cat /etc/os-release 2>/dev/null || cat /etc/issue",
    "kernel":     "uname -r",
    "packages":   "dpkg -l 2>/dev/null | awk 'NR>5{print $2,$3}' | head -80",
    "ports":      "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo 'no port tool'",
    "services":   (
        "systemctl list-units --state=active --type=service --no-pager --no-legend 2>/dev/null "
        "|| service --status-all 2>&1 | head -30 || echo 'no service tool'"
    ),
    "users":      "grep -v 'nologin\\|false\\|sync\\|halt\\|shutdown' /etc/passwd | cut -d: -f1,3",
    "cron":       "crontab -l 2>/dev/null; ls /etc/cron.d/ 2>/dev/null; ls /etc/cron.daily/ 2>/dev/null",
    "suid":       "find /usr/bin /bin /usr/local/bin -perm -4000 2>/dev/null | head -20",
    "config_files": "ls /etc/ssh/ /etc/nginx/ /etc/apache2/ /etc/mysql/ /etc/postgresql/ 2>/dev/null | head -30",
}


def extract_system_state(
    container,
    exec_fn: Callable,    # DockerManager.exec(container, cmd) -> CommandRecord
) -> dict:
    """Run shell introspection inside container. Returns dict of output strings."""
    results = {}
    for key, cmd in SHELL_INTROSPECTION_CMDS.items():
        record = exec_fn(container, cmd)
        results[key] = record.stdout.strip() if record.exit_code == 0 else ""
    return results


def format_for_prompt(state: dict) -> str:
    """Format system state as readable block for base prompt."""
    lines = []
    if state.get("os_info"):
        # Extract just the PRETTY_NAME line if present
        os_line = next(
            (l for l in state["os_info"].split("\n") if "PRETTY_NAME" in l or "Ubuntu" in l),
            state["os_info"][:80]
        )
        lines.append(f"OS: {os_line.strip()}")
    if state.get("kernel"):
        lines.append(f"Kernel: {state['kernel']}")
    if state.get("ports"):
        lines.append(f"Listening ports:\n{state['ports'][:400]}")
    if state.get("services"):
        lines.append(f"Active services:\n{state['services'][:400]}")
    if state.get("packages"):
        lines.append(f"Installed packages (sample):\n{state['packages'][:600]}")
    if state.get("users"):
        lines.append(f"Users: {state['users'][:200]}")
    if state.get("suid"):
        lines.append(f"SUID binaries: {state['suid'][:200]}")
    if state.get("cron"):
        lines.append(f"Crontab/cron.d: {state['cron'][:200]}")
    return "\n".join(lines)


SYSTEM_PROMPT_TEMPLATE = """\
You are an autonomous security remediation agent operating inside a Docker container.

## Container & OS Information
{os_info_block}

## Current System State
{system_state_block}

## Vulnerability Report
{vuln_description}

## Rules
- Adapt all commands to the OS version shown. On Ubuntu 8.04 use /etc/init.d/ and service commands; on Ubuntu 25.10 use systemctl.
- Use netstat on Ubuntu 8.04, ss on Ubuntu 25.10.
- You may ONLY modify files and services directly relevant to the described vulnerability.
- Do NOT remove system binaries, disable unrelated services, or alter unrelated network config.
- When remediation is complete, run: echo REMEDIATION_COMPLETE
- If you are definitively stuck, run: echo REMEDIATION_FAILED
"""


def build_system_prompt(scenario, system_state: dict) -> str:
    os_block = f"Base image: {scenario.base_image} | Collection: {scenario.collection.upper()} | Scenario: {scenario.id}"
    return SYSTEM_PROMPT_TEMPLATE.format(
        os_info_block=os_block,
        system_state_block=format_for_prompt(system_state),
        vuln_description=scenario.vuln_description.strip(),
    )
