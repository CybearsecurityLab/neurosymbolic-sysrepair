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
import os
import re
import shlex
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
  uptime is part of the remediation contract.
- ONE VALUE PER SETTING. A setting holds a single value, so a goal must
  name exactly one target value token per setting. NEVER assert two values
  for the same setting at once (e.g. both (setting_value_is SSLProtocol
  tlsv1_2) and (setting_value_is SSLProtocol tlsv1_3)) — that is an
  unsatisfiable mutex and the task is provably unsolvable. If the fix is
  "allow only modern protocols", encode it as one token, e.g.
  (setting_value_is SSLProtocol tls12_plus).
- RUNTIME EFFECT VIA RELOAD. When the remediation edits a config file that a
  RUNNING service reads, the daemon must be reloaded for the change to take
  effect, or the live check fails. Force the reload one of two ways:
  (a) PREFERRED, if the domain declares (config_applied ?svc): put
      (config_applied <svc>) in the GOAL and NOT in :init, and keep
      (service_running <svc>) in BOTH :init and goal. Plan = edit-then-reload;
      the reload action requires only (service_running <svc>) and works on a
      bare-process daemon without systemd.
  (b) FALLBACK, if the domain does NOT declare (config_applied): keep
      (service_running <svc>) in the GOAL but OMIT it from :init, so the
      planner must add a service action to re-establish it (run as a reload).
  NEVER leave (service_running <svc>) in both :init and goal with no reload
  path — that yields an edit-only plan that fails the live check.
- systemd is optional: the reload path needs no (systemd_init_present). Only
  declare it if you deliberately use start_service/restart_service.
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
      (service_running sshd))
    (:goal (and
      (setting_value_is PermitRootLogin no)
      (service_running sshd)
      (config_applied sshd))))
  This yields edit-then-reload: edit_config_setting sets PermitRootLogin no,
  reload_sshd_no_systemd applies it (config_applied sshd) while keeping the
  service up. The same shape works for apache2 SSL, nginx, etc.

Worked example for filesystem-hardening scenarios (SUID binary, world-writable
directory, sensitive log, dangerous capability). Name the file object after its
real path; the concretizer resolves it. Pick the MINIMAL operator: use
remove_world_writable (drops only o-w, preserving execute/serve) for a
world-writable dir like /usr/lib/cgi-bin; use restrict_file_access (drops all
world access) only for files that must not be world-readable at all (logs, keys):

  (define (problem harden_X) (:domain sysadmin)
    (:objects
      usr_sbin_exim4 - file)
    (:init
      (has_suid usr_sbin_exim4))
    (:goal (and
      (suid_removed usr_sbin_exim4))))
  This yields remove_suid_bit, which chmod u-s,g-s the real /usr/sbin/exim4.
  For a world-writable cgi-bin: :init (world_writable usr_lib_cgi_bin),
  :goal (world_write_removed usr_lib_cgi_bin) -> remove_world_writable.
  For a dangerous capability: :init (has_dangerous_capability usr_bin_find),
  :goal (capability_removed usr_bin_find) -> remove_file_capability.
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
    "- To apply a config change to a RUNNING service, prefer a signal-based"
    " reload of the live process — it is init-agnostic and non-destructive."
    " If the container has no systemd as PID 1 and no /etc/init.d script for"
    " the service (e.g. sshd started as a bare process), do NOT use"
    " `service X restart` or `systemctl` — they will fail. Instead validate"
    " then signal, e.g. `sshd -t && kill -HUP $(pgrep -x sshd | head -1)`"
    " for sshd, or `kill -HUP $(pgrep -x <svc> | head -1)` generally; only if"
    " the process is not running should you start it (`/usr/sbin/<svc>`)."
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
    # Applying a config change to a RUNNING service: prefer a signal-based
    # reload (SIGHUP) of the live process. This is init-agnostic — it works
    # whether the service is supervised by systemd, SysV init, or (as in the
    # benchmark containers) started as a bare process with no init at all,
    # where `service X restart` fails because there is no /etc/init.d/X. It
    # is also NON-DESTRUCTIVE (no downtime), which matters for the
    # availability objective. Falls back to service/systemctl/direct-exec
    # only when the process is not already running.
    # Aliveness-checked reload: SIGHUP the live daemon, and if it did NOT
    # survive (e.g. apache2, which treats SIGHUP as a hard restart and needs its
    # envvars sourced) bring it back via its init wrapper, which does source
    # them. sshd survives HUP so the restart branch never fires. General across
    # daemons; non-destructive where possible, self-healing where not.
    "restart_service":      "pid=$(pgrep -x {0} 2>/dev/null | head -1); if [ -n \"$pid\" ]; then kill -HUP \"$pid\" 2>/dev/null; sleep 1; pgrep -x {0} >/dev/null 2>&1 || service {0} restart 2>/dev/null || systemctl restart {0} 2>/dev/null || /usr/sbin/{0} 2>/dev/null; else service {0} restart 2>/dev/null || systemctl restart {0} 2>/dev/null || /usr/sbin/{0} 2>/dev/null; fi",
    "start_service":        "pid=$(pgrep -x {0} 2>/dev/null | head -1); if [ -n \"$pid\" ]; then kill -HUP \"$pid\" 2>/dev/null; sleep 1; pgrep -x {0} >/dev/null 2>&1 || service {0} restart 2>/dev/null || systemctl restart {0} 2>/dev/null || /usr/sbin/{0} 2>/dev/null; else service {0} start 2>/dev/null || /usr/sbin/{0} 2>/dev/null || systemctl start {0} 2>/dev/null; fi",
    # Phase-1 mined synonym for start_service in some domains
    # (e.g. ccdc-01's refined domain). Same semantic: ensure the
    # service is running with the current config. Reload-in-place if
    # already up so it succeeds on containers that boot with a bash
    # keepalive (or the service itself) as pid 1.
    "apply_unit_state":     "pid=$(pgrep -x {0} 2>/dev/null | head -1); if [ -n \"$pid\" ]; then kill -HUP \"$pid\" 2>/dev/null; sleep 1; pgrep -x {0} >/dev/null 2>&1 || service {0} restart 2>/dev/null || systemctl restart {0} 2>/dev/null || /usr/sbin/{0} 2>/dev/null; else service {0} start 2>/dev/null || /usr/sbin/{0} 2>/dev/null || systemctl start {0} 2>/dev/null; fi",
    "stop_service":         "(service {0} stop 2>/dev/null) || systemctl stop {0}",
    "enable_service":       "systemctl enable {0}",
    "disable_service":      "(service {0} stop 2>/dev/null; systemctl disable {0})",
    "reload_service":       "pid=$(pgrep -x {0} 2>/dev/null | head -1); if [ -n \"$pid\" ]; then kill -HUP \"$pid\" 2>/dev/null; sleep 1; pgrep -x {0} >/dev/null 2>&1 || service {0} restart 2>/dev/null || systemctl restart {0} 2>/dev/null || /usr/sbin/{0} 2>/dev/null; else service {0} reload 2>/dev/null || systemctl reload {0} 2>/dev/null; fi",
    # No-systemd config reload (domain models this explicitly). SIGHUP the
    # running daemon named {0} so it re-reads its config — works for a bare
    # process (sshd, apache2, nginx, ...) and is non-destructive. Parameterised
    # on the service, NOT hard-coded to sshd (a plan grounding this with apache2
    # must never HUP sshd). Falls back to service/systemctl reload.
    "reload_sshd_no_systemd":
        "pid=$(pgrep -x {0} 2>/dev/null | head -1); if [ -n \"$pid\" ]; then kill -HUP \"$pid\" 2>/dev/null; sleep 1; pgrep -x {0} >/dev/null 2>&1 || service {0} restart 2>/dev/null || systemctl restart {0} 2>/dev/null || /usr/sbin/{0} 2>/dev/null; else service {0} reload 2>/dev/null || systemctl reload {0} 2>/dev/null; fi",
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
    # Filesystem-hardening operators (canonical). Single file param {0},
    # resolved to a real path by the concretizer's file grounding.
    "remove_suid_bit":        "chmod u-s,g-s {0}",
    "remove_world_writable":  "chmod -R o-w {0}",
    "restrict_file_access":   "chmod o-rwx {0}",
    "remove_file_capability": "setcap -r {0} 2>/dev/null || setcap -q -r {0}",
}

# osquery tables read at solve time when osqueryi is available. These mirror the
# categories the offline domain-construction snapshot uses, so the lifted state
# has the same shape whether it came from osquery or from the shell probes.
_OSQUERY_QUERIES = {
    "osq_packages": "SELECT name, version FROM deb_packages LIMIT 60",
    "osq_services": "SELECT name, status FROM systemd_units WHERE active_state='active' LIMIT 30",
    "osq_ports":    "SELECT DISTINCT port, protocol FROM listening_ports WHERE port != 0 LIMIT 30",
    "osq_users":    "SELECT username, uid, shell FROM users LIMIT 40",
}


async def _ensure_osquery(sb, os_name: str, bash_timeout: int) -> tuple[bool, str]:
    """Install osquery into the sandbox and confirm it answers a query.

    Returns (available, detail). Never raises: a base that cannot host osquery
    (musl, an image with no shell, Ubuntu 8.04's glibc 2.7 against osquery's
    GLIBC_2.12 floor) must fall through to the shell probes rather than fail the
    episode. That fallback is the normal path for 107 of the 297 scenarios,
    measured across every base image the corpus builds from.

    Gated by NEUROPLAN_INSTALL_OSQUERY so a run's substrate is a recorded
    choice: results produced with osquery in the loop are not comparable with
    results produced without it.
    """
    if os.environ.get("NEUROPLAN_INSTALL_OSQUERY", "1") != "1":
        return False, "disabled by NEUROPLAN_INSTALL_OSQUERY"
    if os_name == "windows":
        # osquery ships an MSI for Windows; the Linux install script cannot run
        # there. Left to the Windows host rather than half-attempted here.
        return False, "windows: MSI path not attempted from this host"
    probe = '/usr/bin/osqueryi --json "SELECT name FROM os_version LIMIT 1" 2>/dev/null'
    try:
        r = await sb.exec(_shell_exec_argv(os_name, probe), timeout=bash_timeout)
        if r.returncode == 0 and '"name"' in (r.stdout or ""):
            return True, "already present"
    except Exception:
        pass
    try:
        from common.container import osquery_install_sh
        r = await sb.exec(_shell_exec_argv(os_name, osquery_install_sh()),
                          timeout=max(bash_timeout, 600))
        r2 = await sb.exec(_shell_exec_argv(os_name, probe), timeout=bash_timeout)
        if r2.returncode == 0 and '"name"' in (r2.stdout or ""):
            return True, "installed"
        return False, ((r.stderr or r.stdout or "").strip()[-120:] or "install did not yield a working osqueryi")
    except Exception as e:
        return False, f"{type(e).__name__}: {str(e)[:100]}"


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
    # Application name+version behind each listening socket, plus the owning
    # package. Process-driven (whatever daemon holds a port), NOT keyed on any
    # application name, so it works identically for apache2/nginx/vsftpd/exim/
    # sshd/mysqld. Feeds value-grounding so generated directives match the app's
    # real syntax + version.
    # Standard filesystem-hardening audit: SUID/SGID binaries, file
    # capabilities, and world-writable paths in common web/service roots. This
    # is a textbook security audit (not benchmark-specific), and its real paths
    # both inform the problem generator and ground the file-permission operators.
    "perm_audit": (
        "echo '# suid'; find / -xdev -type f -perm -4000 2>/dev/null | head -30; "
        "echo '# sgid'; find / -xdev -type f -perm -2000 2>/dev/null | head -20; "
        "echo '# caps'; getcap -r / 2>/dev/null | head -20; "
        "echo '# world_writable'; find /var/www /usr/lib/cgi-bin /srv /opt "
        "/tmp /var/tmp /var/spool -xdev \\( -perm -0002 \\) 2>/dev/null | head -40; "
        # World-accessible log files. The command MUST exit 0 even when some
        # paths are absent, or the whole audit's stdout is discarded on
        # returncode!=0 (which was dropping the SUID list and forcing grounding
        # onto threat-report prose). find never errors on a missing path.
        "echo '# world_readable_logs'; find /var/log -maxdepth 2 -type f "
        "-perm -0004 2>/dev/null | head -20; true"
    ),
    "app_versions": (
        # Binaries of the currently-running daemons via /proc (portable: no ss /
        # netstat / lsof dependency), each with its version banner and owning
        # package. Process-driven, keyed on no application name.
        "for l in /proc/[0-9]*/exe; do readlink \"$l\" 2>/dev/null; done "
        "| grep -E '^/(usr/)?(s?bin)/' | sort -u | while read e; do "
        "echo \"== $e\"; { \"$e\" -v 2>&1; \"$e\" -V 2>&1; } | head -2; "
        "dpkg -S \"$e\" 2>/dev/null | cut -d: -f1 | sort -u "
        "| xargs -r dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null; "
        "done | head -50"
    ),
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


# Generic tokens that carry no discriminating signal when matching an
# invented config identifier to a real file (e.g. "default_ssl_conf").
_CONFIG_GENERIC_TOKENS = frozenset({
    "config", "conf", "cfg", "file", "default", "etc", "settings",
    "configuration", "cnf", "d", "main",
})


def _config_tokens(s: str) -> set[str]:
    """Discriminating tokens of a config identifier or path basename."""
    base = s.rsplit("/", 1)[-1]
    parts = re.split(r"[^a-z0-9]+", base.lower())
    return {p for p in parts if p and p not in _CONFIG_GENERIC_TOKENS}


def _load_scenario_config_map(domain_path: str) -> dict[str, str]:
    """Build a per-scenario {identifier -> real path} map from the Phase 1
    introspection that sits beside the domain (``phase1_state.json``).

    Phase 1 records every discovered ``configuration_file`` object with its
    real ``path`` and ``original_name`` (e.g. ``/etc/apache2/mods-enabled/
    ssl.conf``). Keying on the PDDL-safe name, the original path, and the
    bare/normalized basename lets the concretizer resolve nested service
    configs the static alias map never enumerates, which is the general
    PDDL-identifier <-> real-path grounding gap.
    """
    mapping: dict[str, str] = {}
    if not domain_path:
        return mapping
    state_file = Path(domain_path).parent / "phase1_state.json"
    if not state_file.exists():
        return mapping
    try:
        state = json.loads(state_file.read_text())
    except Exception:
        return mapping
    objects = state.get("objects", {}) or {}
    cfgs = objects.get("configuration_file", []) or []
    for obj in cfgs:
        props = obj.get("properties", {}) or {}
        path = props.get("path") or obj.get("original_name")
        if not path:
            continue
        for key in (obj.get("name"), obj.get("original_name"),
                    props.get("filename"), path):
            if key:
                mapping[key] = path
                mapping[_normalize_setting_key(str(key))] = path

    # Phase 1 also records users, groups, processes and ports, and mined
    # templates reference them exactly as they reference config files. Keying
    # only on configuration_file meant a parameter naming a user or a service
    # could NEVER resolve and reached the shell as a literal identifier:
    # measured on vulnhub, `mysql -e "REVOKE ... FROM 'webapp_user'"` ran with
    # the PDDL token in place of the account name, on a scenario whose Phase 1
    # had recorded 4 users. Config files resolve to a path; these resolve to
    # their real name, which is what a command needs.
    for kind in ("user", "group", "process", "port", "service"):
        for obj in objects.get(kind, []) or []:
            props = obj.get("properties", {}) or {}
            real = (props.get("username") or props.get("name")
                    or props.get("port") or obj.get("original_name"))
            if real is None:
                continue
            real = str(real)
            for key in (obj.get("name"), obj.get("original_name"), props.get("name")):
                if key and str(key) not in mapping:
                    mapping[str(key)] = real
                    mapping[_normalize_setting_key(str(key))] = real
    return mapping


def _resolve_config_path(pddl_name: str,
                         scenario_map: dict[str, str] | None = None) -> str:
    """Translate a PDDL identifier for a config file to its real path.

    Resolution order: static alias map (common system files) -> per-scenario
    discovered configs (exact, then normalized) -> best token-overlap match
    against discovered configs (recovers invented identifiers like
    ``default_ssl_conf`` for ``/etc/apache2/mods-enabled/ssl.conf``) -> raw
    name (the bash command then fails visibly rather than silently).
    """
    if pddl_name in _CONFIG_PATH_ALIASES:
        return _CONFIG_PATH_ALIASES[pddl_name]
    if os.environ.get("NEUROPLAN_DISABLE_GROUNDING") == "1":
        return _CONFIG_PATH_ALIASES.get(pddl_name, pddl_name)
    if scenario_map:
        if pddl_name in scenario_map:
            return scenario_map[pddl_name]
        norm = _normalize_setting_key(pddl_name)
        if norm in scenario_map:
            return scenario_map[norm]
        want = _config_tokens(pddl_name)
        if want:
            best, best_score = None, 0
            for key, path in scenario_map.items():
                score = len(want & _config_tokens(path))
                if score > best_score:
                    best, best_score = path, score
            if best is not None:
                return best
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


def _concretize_template(action: dict,
                         scenario_map: dict[str, str] | None = None,
                         file_map: dict[str, str] | None = None,
                         mined_templates: dict | None = None) -> str | None:
    name = action["name"]
    params = action.get("params", []) or []
    # Prefer the operator's OWN mined command_template over a static one. FD plan
    # actions carry only {name, params}, so without this the static
    # _ACTION_TEMPLATES entry wins — e.g. a benign mined `service {svc} restart`
    # gets shadowed by the destructive static `disable_service` (stop+disable).
    mined = (mined_templates or {}).get(name)
    tmpl = (mined.get("command_template") if mined else None) or \
        _ACTION_TEMPLATES.get(name) or _ACTION_TEMPLATES.get(name.replace("-", "_"))
    if tmpl and params:
        params = list(params)
        # Ground params by the mined operator's per-param grounding tags when
        # present (config_path/audited_file resolve to real paths); else fall
        # back to the canonical name-based resolution below.
        grounding = (mined or {}).get("grounding") if mined else None
        if grounding:
            for i, p in enumerate(action.get("params", []) or []):
                pname = None
                schema_params = (mined or {}).get("parameters", [])
                if i < len(schema_params):
                    pname = schema_params[i].get("name")
                tag = grounding.get(pname) if pname else None
                if tag in ("config_path", "setting_key"):
                    params[i] = _resolve_config_path(p, scenario_map)
                elif tag in ("audited_file", "capability"):
                    params[i] = _resolve_config_path(p, file_map or scenario_map)
        # For canonical config-edit operators, the first param is a
        # PDDL file identifier that must be resolved to a real path.
        elif name in ("edit_config_setting", "set_setting_no"):
            params[0] = _resolve_config_path(params[0], scenario_map)
        # Filesystem-hardening operators: their single file param is a real
        # path (SUID binary, world-writable dir, log). Resolve against the audit
        # file-map first (falling back to config paths only if unmatched).
        elif name in ("remove_suid_bit", "remove_world_writable",
                      "restrict_file_access", "remove_file_capability"):
            params[0] = _resolve_config_path(params[0], file_map or scenario_map)
            # The second param is the setting key — strip separators
            # so sed can match the on-disk CamelCase directive name
            # case-insensitively.
            if len(params) > 1:
                params[1] = _normalize_setting_key(params[1])
        # The miner REQUIRES named placeholders: operator_miner.py's lint rejects
        # any command_template whose {placeholders} are not a subset of the
        # operator's parameter names. Substituting positionally therefore raises
        # KeyError on every mined template, which was caught below and returned
        # None, so the step fell through to the LLM concretiser. Measured on the
        # 30-scenario vulnhub run: 27 steps carried a template with placeholders
        # and 25 of them did not execute it. The neuro-symbolic lowering the
        # pipeline is built around had never run.
        #
        # Bind by NAME from the mined schema's parameter order, and keep the
        # positional path for the static _ACTION_TEMPLATES, which use {0}/{1}.
        try:
            names = [q.get("name") for q in ((mined or {}).get("parameters") or [])]
            if names and len(names) >= len(params):
                bound = {n: v for n, v in zip(names, params) if n}
                return tmpl.format_map(_DefaultingMap(bound, params))
            return tmpl.format(*params)
        except (IndexError, KeyError, ValueError):
            pass
    return None


class _DefaultingMap(dict):
    """Named lookup first, then positional, so a template may mix {f} and {0}.

    A missing key raises KeyError as usual, which the caller treats as "this
    template does not apply" rather than substituting something wrong.
    """

    def __init__(self, named: dict, positional: list):
        super().__init__(named)
        self._pos = positional

    def __missing__(self, key):
        if isinstance(key, str) and key.isdigit():
            return self._pos[int(key)]
        raise KeyError(key)


# ---------------------------------------------------------------------------
# Value grounding: a PDDL value token (e.g. `tls12_plus`) is a symbolic goal,
# not literal config syntax. For config-edit actions we ground it neurally
# against the live application + version and the real file, then accept the
# edit only if the application's OWN native validator passes. No application
# names, directive strings, or scenario ids appear here — every app-specific
# fact arrives at runtime through introspection and the app's own checker.
# ---------------------------------------------------------------------------

_VALUE_GROUND_PROMPT = (
    "You are grounding ONE configuration edit for a remediation plan.\n\n"
    "Applications on this host (name/version, from live introspection):\n{app_versions}\n\n"
    "Vulnerability being remediated:\n{vuln_brief}\n\n"
    "Default file to edit: {path}\n"
    "Directive/setting to set: {key}\n"
    "Symbolic target from the plan (an intent label, NOT literal syntax): {symbolic_value}\n\n"
    "Current contents of {path} (first lines):\n{current}\n\n"
    "{effective}"
    "Return STRICT JSON only, no prose and no markdown fences:\n"
    '{{"line": "<one syntactically-valid configuration directive line for THIS '
    "application and version that achieves the symbolic target above>\", "
    '"validate": "<this application\'s own native configuration-check command, '
    "which exits non-zero on a syntax error (its -t / configtest / -c mode)>\", "
    '"target_path": "<the file the RUNNING daemon actually obeys for this '
    "directive: if the evidence above shows the directive already set in an "
    "active file, use THAT file; otherwise use the default file>\", "
    '"service": "<the exact process name (as `pgrep -x` would match, e.g. '
    "apache2, nginx, sshd, smbd, exim4) of the daemon that must be RESTARTED for "
    "this edit to take effect on its live socket; give one whenever a daemon "
    "reads this file>\", "
    '"prep": "<optional command to regenerate derived config before the restart '
    "(e.g. update-exim4.conf, a2enmod ssl); empty if none>\"}}\n"
    "If ONE directive line cannot achieve the target -- a scoped section "
    "(<Directory>/<Files>/location{{}}/an INI [section]) or an order-sensitive "
    "ACL line -- return instead of \"line\":\n"
    '"block": ["<line 1>", "<line 2>", ...] (the full multi-line payload), and '
    "optionally ONE of:\n"
    '"insert_before": "<extended regex matching an EXISTING line the payload '
    "must PRECEDE -- REQUIRED when the file has first-match semantics and a "
    "broader existing rule would otherwise shadow the new one, e.g. squid's "
    "http_access allow all>\",\n"
    '"insert_in_section": "<extended regex matching the OPENING line of the '
    "section the payload belongs inside (e.g. a server or virtual-host opening, "
    "an INI section header like ^[[:space:]]*\\[global\\])>\".\n"
    "Prefer the single \"line\" form whenever one line suffices. Use "
    "[[:space:]] not \\s in regexes.\n"
    "The directive line must be valid for the application and version shown. "
    "The validate command must be that application's own checker. target_path "
    "must be one of the active files listed in the evidence, or the default file."
)

_EFFECTIVE_PROBE_PROMPT = (
    "A remediation must set directive '{key}' where the RUNNING daemon actually "
    "reads it. Applications on this host:\n{app_versions}\n\n"
    "Remediation context (identifies WHICH daemon and config this targets):\n"
    "{vuln_brief}\n\n"
    "Give THAT application's OWN read-only command that prints the FILE PATHS of "
    "every configuration file the running daemon loads or includes (e.g. "
    "`nginx -T`, `apache2ctl -t -D DUMP_INCLUDES`, `sshd -T`, `testparm -sv`), "
    "so we can locate which file sets the directive. It must emit real /etc/... "
    "file paths, not merely a syntax check. Return STRICT JSON only: "
    '{{"dump": "<the command>"}}.'
)


def _extract_first_json(text: str) -> dict | None:
    """Pull the first JSON object out of an LLM reply (tolerates <think>
    preambles and markdown fences)."""
    if not text:
        return None
    text = re.sub(r"<think>[\s\S]*?</think>", "", text, flags=re.IGNORECASE)
    depth, start = 0, -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                try:
                    obj = json.loads(text[start:i + 1])
                    if isinstance(obj, dict):
                        return obj
                except Exception:
                    start = -1
    return None


def _looks_safe_validator(cmd: str) -> bool:
    """A native config-check is a simple read-only invocation. Reject anything
    that could mutate the box or chain commands — a guard on SHAPE, not on any
    application. Blocks redirection, pipes, chaining, subshells, deletion."""
    if not cmd or len(cmd) > 200:
        return False
    if any(tok in cmd for tok in (">", "<", "|", ";", "&", "$(", "`", "\n",
                                   " rm ", "rm -", "dd ", "mkfs", ":(){", "eval ")):
        return False
    return True


def _directive_grep_pattern(key: str) -> str:
    """Separator-tolerant ERE for a directive key so it matches the CamelCase
    (Apache/sshd `SSLProtocol`), snake_case (nginx `ssl_protocols`) AND
    space-separated (samba `wide links`) on-disk spellings, regardless of which
    separator Fast Downward's PDDL token used. Tokens may be joined on disk by a
    space, hyphen, or underscore, so match any of them between tokens."""
    toks = [t for t in re.split(r"[-_\s]+", key) if t]
    return r"[-_[:space:]]?".join(re.escape(t) for t in toks) or re.escape(key)


async def _effective_config_probe(key, app_versions, model, sb, os_name, bash_timeout,
                                  dbg=None, scenario_map=None, vuln_brief=""):
    """Locate the file the RUNNING daemon actually obeys for ``key``.

    Symmetric to the native-validator idea: the model supplies the application's
    OWN effective-config dump command (e.g. `apache2ctl -t -D DUMP_INCLUDES`,
    `nginx -T`, `sshd -T`); the code guards its shape, runs it, harvests the
    active files it names, keeps the ones that exist, and greps the directive
    across them. Returns ``(evidence_text, candidate_files_set)`` — evidence for
    the value-grounding prompt, and the set the model's target_path is confined
    to. Any failure degrades to ``("", set())`` (caller keeps single-file
    grounding), so a wrong/hallucinated dump never causes a wrong edit.
    """
    try:
        resp = await model.generate(
            input=[ChatMessageUser(content=_EFFECTIVE_PROBE_PROMPT.format(
                key=key, app_versions=(app_versions or "(none)")[:1000],
                vuln_brief=(vuln_brief or "(none)")[:800]))],
            config=GenerateConfig(temperature=0.0, max_tokens=4096))
    except Exception:
        return "", set()
    if dbg is None:
        dbg = {}
    raw = resp.completion or ""
    dump = str((_extract_first_json(raw) or {}).get("dump", "")).strip()
    # Keep only the bare command + args: cut at the first shell metacharacter
    # (pipe/redirect/chain). We capture stdout AND stderr ourselves, so the model
    # never needs `2>&1` or a `| grep`, and the strict shape guard still applies.
    dump = re.split(r"[|;&><`\n]|\$\(", dump)[0].strip()
    dbg["dump_cmd"] = dump
    dbg["raw_head"] = raw[:200]
    if not dump or not _looks_safe_validator(dump):
        dbg["fail"] = "no-dump-or-unsafe"
        return "", set()
    try:
        dr = await sb.exec(_shell_exec_argv(os_name, dump), timeout=bash_timeout)
        dump_out = ((dr.stdout or "") + "\n" + (dr.stderr or ""))[:4000]
    except Exception as e:
        dbg["fail"] = f"dump-exec:{str(e)[:60]}"
        return "", set()
    dbg["dump_out_len"] = len(dump_out)
    dbg["dump_out_head"] = dump_out[:200]
    cands = {c for c in re.findall(r"/[\w.@/+-]+", dump_out)
             if "/" in c and not c.endswith("/")}
    # Fallback / augmentation: also consider the config files Phase 1 already
    # discovered for this scenario. This makes the mechanism robust when the
    # app's dump reports a syntax check rather than a file list, and still lets
    # the grep below reveal exactly which discovered file sets the directive.
    if scenario_map:
        cands |= {v for v in scenario_map.values() if isinstance(v, str) and v.startswith("/")}
    dbg["n_candidates"] = len(cands)
    if not cands:
        dbg["fail"] = "no-candidates"
        return "", set()
    listing = " ".join(shlex.quote(c) for c in list(cands)[:120])
    try:
        lr = await sb.exec(_shell_exec_argv(
            os_name, f"for f in {listing}; do [ -f \"$f\" ] && echo \"$f\"; done"),
            timeout=bash_timeout)
        existing = {l.strip() for l in (lr.stdout or "").splitlines() if l.strip()}
    except Exception:
        existing = set()
    dbg["n_existing"] = len(existing)
    if not existing:
        dbg["fail"] = "no-existing-files"
        return "", set()
    pat = _directive_grep_pattern(key)
    # grep -H forces filename prefixes even with a single file; follow symlinks
    # (sites-enabled/*.conf are symlinks to sites-available).
    files = " ".join(shlex.quote(f) for f in list(existing)[:120])
    hits = ""
    try:
        gr = await sb.exec(_shell_exec_argv(
            os_name, f"grep -HinE '^[[:space:]]*{pat}([[:space:]]|=)' {files} 2>/dev/null | head -20"),
            timeout=bash_timeout)
        hits = (gr.stdout or "").strip()
    except Exception:
        hits = ""
    # Files that actually set the directive are the best edit targets; confine
    # the model's target_path to them (fall back to all active files if none).
    hit_files = {ln.split(":", 1)[0].strip() for ln in hits.splitlines() if ":" in ln}
    hit_files = {f for f in hit_files if f in existing} or existing
    dbg["n_hit_files"] = len(hit_files)
    ev = ("Effective configuration (from the application's own tools and the "
          "discovered config files):\n")
    ev += (f"Directive '{key}' is currently set in these files (choose the one "
           f"the running daemon actually obeys, e.g. a virtual-host/site file "
           f"overrides a module default):\n{hits[:700]}\n\n" if hits
           else f"Directive '{key}' is not set in any known file yet; add it to "
                f"the file the daemon effectively uses.\n\n")
    return ev, hit_files


def _config_edit_triple(action, mined_schema, scenario_map):
    """Extract (path, key, symbolic_value) for a config-edit action.

    Canonical ``edit_config_setting`` uses positional params (file, key, old,
    new). A mined config-edit operator (grounding tags include ``setting_key``
    or ``value_token``) is mapped BY TAG instead. Returns None if the action is
    not a config edit.
    """
    params = list(action.get("params", []) or [])
    name = action["name"]
    # A PDDL object is often an LLM-INVENTED symbol (e.g. `nginx_default_cfg`)
    # that `_resolve_config_path` cannot map to a real file, so it returns the
    # symbol unchanged. Passing that non-file string downstream makes grounding
    # silently no-op against a path that does not exist. Treat any non-absolute
    # resolution as unknown (None) so `_ground_and_apply_edit`'s live-system
    # locator finds the real config file from the running daemon instead.
    def _abs_or_none(p):
        return p if (isinstance(p, str) and p.startswith("/")) else None
    if name in ("edit_config_setting", "set_setting_no"):
        if len(params) < 2:
            return None
        path = _abs_or_none(_resolve_config_path(params[0], scenario_map))
        key = params[1]
        value = params[3] if len(params) > 3 else (
            params[2] if len(params) > 2 else key)
        return path, key, value
    # Mined operator: classify + map by its grounding tags. A config edit is
    # signalled by a setting_key/value_token tag OR by the block-insertion verb
    # (insert_directive_block), whose ops may only carry a config_path tag.
    grounding = (mined_schema or {}).get("grounding") or {}
    tags = set(grounding.values())
    verb = (mined_schema or {}).get("source_utility", "")
    if not ({"setting_key", "value_token"} & tags) and \
            verb != "insert_directive_block":
        return None  # not a config edit
    schema_params = (mined_schema or {}).get("parameters", [])
    path = key = value = None
    for i, sp in enumerate(schema_params):
        if i >= len(params):
            break
        tag = grounding.get(sp.get("name"))
        if tag == "config_path" and path is None:
            path = _abs_or_none(_resolve_config_path(params[i], scenario_map))
        elif tag == "setting_key" and key is None:
            key = params[i]
        elif tag == "value_token" and value is None:
            value = params[i]
    key = key or name
    value = value or key
    # path may be None -> the effective-config probe will supply it downstream.
    return path, key, value


def _directive_from_template(tmpl: str):
    """Extract the config DIRECTIVE/line a mined operator's command_template
    writes into a file, e.g. from
      grep -q '...' {cfg} || echo 'location ~ /\\. { deny all; }' >> {cfg}
    return `location ~ /\\. { deny all; }`. Picks the quoted payload of the
    write verb (echo/printf/tee/cat<<<). Returns "" if none. General: the
    content is the miner's OWN output, no app names in code."""
    if not tmpl:
        return ""
    # A self-contained in-place editor (sed/awk/perl -i) IS the fix and runs as
    # a whole command via the template path; do NOT extract a "directive" from
    # its expression (that would apply the sed s/// string as a config block).
    if re.search(r"\b(sed|awk|perl)\b.*(-i|s/|/[a-z]?')", tmpl):
        return ""
    # payload of a write verb: echo/printf 'X' ...   |  tee ... <<< 'X'
    m = re.search(r"(?:echo|printf)\s+(?:-\S+\s+)*'([^']{3,})'", tmpl)
    if not m:
        m = re.search(r"<<<\s*'([^']{3,})'", tmpl)
    if not m:
        # any quoted string that looks like a directive (has a space or brace)
        for q in re.findall(r"'([^']{3,})'", tmpl):
            if " " in q or "{" in q or "=" in q:
                if not q.strip().startswith("{"):  # skip placeholder-only
                    return q.strip()
        return ""
    return m.group(1).strip()


async def _ground_and_apply_edit(path, key, symbolic_value, scenario_map,
                                 app_versions, vuln_brief,
                                 model, sb, os_name, bash_timeout,
                                 mined_template=""):
    """Value-ground and apply a config edit given resolved (path, key, value).

    Asks the model for the literal directive line + the application's native
    validator + the daemon to reload (given the app+version and the real file),
    applies it with backup (comment old, append new), gates on the validator
    (rollback + re-prompt on failure), then reloads the owning daemon so a
    live-socket/live-HTTP oracle sees the change.

    Returns ``(applied_cmd_str | None, meta)``. ``None`` -> caller falls back.
    """
    if path is None:
        path = ""  # effective-config probe below may still find the file
    # If the path did not resolve to an absolute file (a bare PDDL identifier
    # like `smb_conf`/`php_ini`), locate the real config file under /etc by its
    # discriminating tokens. General config-file locator, no app names in code.
    if not str(path).startswith("/"):
        # Use the PATH identifier's tokens (e.g. smb_conf -> {smb}); only fall
        # back to the key's tokens if the path identifier has none. Mixing them
        # over-constrains the AND-chained grep (smb_conf + widelinks -> no hit).
        disc = _config_tokens(str(path)) or _config_tokens(str(key))
        found = ""
        if disc:
            # Match every discriminating token, order-independent, via chained
            # greps (e.g. php_ini -> grep php | grep ini -> /etc/php/.../php.ini;
            # smb_conf -> grep smb -> /etc/samba/smb.conf).
            greps = " | ".join(f"grep -i {shlex.quote(t)}" for t in sorted(disc))
            try:
                fr = await sb.exec(_shell_exec_argv(
                    os_name,
                    f"find /etc -maxdepth 5 -type f \\( -iname '*.conf' -o -iname '*.cnf' "
                    f"-o -iname '*.ini' -o -iname '*.cf' \\) 2>/dev/null "
                    f"| {greps} | head -1"),
                    timeout=bash_timeout)
                out = (fr.stdout or "").strip()
                found = out.splitlines()[0].strip() if out else ""
            except Exception:
                found = ""
        if found.startswith("/"):
            path = found
    qp = shlex.quote(path) if path else "''"
    try:
        r = await sb.exec(_shell_exec_argv(os_name, f"sed -n '1,120p' {qp} 2>/dev/null"),
                          timeout=bash_timeout)
        current = (r.stdout or "")[:2000]
    except Exception:
        current = ""

    # Listening daemons: the process owning the vulnerable port is usually the
    # one to restart. Fed to the prompt, and used as a deterministic fallback
    # when the model does not name a service (fixes bind-address edits whose
    # plan had no reload action).
    try:
        sr = await sb.exec(_shell_exec_argv(
            os_name, "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"),
            timeout=bash_timeout)
        ss_out = (sr.stdout or "")[:800]
    except Exception:
        ss_out = ""
    listening = ("Listening daemons (the process owning the vulnerable port is "
                 "usually the one to restart):\n" + ss_out + "\n\n") if ss_out else ""

    # Effective-config introspection: find where the running daemon actually
    # obeys this directive (multi-file include graphs: apache vhosts, nginx
    # includes). The model may then target that file instead of the default.
    _probe_dbg: dict = {}
    effective, candidate_files = await _effective_config_probe(
        key, app_versions, model, sb, os_name, bash_timeout, _probe_dbg,
        scenario_map=scenario_map, vuln_brief=vuln_brief)
    effective = listening + effective

    meta: dict = {"path": path, "key": key, "value_grounding_used": True,
                  "effective_probe_used": bool(candidate_files),
                  "candidate_files": len(candidate_files),
                  "probe_debug": _probe_dbg}
    last_err = ""

    # Deterministic mined-directive path. A mined operator carries its OWN
    # directive in its command_template (e.g. echo 'location ~ /\. { deny all; }'
    # >> {cfg}). Applying that content directly -- into the file+context where it
    # takes effect (a scoped `location` inside its `server {`; else the setting's
    # section) -- is more reliable than re-deriving it through the LLM, which is
    # non-deterministic and was silently no-opping mined block operators. Runs
    # BEFORE the model loop; on success returns immediately. General: content is
    # the miner's, file/context found from the live daemon's own config graph.
    _directive = _directive_from_template(mined_template)
    if _directive and candidate_files:
        scoped = re.match(r"(location|<Directory|<Location|<Files)", _directive, re.I)
        fl = " ".join(shlex.quote(f) for f in list(candidate_files)[:60])
        tgt = ""
        needle = (r"^[[:space:]]*(server[[:space:]]*\{|<VirtualHost|<Directory)"
                  if scoped else
                  r"^[[:space:]]*\[[A-Za-z0-9_.-]+\][[:space:]]*$")
        try:
            gr = await sb.exec(_shell_exec_argv(
                os_name, f"grep -lE -- {shlex.quote(needle)} {fl} 2>/dev/null | head -1"),
                timeout=bash_timeout)
            hits = (gr.stdout or "").strip().splitlines()
            if hits and hits[0] in candidate_files:
                tgt = hits[0]
        except Exception:
            tgt = ""
        # A scoped directive (nginx `location`, apache `<Directory>`) is INERT in
        # the wrong file, and worse, applying it to an unrelated /etc file (e.g.
        # nsswitch.conf) is a silent no-op remediation. If no candidate file holds
        # the container, search the daemon's OWN config tree live (via its config
        # dir), and NEVER fall back to an arbitrary file.
        if not tgt and scoped:
            try:
                dirs = "/etc/nginx /etc/apache2 /etc/httpd /etc/lighttpd"
                gr = await sb.exec(_shell_exec_argv(
                    os_name, f"grep -rlE -- {shlex.quote(needle)} {dirs} 2>/dev/null | head -1"),
                    timeout=bash_timeout)
                h = (gr.stdout or "").strip().splitlines()
                if h and h[0].startswith("/"):
                    tgt = h[0]
            except Exception:
                pass
        if not tgt and not scoped:
            # a plain setting can land in any single-file candidate that exists
            tgt = next(iter(candidate_files), "")
        # scoped with no container file found -> do NOT guess; fall through to
        # the LLM value-grounding rather than corrupting a random file.
        if tgt:
            import base64 as _b64
            b64 = _b64.b64encode((_directive + "\n").encode()).decode()
            qt = shlex.quote(tgt)
            # Placement: a scoped block goes just inside `server {`; a plain INI
            # setting (samba `wide links = no`, exim `dc_local_interfaces=...`)
            # goes inside its section ([global]) with the stale key commented,
            # NOT appended at EOF (inert / last-value-wins). The directive's key
            # is the text before '=' (or the whole line for a bare directive).
            anch = "server {" if scoped else "[global]"
            comment_old = ""
            if not scoped:
                _dk = _directive.split("=", 1)[0].strip() if "=" in _directive else _directive.strip()
                _pat = _directive_grep_pattern(_dk)
                comment_old = (f"sed -i -E 's|^([[:space:]]*{_pat}[[:space:]].*)$|# \\1|I' "
                               f"{qt} 2>/dev/null; ")
            # derive the daemon to restart from listening-socket evidence
            svc = ""
            if ss_out:
                procs = set(re.findall(r'"([\w.-]+)"', ss_out))
                cand = [p for p in procs if _config_tokens(p) & (_config_tokens(tgt) or {"x"})]
                if len(set(cand)) == 1:
                    svc = re.sub(r"[^A-Za-z0-9_.-]", "", cand[0])[:40]
                elif procs:
                    svc = re.sub(r"[^A-Za-z0-9_.-]", "", sorted(procs)[0])[:40]
            qsv = shlex.quote(svc) if svc else ""
            reload_c = (
                f"; {{ service {qsv} restart 2>/dev/null || systemctl restart {qsv} 2>/dev/null "
                f"|| {{ p=$(pgrep -x {qsv}|head -1); [ -n \"$p\" ] && kill -HUP \"$p\"; }}; "
                f"sleep 1; pgrep -x {qsv} >/dev/null || service {qsv} start 2>/dev/null "
                f"|| /usr/sbin/{qsv} 2>/dev/null; }}") if svc else ""
            apply = (
                f"cp {qt} {qt}.neuroplan.bak 2>/dev/null; "
                f"{comment_old}"
                f"printf '%s' {shlex.quote(b64)} | base64 -d > /tmp/.np.md; "
                f"if grep -qzF -- \"$(cat /tmp/.np.md)\" {qt} 2>/dev/null; then :; else "
                # index() = LITERAL substring match, so a section header like
                # [global] (a regex char-class) or `server {` matches verbatim;
                # insert the block right after the first anchor line, else EOF.
                f"ANCH={shlex.quote(anch)} awk 'BEGIN{{while((getline l<\"/tmp/.np.md\")>0)b=b l \"\\n\"}} "
                "{ print } "
                "!d && ENVIRON[\"ANCH\"]!=\"\" && index($0, ENVIRON[\"ANCH\"])>0 { printf \"%s\", b; d=1 } "
                "END{ if(!d) printf \"%s\", b }' "
                f"{qt} > /tmp/.np.mnew && cat /tmp/.np.mnew > {qt}; fi")
            try:
                await sb.exec(_shell_exec_argv(os_name, apply), timeout=bash_timeout)
                # native validator (best-effort): nginx -t / apachectl -t via the daemon
                if svc:
                    await sb.exec(_shell_exec_argv(os_name, "true" + reload_c), timeout=bash_timeout)
                meta.update({"mined_directive_applied": _directive[:120],
                             "edit_path": tgt, "reload_service": svc,
                             "deterministic_mined_path": True})
                return apply + reload_c, meta
            except Exception:
                pass  # fall through to LLM value-grounding

    for attempt in range(3):
        prompt = _VALUE_GROUND_PROMPT.format(
            app_versions=(app_versions or "(none detected)")[:1200],
            vuln_brief=(vuln_brief or "")[:600], path=path, key=key,
            symbolic_value=symbolic_value, current=current or "(empty/unreadable)",
            effective=effective)
        if last_err:
            prompt += (f"\n\nA previous attempt failed the validator with:\n"
                       f"{last_err[:400]}\nReturn a corrected JSON line.")
        try:
            resp = await model.generate(
                input=[ChatMessageUser(content=prompt)],
                config=GenerateConfig(temperature=0.0, max_tokens=2048))
        except Exception as e:
            meta["value_grounding_error"] = str(e)[:150]
            return None, meta
        obj = _extract_first_json(resp.completion or "")
        if not obj or not (obj.get("line") or obj.get("block")):
            continue
        line = str(obj.get("line") or "").strip()
        validate = str(obj.get("validate", "")).strip()
        # Retarget to the effective file only if the model named one the probe
        # verified as active (evidence-gated: never trust a bare string).
        target = str(obj.get("target_path", "")).strip()
        edit_path = target if target in candidate_files else path
        if not edit_path:
            # no default path and the probe named none the model trusts: skip
            continue
        qpe = shlex.quote(edit_path)
        # Daemon to restart so a live-socket/live-HTTP oracle sees the change.
        # Evidence-gated to a running/known daemon. A full restart (not just HUP)
        # is used because many directives (bind address, samba wide-links, squid
        # ACLs) are only re-read on restart; we then ensure the daemon is back up
        # so the availability oracle still passes. An optional model-supplied
        # `prep` command (e.g. update-exim4.conf) regenerates derived config
        # before the restart. All evidence-gated; no app names in code.
        svc = re.sub(r"[^A-Za-z0-9_.-]", "", str(obj.get("service", "")).strip())[:40]
        # Deterministic fallback: if the model named no service, derive the
        # owning daemon from the listening-socket introspection by token overlap
        # with the edited path/key (e.g. /etc/mysql/... intersects mysqld via
        # token 'mysql'). Unique match only; else leave empty.
        if not svc and ss_out:
            procs = set(re.findall(r'"([\w.-]+)"', ss_out)) | \
                set(re.findall(r'/(\w[\w.-]+)\s*$', ss_out, re.M))
            want = _config_tokens(str(edit_path)) | _config_tokens(str(key))
            cand = [p for p in procs if _config_tokens(p) & want]
            if len(set(cand)) == 1:
                svc = re.sub(r"[^A-Za-z0-9_.-]", "", cand[0])[:40]
        prep = str(obj.get("prep", "")).strip()
        prep_cmd = (prep + "; ") if (prep and _looks_safe_validator(prep)) else ""
        reload_suffix = ""
        if svc:
            qsv = shlex.quote(svc)
            reload_suffix = (
                f"; {prep_cmd}"
                f"service {qsv} restart 2>/dev/null || systemctl restart {qsv} 2>/dev/null "
                f"|| {{ pid=$(pgrep -x {qsv} | head -1); [ -n \"$pid\" ] && kill -HUP \"$pid\" 2>/dev/null; }}; "
                f"sleep 1; pgrep -x {qsv} >/dev/null 2>&1 || service {qsv} start 2>/dev/null "
                f"|| /usr/sbin/{qsv} 2>/dev/null || /usr/sbin/{qsv} -D 2>/dev/null")
        meta["value_line"] = line
        meta["validator_cmd"] = validate
        meta["reload_service"] = svc
        meta["validator_attempts"] = attempt + 1
        meta["edit_path"] = edit_path

        blk = obj.get("block")
        if isinstance(blk, list) and any(str(l).strip() for l in blk):
            # Multi-line block / ordered-ACL insertion. Payload carried via
            # base64 (no quoting hazards); idempotent (grep -qzF skips if already
            # present); anchor via awk ENVIRON, inserting before/after the FIRST
            # match, else appending at EOF (validator gate + rollback bound it).
            import base64 as _b64
            payload = "\n".join(str(l).rstrip() for l in blk[:60])
            anchor = str(obj.get("insert_before") or obj.get("insert_in_section") or "").strip()[:160]
            mode = ("before" if obj.get("insert_before")
                    else "after" if obj.get("insert_in_section") else "append")
            # A scoped/context directive is inert unless it lands inside its
            # container: an nginx `location` must live in the file whose
            # `server {` it belongs to (often an included site file, NOT the
            # top-level nginx.conf); an apache `<Directory>`/`<Location>` inside
            # a vhost. The model's target_path is a guess; deterministically
            # RETARGET edit_path to the candidate file that actually contains the
            # block's anchor (or, for a recognizably-scoped block with no useful
            # anchor, a server/vhost container), so a correct plan is not wasted
            # on the wrong file. Evidence-gated to candidate_files; a single-file
            # config (e.g. squid.conf) simply finds no better target and stays.
            first_ln = next((str(l).strip() for l in blk if str(l).strip()), "")
            scoped = re.match(r"(location|<Directory|<Location|<Files)", first_ln, re.I)
            if candidate_files:
                fl = " ".join(shlex.quote(f) for f in list(candidate_files)[:60])
                # (grep_expr, is_regex): the model's literal anchor first, then
                # UNCOMMENTED container openers (a line-anchored ERE so a
                # commented `#\tserver {` example does not win over the real one).
                needles = [(anchor, False)] if anchor else []
                if scoped:
                    needles.append((r"^[[:space:]]*(server[[:space:]]*\{|<VirtualHost|<Directory)", True))
                for needle, is_re in needles:
                    flag = "-lE" if is_re else "-lF"
                    try:
                        gr = await sb.exec(_shell_exec_argv(
                            os_name, f"grep {flag} -- {shlex.quote(needle)} {fl} 2>/dev/null | head -1"),
                            timeout=bash_timeout)
                        hit = (gr.stdout or "").strip().splitlines()
                    except Exception:
                        hit = []
                    if hit and hit[0] in candidate_files:
                        edit_path = hit[0]; qpe = shlex.quote(edit_path)
                        meta["retargeted_to"] = edit_path
                        # Scoped block with no useful anchor: place it just inside
                        # the container opener (after `server {`) rather than EOF.
                        if scoped and mode == "append":
                            anchor, mode = "server {", "after"
                        break
            b64 = _b64.b64encode(payload.encode()).decode()
            qanch = shlex.quote(anchor)
            meta["value_block"] = [str(l) for l in blk[:8]]
            meta["insert_mode"] = mode
            apply_cmd = (
                f"cp {qpe} {qpe}.neuroplan.bak 2>/dev/null; "
                f"printf '%s' {shlex.quote(b64)} | base64 -d > /tmp/.np.block; "
                f"if grep -qzF -- \"$(cat /tmp/.np.block)\" {qpe} 2>/dev/null; then :; else "
                f"ANCH={qanch} MODE={mode} awk '"
                "BEGIN{ while ((getline l < \"/tmp/.np.block\") > 0) b = b l \"\\n\" } "
                "!d && ENVIRON[\"MODE\"]==\"before\" && ENVIRON[\"ANCH\"]!=\"\" && $0 ~ ENVIRON[\"ANCH\"] { printf \"%s\", b; d=1 } "
                "{ print } "
                "!d && ENVIRON[\"MODE\"]==\"after\" && ENVIRON[\"ANCH\"]!=\"\" && $0 ~ ENVIRON[\"ANCH\"] { printf \"%s\", b; d=1 } "
                "END { if (!d) printf \"%s\", b }' "
                f"{qpe} > /tmp/.np.new && cat /tmp/.np.new > {qpe}; fi"
            )
        else:
            ql = line.replace("'", "'\\''")
            pat = _directive_grep_pattern(key)
            # Comment the old occurrence, then place the new line. A plain EOF
            # append is WRONG for INI/section files: a global directive (samba
            # `wide links`, appended after the last share section) is inert
            # unless it sits in its section. If the file is section-structured
            # ([global]/[PHP]/...), insert just after the target section header
            # (model's `insert_in_section`, else `[global]`, else EOF); a file
            # with NO sections keeps the EOF append. Same "land it in the right
            # context" principle as the block path; general, no app names. Line
            # carried via base64 + ENVIRON to avoid any nested-quote hazard.
            import base64 as _b64
            b64line = _b64.b64encode(line.encode()).decode()
            sect = str(obj.get("insert_in_section") or "").strip() or "[global]"
            qsect = shlex.quote(sect)
            apply_cmd = (
                f"cp {qpe} {qpe}.neuroplan.bak 2>/dev/null; "
                f"sed -i -E 's|^([[:space:]]*{pat}[[:space:]].*)$|# \\1|I' {qpe} 2>/dev/null; "
                f"printf '%s' {shlex.quote(b64line)} | base64 -d > /tmp/.np.line; "
                f"if grep -qE '^[[:space:]]*\\[[A-Za-z0-9_.-]+\\][[:space:]]*$' {qpe} 2>/dev/null; then "
                f"SECT={qsect} awk 'BEGIN{{ getline L < \"/tmp/.np.line\"; done=0 }} "
                "{ print; t=$0; sub(/^[[:space:]]+/,\"\",t); sub(/[[:space:]]+$/,\"\",t); "
                "if(!done && t==ENVIRON[\"SECT\"]){ print L; done=1 } } "
                "END{ if(!done) print L }' "
                f"{qpe} > /tmp/.np.ini && cat /tmp/.np.ini > {qpe}; "
                f"else printf '%s\\n' '{ql}' >> {qpe}; fi"
            )
        try:
            await sb.exec(_shell_exec_argv(os_name, apply_cmd), timeout=bash_timeout)
        except Exception:
            return None, meta

        async def _reload_and_return():
            # Reload the owning daemon AFTER the edit is accepted, so a live
            # oracle sees the change; harmless HUP of a validator-blessed config.
            if reload_suffix:
                try:
                    await sb.exec(_shell_exec_argv(os_name, "true" + reload_suffix),
                                  timeout=bash_timeout)
                except Exception:
                    pass
            return apply_cmd + reload_suffix

        if validate and _looks_safe_validator(validate):
            try:
                vr = await sb.exec(_shell_exec_argv(os_name, validate), timeout=bash_timeout)
            except Exception:
                vr = None
            if vr is not None and vr.returncode == 0:
                meta["validator_passed"] = True
                return await _reload_and_return(), meta
            last_err = (getattr(vr, "stderr", "") or getattr(vr, "stdout", "") or "")[:400]
            meta["validator_passed"] = False
            # roll back the edited file before retrying
            await sb.exec(_shell_exec_argv(os_name, f"cp {qpe}.neuroplan.bak {qpe} 2>/dev/null"),
                          timeout=bash_timeout)
            continue
        # No usable validator: keep the grounded edit but flag it unverified.
        meta["validator_passed"] = None
        return await _reload_and_return(), meta
    return None, meta


# ---------------------------------------------------------------------------
# Fast Downward runner (blocking, run in executor)
# ---------------------------------------------------------------------------

def _block_symbols(domain_pddl: str, opener: str) -> set[str]:
    """Leading symbols of every form inside a top-level domain block.

    Balanced-paren scan so a block written on one line, or closed on its last
    entry, is still found. A regex with a newline lookahead missed both.
    """
    i = domain_pddl.find(opener)
    if i < 0:
        return set()
    depth = 0
    for j in range(i, len(domain_pddl)):
        if domain_pddl[j] == "(":
            depth += 1
        elif domain_pddl[j] == ")":
            depth -= 1
            if depth == 0:
                block = domain_pddl[i:j + 1]
                break
    else:
        return set()
    names = {m.group(1) for m in re.finditer(r"\(([A-Za-z_][\w-]*)", block)}
    names.discard(opener.lstrip("(:"))
    return names


def _declared_domain_types(domain_pddl: str) -> set[str]:
    """Type names declared in the domain's (:types ...) block.

    Parsed here rather than with `_extract_types`, which harvests bare words
    and so also returns comment text: on the refined domain it reports 721
    "types" including `Base`, `types` and `Filesystem`, which are words from
    the section headers. That is harmless for a prompt summary and useless as
    a validation gate, because it accepts almost anything.
    """
    m = re.search(r"\(:types\b(.*?)\n\s*\)", domain_pddl, re.S)
    if not m:
        return set()
    body = re.sub(r";[^\n]*", " ", m.group(1))          # strip line comments
    body = body.replace("-", " - ")
    names = {tok for tok in re.findall(r"[A-Za-z_][\w-]*", body)}
    names.discard("either")
    names.add("object")
    return {n.lower() for n in names}


def _undeclared_problem_types(domain_pddl: str, problem_pddl: str) -> list[str]:
    """Type names the problem's :objects block uses that the domain lacks.

    The third face of the same failure. Fast Downward does not reject an
    undeclared type at parse time; it crashes during grounding with
    `KeyError` in `pddl_to_prolog.translate_typed_object` and exits 30, which
    the solver reported as PLANNER_FOUND_NO_PLAN like everything else.

    Measured on ccdc/scenario-01: given the FULL predicate vocabulary the model
    wrote a problem whose predicates were all real, then declared
    `yes no - value`. No type `value` exists in the domain, and the translator
    died at "Generating Datalog program".
    """
    declared = _declared_domain_types(domain_pddl)
    if not declared:
        return []
    om = re.search(r"\(:objects\b(.*?)\)\s*(?=\(:init)", problem_pddl, re.S)
    if not om:
        return []
    body = re.sub(r";[^\n]*", " ", om.group(1))
    used = re.findall(r"-\s*([A-Za-z_][\w-]*)", body)
    missing: list[str] = []
    for t in used:
        if t.lower() in declared or t.lower() in {x.lower() for x in missing}:
            continue
        missing.append(t)
    return missing


def _undeclared_problem_predicates(domain_pddl: str, problem_pddl: str) -> list[str]:
    """Predicate names the problem uses that the domain never declares.

    The sibling of _declare_missing_objects, for the other half of the same
    Fast Downward abort. FD exits 31 on "Undefined predicate" exactly as it
    does on "Undefined object", and `assert_valid_problem` passes both: it
    parses the problem, it does not check it against the domain's vocabulary.

    An undeclared OBJECT is repaired deterministically below, because the
    intended object is obvious from the atom that names it. An undeclared
    PREDICATE cannot be repaired that way: inventing a declaration would let
    the problem assert a fact no operator can ever read, and a goal on such a
    fact is unreachable, so the run would still fail, just later and more
    quietly. The caller instead reports the names back to the model and asks
    for the problem again in the domain's own vocabulary.

    Measured case: ccdc/scenario-01's generated problem opened its :init with
    `(config_file sshd_config)`. No such predicate exists in the refined
    domain. The problem validated, FD refused it, and the scenario was scored
    as a planning failure.
    """
    # Balanced-paren extraction, not a regex with a newline lookahead. The
    # regex form missed a block written compactly or closed on its last
    # predicate line, and then the empty-set early return below turned that
    # miss into a silent pass: exactly the malformed domains most worth
    # catching were the ones waved through.
    declared = {n.lower() for n in _block_symbols(domain_pddl, "(:predicates")}
    if not declared:
        return []
    # Functions are NOT folded into the predicate set. Doing so let a problem
    # use a function symbol as a predicate without being flagged.
    functions = {n.lower() for n in _block_symbols(domain_pddl, "(:functions")}

    structural = {"and", "or", "not", "when", "forall", "exists", "imply",
                  "init", "goal", "objects", "="}
    idx = problem_pddl.find("(:init")
    body = problem_pddl[idx:] if idx >= 0 else ""
    missing: list[str] = []
    for atom in re.finditer(r"\(([A-Za-z_][\w-]*)", body):
        name = atom.group(1)
        low = name.lower()
        if (low in structural or low in declared or low in functions
                or low in {m.lower() for m in missing}):
            continue
        missing.append(name)
    return missing


def _declare_missing_objects(problem_pddl: str, domain_pddl: str) -> str:
    """Declare in :objects any symbol used in :init/:goal but not declared.

    Fast Downward's translator ABORTS with exit 31 ("Undefined object") when a
    problem references an object it never declares (a frequent LLM omission: the
    service symbol in `(service_running nginx)` left out of :objects). The parser
    validator is more lenient and passes it, so the failure surfaces only as a
    spurious NO_PLAN. This deterministically repairs the omission before FD:
    infer each missing object's type from the predicate signature in the domain,
    else `object`. General; no scenario/app specifics."""
    pm = re.search(r"\(:predicates(.*?)\n\s*\)\s*\n", domain_pddl, re.S)
    ptypes: dict[str, list[str]] = {}
    if pm:
        for m in re.finditer(r"\(([A-Za-z_][\w-]*)((?:\s+\?[\w-]+\s*-\s*[\w-]+)*)\s*\)",
                             pm.group(1)):
            ptypes[m.group(1)] = re.findall(r"\?[\w-]+\s*-\s*([\w-]+)", m.group(2))
    om = re.search(r"\(:objects(.*?)\)\s*(?=\(:init)", problem_pddl, re.S)
    declared = {d for d in re.findall(r"([A-Za-z_][\w-]*)", om.group(1))} if om else set()
    idx = problem_pddl.find("(:init")
    body = problem_pddl[idx:] if idx >= 0 else ""
    used: dict[str, str] = {}
    for atom in re.finditer(r"\(([A-Za-z_][\w-]*)((?:\s+[\w./-]+)*)\)", body):
        pred, args = atom.group(1), atom.group(2).split()
        if pred in ("and", "not", "init", "goal", "oneof", "when"):
            continue
        tys = ptypes.get(pred, [])
        for i, a in enumerate(args):
            if re.match(r"^[A-Za-z_][\w-]*$", a):
                used.setdefault(a, tys[i] if i < len(tys) else "object")
    missing = {o: t for o, t in used.items() if o not in declared}
    if not missing:
        return problem_pddl
    decl = " ".join(f"{o} - {t}" for o, t in missing.items())
    if om:
        repl = f"(:objects{om.group(1).rstrip()}\n    {decl})"
        return problem_pddl.replace(om.group(0), repl + "\n  ", 1)
    # no :objects block at all -> insert one before :init
    return problem_pddl[:idx] + f"(:objects\n    {decl})\n  " + problem_pddl[idx:]


async def _run_fast_downward(
    domain_pddl: str, problem_pddl: str, fd_path: str, timeout: int,
    diag: dict | None = None,
) -> list[dict]:
    """Plan with Fast Downward. Optionally fill `diag` with why it did not.

    WHY `diag` EXISTS. The subprocess result used to be discarded, so every
    non-plan outcome collapsed into one bucket: a translator abort on a
    malformed domain (exit 31), a proof that the problem is unsolvable (12),
    and a search that exhausted its time (23) all produced an empty plan and
    then `PLANNER_FOUND_NO_PLAN`. Those mean opposite things. "The domain
    never parsed" is a defect in this pipeline; "no plan exists" is a claim
    about the benchmark. Choosing between them per scenario is the whole
    point of the failure triage, and it was not recoverable from the logs.

    This RECORDS ONLY. The returned plan, the completion string, and every
    scored value are unchanged; the diagnosis is read back from sample
    metadata after the run.
    """
    import asyncio

    _diag = diag if diag is not None else {}

    def _fd_sync() -> list[dict]:
        with tempfile.TemporaryDirectory(prefix="neurosym_fd_") as tmpdir:
            d = Path(tmpdir) / "domain.pddl"
            p = Path(tmpdir) / "problem.pddl"
            d.write_text(domain_pddl)
            p.write_text(problem_pddl)
            try:
                res = subprocess.run(
                    ["python3", fd_path,
                     "--overall-time-limit", str(timeout),
                     str(d), str(p),
                     "--search", "eager_greedy([ff()])"],
                    capture_output=True, text=True,
                    timeout=timeout + 30, cwd=tmpdir,
                )
            except subprocess.TimeoutExpired:
                _diag.update(returncode=None, timed_out=True, stderr="")
                return []
            # Fast Downward reports translator errors on STDOUT, not stderr, so
            # capturing stderr alone yields an empty string on exactly the
            # failure this diagnostic exists to explain.
            _diag.update(returncode=res.returncode, timed_out=False,
                         stderr=(res.stderr or "")[-1500:],
                         stdout_tail=(res.stdout or "")[-2500:])
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


async def _mine_operators_async(threat_text, sb, os_name, bash_timeout, llm,
                                vocabulary):
    """Async wrapper around the operator miner: intent extraction (LLM) ->
    tool-confirm + doc harvest (sb.exec) -> operator extraction (LLM) -> lint.
    Mirrors operator_miner.mine_operators but uses the async sandbox."""
    import asyncio
    from phase1.mining import operator_miner as _om

    async def _sh(cmd):
        try:
            r = await sb.exec(_shell_exec_argv(os_name, cmd), timeout=bash_timeout)
            return (r.returncode, r.stdout or "")
        except Exception:
            return (1, "")

    def _call_llm(system, user):
        return llm.json(system, user)

    # 1. intents (LLM, off-thread so we don't block the loop)
    loop = asyncio.get_event_loop()
    intents = await loop.run_in_executor(
        None, _om.extract_intents, threat_text, llm)
    vocab = list(vocabulary or [])
    actions, predicates, rejected, seen = [], [], [], set()
    for it in intents:
        # 2. confirm tools via async shell
        cands = list(dict.fromkeys(
            [t for t in it.tool_candidates if t] + _om.REMEDIATION_ONTOLOGY[it.verb]))
        present = []
        for tool in cands:
            base = tool.split()[0]
            rc, out = await _sh(f"command -v {base} >/dev/null 2>&1 && echo yes")
            if "yes" in out:
                present.append(base)
        if not present:
            continue
        # doc harvest
        _, man = await _sh(f"man {present[0]} 2>/dev/null | col -bx 2>/dev/null | head -80")
        if len((man or "").strip()) < 40:
            _, man = await _sh(f"{present[0]} --help 2>&1 | head -40")
        # 3. operator extraction (LLM off-thread), RETRY-UNTIL-VALID. A single
        # temp>0 attempt intermittently emits an operator the soundness lint
        # rejects (e.g. missing delete-effect, free var), which silently drops
        # the scenario's remediation operator and makes the failure point move
        # run-to-run. Retry a few times and keep the first lint-passing operator;
        # this is the determinism half that lets the execution-grounding fixes
        # actually take effect (the miner is the upstream reliability bottleneck).
        op = None
        ok = False
        reason = "extraction-empty"
        for _try in range(3):
            cand = await loop.run_in_executor(
                None, _om.mine_operator, it, (man or "")[:2000], vocab, llm)
            if not cand:
                reason = "extraction-empty"
                continue
            _ok, _reason = _om.lint_operator(cand)
            if _ok:
                op, ok, reason = cand, True, "ok"
                break
            op, reason = cand, _reason  # keep last for the reject record
        if not op:
            rejected.append((it.verb, "extraction-empty"))
            continue
        if not ok:
            rejected.append((op.get("name", it.verb), reason))
            continue
        if op["name"] in seen:
            continue
        seen.add(op["name"])
        actions.append(op)
        for pe in (op.get("preconditions", []) + op.get("effects", [])):
            nm = _om._pred_name(pe)
            if nm and nm != "not" and nm not in {_om._pred_name(v) for v in vocab}:
                ptypes = {p["name"]: p["type"] for p in op["parameters"]}
                m = re.match(r"\(\s*(?:not\s*\()?\s*[A-Za-z_][\w-]*\s+\?(\w+)", pe)
                pv = m.group(1) if m else None
                decl = f"({nm} ?{pv or 'x'} - {ptypes.get(pv, 'object') if pv else 'object'})"
                predicates.append(decl)
                vocab.append(decl)
    return {"actions": actions, "predicates": predicates, "rejected": rejected}


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
        if domain_path:
            if not Path(domain_path).exists():
                raise RuntimeError(
                    f"domain_path={domain_path!r} was supplied but does not "
                    f"exist. Refusing to score this scenario as a planning "
                    f"failure: see the note below.")
            domain_pddl = Path(domain_path).read_text()
            try:
                # (assert_valid_domain imported at module top)
                dval = assert_valid_domain(domain_pddl, source="solver.domain")
                if not dval.ok:
                    # A DOMAIN THE CALLER SUPPLIED AND WE CANNOT PARSE IS A
                    # CONFIGURATION ERROR, NOT A RESULT.
                    #
                    # This used to set domain_pddl = "" and carry on. The run
                    # then completed, terminated as NO_DOMAIN_PROVIDED, and was
                    # handed to the same oracle as every other sample, so it
                    # came out as a scored zero. A whole suite could be run
                    # against an unparseable domain and produce a clean-looking
                    # table of failures that said nothing about the planner.
                    # That happened: the FD cleaner's `?_pad_0` output made the
                    # global refined domain unparseable, and ccdc/scenario-01
                    # scored 0.00/0.00/0.00 for that reason alone.
                    #
                    # Erroring the sample keeps it OUT of the denominator,
                    # which is where a configuration error belongs.
                    state.metadata["domain_invalid"] = dval.detail or dval.error
                    raise RuntimeError(
                        f"supplied domain {domain_path!r} does not parse: "
                        f"{(dval.detail or dval.error or '')[:200]}")
            except RuntimeError:
                raise
            except Exception as e:
                state.metadata["domain_validation_error"] = str(e)[:200]

        # ── Make the domain deliver what the problem-generation prompt promises ──
        #
        # `_PROBLEM_GEN_SYSTEM` teaches the model `config_file`, `setting`,
        # `setting_value_is`, `edit_config_setting` and `config_applied` by
        # worked example. The model is not inventing those names, it is
        # following instructions. Whether they resolve depends entirely on
        # which domain is loaded:
        #
        #   pddl_output/phase3/sysadmin_refined*.pddl   built 2026-04-23
        #   common/canonical_actions.py config family   added 2026-05-21
        #
        # so the default global domain predates the operator family the prompt
        # is built around, declares none of those names, and Fast Downward
        # refuses every problem written to the prompt's recipe with exit 31.
        # The per-scenario domains have the family merged in and plan the same
        # problem in milliseconds, which is why this was never seen on vulnhub.
        #
        # Measured on ccdc/scenario-01 with one problem text:
        #   global domain                     FD exit 31, undefined predicate
        #   pddl_ccdc_validate/ccdc-01        FD exit 0, 2-step plan
        #   global domain + canonical merge   FD exit 0, the SAME 2-step plan
        #
        # The merge is idempotent, so a domain that already carries the family
        # is unchanged. This is a repair to the domain, not to the prompt,
        # because the canonical operators are part of NeuroPlan's declared
        # action set either way.
        if domain_pddl and os.environ.get("NEUROPLAN_DISABLE_CANONICAL") != "1":
            try:
                import tempfile as _tf
                from common.canonical_actions import merge_canonical_into_domain
                _cpath = Path(_tf.mkdtemp(prefix="neurosym_canon_")) / "sysadmin.pddl"
                _cpath.write_text(domain_pddl)
                _rep = merge_canonical_into_domain(str(_cpath))
                _merged = _cpath.read_text()
                _cv = assert_valid_domain(_merged, source="solver.canonical")
                if _cv.ok:
                    domain_pddl = _merged
                    state.metadata["canonical_merge"] = {
                        "types_added": _rep.get("types_added", []),
                        "predicates_added": len(_rep.get("predicates_added", []) or []),
                        "actions_added": len(_rep.get("actions_added", []) or []),
                    }
                else:
                    state.metadata["canonical_merge_invalid"] = (
                        _cv.detail or _cv.error or "")[:150]
            except Exception as e:  # noqa: BLE001
                state.metadata["canonical_merge_error"] = str(e)[:200]

        # Per-scenario config-path map from the Phase 1 introspection beside
        # the domain: lets the concretizer ground nested service configs
        # (e.g. /etc/apache2/mods-enabled/ssl.conf) the static alias map does
        # not enumerate, including invented identifiers via token matching.
        scenario_config_map = _load_scenario_config_map(domain_path)
        state.metadata["scenario_config_files"] = len(scenario_config_map)

        # ── Phase 1: Introspect ──
        sb = sandbox()
        osq_ok, osq_detail = await _ensure_osquery(sb, os_name, bash_timeout)
        state.metadata["osquery_available"] = osq_ok
        state.metadata["osquery_detail"] = osq_detail
        sys_state: dict[str, str] = {}
        if osq_ok:
            for key, q in _OSQUERY_QUERIES.items():
                try:
                    r = await sb.exec(
                        _shell_exec_argv(os_name, f'/usr/bin/osqueryi --json {shlex.quote(q)}'),
                        timeout=bash_timeout)
                    sys_state[key] = (r.stdout or "").strip() if r.returncode == 0 else ""
                except TimeoutError:
                    sys_state[key] = ""
        for key, cmd in _INTROSPECT_CMDS.items():
            try:
                r = await sb.exec(_shell_exec_argv(os_name, cmd), timeout=bash_timeout)
                sys_state[key] = (r.stdout or "").strip() if r.returncode == 0 else ""
            except TimeoutError:
                sys_state[key] = ""
        state_block = "\n".join(f"[{k}]\n{v}" for k, v in sys_state.items() if v)

        # Ground file-permission operator targets against a SEPARATE map built
        # from the security audit (SUID binaries, world-writable dirs, sensitive
        # logs) plus paths named in the threat report — kept distinct from the
        # config-file map so a permission op never resolves to a same-named
        # config file (e.g. remove_suid_bit exim4 must hit /usr/sbin/exim4, not
        # /etc/exim4/...conf). Keyed by full path, basename, and normalized forms.
        scenario_file_map: dict[str, str] = {}
        audit_paths = re.findall(r"/[\w.@/+-]+",
                                 (sys_state.get("perm_audit", "") or "") + "\n" +
                                 (state.input_text or ""))
        for pth in audit_paths:
            if pth.count("/") >= 1 and not pth.endswith("/") and len(pth) > 3:
                for key in (pth, pth.rsplit("/", 1)[-1]):
                    scenario_file_map[key] = pth
                    scenario_file_map[_normalize_setting_key(key)] = pth
        state.metadata["scenario_audit_paths"] = len(scenario_file_map)

        # ── Phase 1.5: Mine remediation operators ──
        # Discover the PDDL remediation operators this scenario needs from its
        # own threat report + live container tool availability + man pages, and
        # merge them into a per-scenario domain copy so Fast Downward can plan
        # them. Suite-agnostic; the hand-authored canonical operators are the
        # verified cache/seed. Env-gated (NEUROPLAN_DISABLE_MINER=1 to skip).
        if domain_pddl and os.environ.get("NEUROPLAN_DISABLE_MINER") != "1":
            try:
                from phase1.mining.operator_miner import mine_operators, _LLM
                from common.canonical_actions import (
                    merge_actions_into_domain, canonical_predicates)
                _ls = None
                try:
                    from common.config_loader import llm_settings as _lset
                    _ls = _lset()
                except Exception:
                    pass
                _model = getattr(_ls, "model", None) or os.environ.get(
                    "SYSREPAIR_LLM_MODEL", "MiniMax-M2.7")
                _base = getattr(_ls, "base_url", None) or os.environ.get(
                    "SYSREPAIR_LLM_BASE_URL", "https://api.minimax.io/v1")
                _key = (getattr(_ls, "api_key", None) or os.environ.get("MINIMAX_API_KEY")
                        or os.environ.get("OPENAI_API_KEY") or "vllm")

                # sb.exec is async and we're inside async solve(); mine via an
                # async-capable adapter that runs the miner's tool-confirm/doc
                # probes through sb.exec and its two LLM passes off-thread.
                mined = await _mine_operators_async(
                    state.input_text or "", sb, os_name, bash_timeout,
                    _LLM(_model, _base, _key), canonical_predicates())
                if mined.get("actions"):
                    import tempfile as _tf
                    _dcopy = Path(_tf.mkdtemp(prefix="neurosym_dom_")) / "sysadmin_mined.pddl"
                    _dcopy.write_text(domain_pddl)
                    rep = merge_actions_into_domain(
                        str(_dcopy), mined["actions"], mined["predicates"])
                    _new = _dcopy.read_text()
                    # Run the merged domain through the FD cleaner (forward-declare
                    # predicates + fix undefined vars), so a mined operator can't
                    # abort FD's translator -> spurious NO_PLAN.
                    try:
                        from phase3.planner_wrapper import RandomWalkGenerator as _RWG
                        try:
                            from phase3.planner_wrapper import PlannerConfig as _PC
                            _cleaned = _RWG(_PC())._validate_pddl_for_fd(_new)
                        except Exception:
                            _cleaned = _RWG()._validate_pddl_for_fd(_new)
                        if _cleaned and "(:action" in _cleaned:
                            _new = _cleaned
                    except Exception:
                        pass
                    dv = assert_valid_domain(_new, source="solver.mined")
                    if dv.ok:
                        domain_pddl = _new
                        if os.environ.get("NEUROPLAN_DUMP_MERGED"):
                            try:
                                _dd = Path(os.environ["NEUROPLAN_DUMP_MERGED"])
                                _dd.mkdir(parents=True, exist_ok=True)
                                (_dd / "merged_domain.pddl").write_text(_new)
                            except Exception:
                                pass
                        state.metadata["mined_operators"] = [
                            a["name"] for a in mined["actions"]]
                        state.metadata["_mined_action_schemas"] = mined["actions"]
                        state.metadata["mined_merge"] = rep
                    else:
                        state.metadata["mined_domain_invalid"] = (dv.detail or dv.error or "")[:150]
                state.metadata["mined_rejected"] = mined.get("rejected", [])
            except Exception as e:  # never let mining break the base pipeline
                state.metadata["miner_error"] = str(e)[:200]

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
            # _extract_types harvests bare words, so on the refined domain it
            # returns 721 "types" that are mostly comment text (`Base`,
            # `types`, `Filesystem` are section headers). The domain declares
            # 16. Handing the model 705 non-types and then telling it to use
            # only declared identifiers is why it invents plausible ones: on
            # ccdc/scenario-01 it wrote `yes no - value` twice in a row, even
            # after being told `value` is not a type, because it could not find
            # the real one in the noise. Fast Downward does not reject an
            # undeclared type at parse time; it crashes during grounding.
            d_types = sorted(_declared_domain_types(domain_pddl)) or _extract_types(domain_pddl)
            d_pred_pairs = _extract_predicates(domain_pddl)  # [(name, full_signature), ...]
            d_actions_full = _extract_actions(domain_pddl)
            d_acts = sorted(d_actions_full.keys())
            _m = re.search(r"\(domain\s+([\w-]+)", domain_pddl)
            d_name = _m.group(1) if _m else "sysadmin"
            # Predicate signatures (not just names) — gives LLM the arity so
            # it doesn't emit (pred x y) when the domain expects (pred x).
            # HOW MUCH OF THE VOCABULARY THE MODEL IS ALLOWED TO SEE.
            #
            # The prompt says "USE ONLY these identifiers". The refined global
            # domain declares 1974 predicates, so a cap of 300 shows the model
            # about 15% of them and then holds it to the whole set. It fills
            # the gaps with plausible inventions: on ccdc/scenario-01 it wrote
            # `(config_file ...)` and `(setting_value_is ...)`, neither
            # declared, while correctly using `config_applied`, which is. Fast
            # Downward then refuses the problem (exit 31) and the scenario is
            # scored as a planning failure.
            #
            # Configurable so the effect of the cap can be measured rather than
            # argued about. 0 means no cap.
            _cap = int(os.environ.get("NEUROPLAN_PROMPT_PRED_CAP", "300") or 0)
            _shown = d_pred_pairs if _cap <= 0 else d_pred_pairs[:_cap]
            pred_lines = [sig for _, sig in _shown]
            preds_str = "\n  ".join(pred_lines)
            if len(_shown) < len(d_pred_pairs):
                preds_str += f"\n  ...(+{len(d_pred_pairs)-len(_shown)} more)"
            state.metadata["prompt_predicates_shown"] = len(_shown)
            state.metadata["domain_predicates_total"] = len(d_pred_pairs)
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

            # If Phase 1.5 mined remediation operators for this scenario, direct
            # the problem generator to include a goal for EACH mined operator's
            # remediated-state effect (and its vulnerable precondition in :init).
            # This is derived mechanically from the mined schemas — the general
            # form of "goal = remediated state" — so no per-scenario authoring.
            mined_hint = ""
            _mined = state.metadata.get("mined_operators") or []
            if _mined:
                _digest = []
                _mined_actions = (state.metadata.get("_mined_action_schemas") or [])
                for _a in _mined_actions:
                    if _a["name"] in _mined:
                        _pos = [e for e in _a.get("effects", [])
                                if not e.strip().lower().startswith("(not")]
                        _digest.append(
                            f"  {_a['name']}: init-pattern {_a.get('preconditions')} "
                            f"-> goal-pattern {_pos}")
                if _digest:
                    mined_hint = (
                        "\n## Required remediation goals (this scenario needs EACH "
                        "of these operators; put its remediated-state predicate in "
                        "the GOAL and its vulnerable-state predicate in :init, with "
                        "the object named from the report/state):\n"
                        + "\n".join(_digest) + "\n")

            problem_prompt = (
                "## Domain vocabulary (USE ONLY these identifiers)\n"
                f"{domain_summary}\n\n"
                f"## Vulnerability Report\n{state.input_text[:3000]}\n\n"
                f"## Current System State\n{state_block[:3000]}\n"
                f"{mined_hint}\n"
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
                    # THE GRAMMAR CHECK IS NOT ENOUGH. `assert_valid_problem`
                    # parses; it does not check that the problem speaks the
                    # domain's vocabulary. A problem whose :init asserts a
                    # predicate the domain never declares parses cleanly, is
                    # recorded as pddl_problem_valid=True, and is then refused
                    # by Fast Downward's translator with exit 31, "Undefined
                    # predicate". Because any missing sas_plan was reported as
                    # PLANNER_FOUND_NO_PLAN, that landed in the logs as "the
                    # domain cannot express this repair" and scored Validate 1.
                    # Measured on ccdc/scenario-01: the model wrote
                    # `(config_file sshd_config)`, no such predicate exists,
                    # and the scenario scored a clean zero.
                    #
                    # The loop already feeds parse errors back to the model, so
                    # the vocabulary mismatch goes through the same channel,
                    # naming the offenders.
                    bad_preds = _undeclared_problem_predicates(
                        domain_pddl, problem_pddl)
                    bad_types = _undeclared_problem_types(
                        domain_pddl, problem_pddl)
                    if not bad_preds and not bad_types:
                        parser_error = ""
                        break
                    state.metadata["problem_undeclared_predicates"] = bad_preds
                    state.metadata["problem_undeclared_types"] = bad_types
                    parts = []
                    if bad_preds:
                        parts.append("predicates the domain does not declare: "
                                     + ", ".join(bad_preds))
                    if bad_types:
                        legal = sorted(_declared_domain_types(domain_pddl))
                        parts.append(
                            "types the domain does not declare: "
                            + ", ".join(bad_types)
                            + ". The ONLY declared types are: "
                            + ", ".join(legal)
                            + ". Use one of those, or drop the object")
                    parser_error = (
                        "Your problem used identifiers the planner cannot "
                        "resolve, so it refuses the problem. " + "; ".join(parts)
                        + ". Rewrite the problem using ONLY identifiers from "
                        "the domain vocabulary above. Do not invent names."
                    )
                    continue
                parser_error = (pval.detail or pval.error or "unknown parse error")[:600]

            state.metadata["pddl_problem"] = problem_pddl[:2000]
            state.metadata["pddl_problem_valid"] = (parser_error == "")
            if os.environ.get("NEUROPLAN_DUMP_MERGED") and problem_pddl:
                try:
                    _dd = Path(os.environ["NEUROPLAN_DUMP_MERGED"])
                    _dd.mkdir(parents=True, exist_ok=True)
                    (_dd / "gen_problem.pddl").write_text(problem_pddl)
                    (_dd / "parser_error.txt").write_text(parser_error or "OK")
                except Exception:
                    pass
            if parser_error:
                state.metadata["pddl_problem_error"] = parser_error

            # ── Phase 3: Plan ──
            # Only invoke the planner if the problem actually parsed; else
            # the failure mode is "PROBLEM_GENERATION_FAILED", not "no plan".
            if problem_pddl and not parser_error and Path(fd_path).exists():
                # Repair undeclared objects so FD's translator does not abort
                # (exit 31) and spuriously report NO_PLAN on a solvable problem.
                problem_pddl = _declare_missing_objects(problem_pddl, domain_pddl)
                state.metadata["pddl_problem"] = problem_pddl[:2000]
                fd_diag: dict = {}
                plan_actions = await _run_fast_downward(
                    domain_pddl, problem_pddl, fd_path, plan_timeout,
                    diag=fd_diag,
                )
                planner_ok = len(plan_actions) > 0
                # Exit 31 means the translator refused the domain or problem,
                # which is not the same event as "no plan exists" even though
                # both end as PLANNER_FOUND_NO_PLAN. Recorded, not acted on.
                state.metadata["fd_returncode"] = fd_diag.get("returncode")
                state.metadata["fd_timed_out"] = fd_diag.get("timed_out")
                state.metadata["fd_stderr"] = fd_diag.get("stderr", "")
                state.metadata["fd_stdout_tail"] = fd_diag.get("stdout_tail", "")

        state.metadata["planner_succeeded"] = planner_ok
        state.metadata["plan_length"] = len(plan_actions)
        # THE PLAN ITSELF IS THE ARTIFACT THE REVIEWABILITY CLAIM RESTS ON.
        # Only its length was kept, so the released logs could not show the
        # operator anything to inspect, and the claim that the artifact retains
        # the Fast Downward plan was not true of any run. Persisting it is what
        # makes the claim checkable: the ordered list of grounded operators, as
        # the planner emitted it, before any reordering or lowering.
        state.metadata["plan"] = [
            {"name": a.get("name"), "params": list(a.get("params") or [])}
            for a in plan_actions
        ]

        # Map mined operator name -> its full schema (grounding + parameters +
        # command_template). _mined_tmpl_map (concretizer template preference)
        # keeps only ops WITH a template; _mined_schema_map keeps all, for the
        # config-edit-routing classifier which needs the grounding tags.
        _mined_schema_map = {a["name"]: a
                             for a in (state.metadata.get("_mined_action_schemas") or [])}
        _mined_tmpl_map = {n: a for n, a in _mined_schema_map.items()
                           if a.get("command_template")}

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

                # Value grounding: a config-edit's value token is a symbolic
                # goal, not literal syntax. Ground it against the live app +
                # version and gate on the app's own validator before accepting.
                # NEUROPLAN_DISABLE_GROUNDING=1 bypasses all grounding fixes
                # (baseline/ablation) -> static templates only.
                _cfg_triple = None
                if os.environ.get("NEUROPLAN_DISABLE_GROUNDING") != "1":
                    _cfg_triple = _config_edit_triple(
                        action, _mined_schema_map.get(action["name"]),
                        scenario_config_map)
                if _cfg_triple is not None:
                    _p, _k, _v = _cfg_triple
                    _mtmpl = (_mined_tmpl_map.get(action["name"], {}) or {}).get(
                        "command_template", "")
                    applied, vmeta = await _ground_and_apply_edit(
                        _p, _k, _v, scenario_config_map,
                        sys_state.get("app_versions", ""),
                        (state.input_text or "")[:800],
                        model, sb, os_name, bash_timeout,
                        mined_template=_mtmpl,
                    )
                    if applied:
                        executed += 1
                        state.metadata.setdefault("value_grounding", []).append(vmeta)
                        state.messages.append(ChatMessageAssistant(content=(
                            f"[neurosym:plan] $ {applied}\n"
                            f"validator={vmeta.get('validator_cmd')} "
                            f"passed={vmeta.get('validator_passed')} "
                            f"attempts={vmeta.get('validator_attempts')}"
                        )))
                        if await _verify_in_sandbox(scenario_path, verify_timeout, os_name):
                            state.output.completion = "REMEDIATION_COMPLETE"
                            return state
                        continue
                    # grounding produced nothing usable -> fall back to template

                bash_cmd = _concretize_template(action, scenario_config_map,
                                                scenario_file_map, _mined_tmpl_map)
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
                    # The step is being DROPPED. Record it: a plan step that
                    # never reaches the host is a lowering failure, and a silent
                    # `continue` makes it indistinguishable from a step that ran
                    # and did not help. Measured at 19% of steps on ccdc and 40%
                    # on meta3/ubuntu, invisible in every artifact until the
                    # transcript was read command by command.
                    state.metadata.setdefault("lowering_failures", []).append({
                        "action": action["name"],
                        "params": action.get("params", []),
                    })
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
            elif not problem_pddl or not state.metadata.get("pddl_problem_valid", True):
                # `not problem_pddl` alone was too narrow. When the generator
                # emitted text that never validated, problem_pddl is non-empty
                # but unusable, the planner block is skipped, and the episode
                # was still reported as PLANNER_FOUND_NO_PLAN: a planner
                # verdict on a scenario the planner never saw. `fd_returncode`
                # is None in exactly this case, which is how triage.py tells
                # the two apart.
                state.output.completion = "PROBLEM_GENERATION_FAILED"
            elif not planner_ok:
                state.output.completion = "PLANNER_FOUND_NO_PLAN"
            else:
                state.output.completion = "PLAN_DID_NOT_REMEDIATE"

        return state

    return solve
