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
        "echo '# world_writable'; find /var/www /usr/lib/cgi-bin /srv /opt -xdev "
        "\\( -perm -0002 \\) 2>/dev/null | head -30; "
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
    cfgs = (state.get("objects", {}) or {}).get("configuration_file", []) or []
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
        try:
            return tmpl.format(*params)
        except (IndexError, KeyError):
            pass
    return None


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
    "active file, use THAT file; otherwise use the default file>\"}}\n"
    "The directive line must be valid for the application and version shown. "
    "The validate command must be that application's own checker. target_path "
    "must be one of the active files listed in the evidence, or the default file."
)

_EFFECTIVE_PROBE_PROMPT = (
    "A remediation must set directive '{key}' where the RUNNING daemon actually "
    "reads it. Applications on this host:\n{app_versions}\n\n"
    "Give the application's OWN read-only command that prints the FILE PATHS of "
    "every configuration file the running daemon loads or includes (so we can "
    "locate which file sets the directive). It must emit real /etc/... file "
    "paths, not merely a syntax check. Return STRICT JSON only: "
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
    """Separator-tolerant ERE for a directive key so it matches both the
    CamelCase (Apache/sshd `SSLProtocol`) and snake_case (nginx `ssl_protocols`)
    on-disk spellings regardless of how Fast Downward cased the PDDL token."""
    toks = [t for t in re.split(r"[-_]", key) if t]
    return "[-_]?".join(re.escape(t) for t in toks) or re.escape(key)


async def _effective_config_probe(key, app_versions, model, sb, os_name, bash_timeout,
                                  dbg=None, scenario_map=None):
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
                key=key, app_versions=(app_versions or "(none)")[:1000]))],
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


async def _ground_and_apply_edit(action, scenario_map, app_versions, vuln_brief,
                                 model, sb, os_name, bash_timeout):
    """Value-ground and apply an ``edit_config_setting`` action.

    Asks the model for the literal directive line + the application's native
    validator (given the app+version and the real file), applies it with a
    backup (comment old, append new), then gates on the validator: on failure
    it rolls back and re-prompts with the validator's stderr (bounded retries).

    Returns ``(applied_cmd_str | None, meta)``. ``None`` means grounding
    produced nothing usable; the caller then falls back to the static template.
    """
    params = list(action.get("params", []) or [])
    if len(params) < 2:
        return None, {}
    path = _resolve_config_path(params[0], scenario_map)
    key = params[1]
    # symbolic target: prefer the 4th param (new_value), else 3rd, else the key
    symbolic_value = params[3] if len(params) > 3 else (
        params[2] if len(params) > 2 else key)
    qp = shlex.quote(path)
    try:
        r = await sb.exec(_shell_exec_argv(os_name, f"sed -n '1,120p' {qp} 2>/dev/null"),
                          timeout=bash_timeout)
        current = (r.stdout or "")[:2000]
    except Exception:
        current = ""

    # Effective-config introspection: find where the running daemon actually
    # obeys this directive (multi-file include graphs: apache vhosts, nginx
    # includes). The model may then target that file instead of the default.
    _probe_dbg: dict = {}
    effective, candidate_files = await _effective_config_probe(
        key, app_versions, model, sb, os_name, bash_timeout, _probe_dbg,
        scenario_map=scenario_map)

    meta: dict = {"path": path, "key": key, "value_grounding_used": True,
                  "effective_probe_used": bool(candidate_files),
                  "candidate_files": len(candidate_files),
                  "probe_debug": _probe_dbg}
    last_err = ""
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
        if not obj or not obj.get("line"):
            continue
        line = str(obj["line"]).strip()
        validate = str(obj.get("validate", "")).strip()
        # Retarget to the effective file only if the model named one the probe
        # verified as active (evidence-gated: never trust a bare string).
        target = str(obj.get("target_path", "")).strip()
        edit_path = target if target in candidate_files else path
        qpe = shlex.quote(edit_path)
        meta["value_line"] = line
        meta["validator_cmd"] = validate
        meta["validator_attempts"] = attempt + 1
        meta["edit_path"] = edit_path

        ql = line.replace("'", "'\\''")
        pat = _directive_grep_pattern(key)
        apply_cmd = (
            f"cp {qpe} {qpe}.neuroplan.bak 2>/dev/null; "
            f"sed -i -E 's|^([[:space:]]*{pat}[[:space:]].*)$|# \\1|I' {qpe} 2>/dev/null; "
            f"printf '%s\\n' '{ql}' >> {qpe}"
        )
        try:
            await sb.exec(_shell_exec_argv(os_name, apply_cmd), timeout=bash_timeout)
        except Exception:
            return None, meta

        if validate and _looks_safe_validator(validate):
            try:
                vr = await sb.exec(_shell_exec_argv(os_name, validate), timeout=bash_timeout)
            except Exception:
                vr = None
            if vr is not None and vr.returncode == 0:
                meta["validator_passed"] = True
                return apply_cmd, meta
            last_err = (getattr(vr, "stderr", "") or getattr(vr, "stdout", "") or "")[:400]
            meta["validator_passed"] = False
            # roll back the edited file before retrying
            await sb.exec(_shell_exec_argv(os_name, f"cp {qpe}.neuroplan.bak {qpe} 2>/dev/null"),
                          timeout=bash_timeout)
            continue
        # No usable validator: keep the grounded edit but flag it unverified.
        meta["validator_passed"] = None
        return apply_cmd, meta
    return None, meta


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
        # 3. operator extraction (LLM off-thread)
        op = await loop.run_in_executor(
            None, _om.mine_operator, it, (man or "")[:2000], vocab, llm)
        if not op:
            rejected.append((it.verb, "extraction-empty"))
            continue
        ok, reason = _om.lint_operator(op)
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

        # Per-scenario config-path map from the Phase 1 introspection beside
        # the domain: lets the concretizer ground nested service configs
        # (e.g. /etc/apache2/mods-enabled/ssl.conf) the static alias map does
        # not enumerate, including invented identifiers via token matching.
        scenario_config_map = _load_scenario_config_map(domain_path)
        state.metadata["scenario_config_files"] = len(scenario_config_map)

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

        # Map mined operator name -> its schema (command_template + grounding),
        # so the concretizer prefers the operator's own template over a static
        # (possibly destructive) one.
        _mined_tmpl_map = {a["name"]: a
                           for a in (state.metadata.get("_mined_action_schemas") or [])
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
                if action["name"] == "edit_config_setting" and \
                        os.environ.get("NEUROPLAN_DISABLE_GROUNDING") != "1":
                    applied, vmeta = await _ground_and_apply_edit(
                        action, scenario_config_map,
                        sys_state.get("app_versions", ""),
                        (state.input_text or "")[:800],
                        model, sb, os_name, bash_timeout,
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
