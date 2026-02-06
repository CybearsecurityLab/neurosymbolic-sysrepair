"""
Action Concretizer for Phase 3: PDDL Action to Bash Command Conversion

This module translates grounded PDDL actions into executable bash commands
that can be run in the Docker sandbox.
"""

import re
import logging
from typing import Optional

from .config import ACTION_TEMPLATES
from .models import GroundedAction

logger = logging.getLogger("Phase3.ActionConcretizer")


class ActionConcretizer:
    """
    Converts grounded PDDL actions into executable bash commands.

    Uses a combination of:
    1. Action templates (direct mapping from PDDL action names to bash)
    2. Pattern matching (for actions with predictable naming conventions)
    3. LLM-based concretization (for complex or unknown actions)
    """

    def __init__(self, custom_templates: Optional[dict[str, str]] = None):
        # Merge default templates with any custom ones
        self.templates = {**ACTION_TEMPLATES}
        if custom_templates:
            self.templates.update(custom_templates)

        # Build reverse lookup for action name patterns
        self._pattern_cache: dict[str, str] = {}

    def concretize(self, action: GroundedAction) -> Optional[str]:
        """
        Convert a grounded PDDL action to a bash command.

        Args:
            action: The grounded action with parameter bindings

        Returns:
            Bash command string or None if cannot concretize
        """
        action_name = action.name.lower()

        # 1. Try direct template lookup
        if action_name in self.templates:
            return self._apply_template(action_name, action.bindings)

        # 2. Try pattern matching (e.g., "apt_install_pkg" -> "install_package")
        matched_template = self._match_pattern(action_name)
        if matched_template:
            return self._apply_template(matched_template, action.bindings)

        # 3. Try to infer from action name
        inferred = self._infer_command(action)
        if inferred:
            return inferred

        logger.warning(f"Could not concretize action: {action_name}")
        return None

    # Mapping from PDDL parameter names to canonical template placeholder names.
    # Key: bare parameter name (without ?), Value: canonical name used in templates.
    _KEY_MAPPINGS = {
        # package
        "p": "package", "pkg": "package", "pack": "package",
        "package-name": "package", "pkg-name": "package",
        "deb": "package", "snap": "package", "app": "package",
        # service
        "s": "service", "svc": "service", "unit": "service",
        "daemon": "service", "service-name": "service",
        # user
        "u": "user", "usr": "user", "login": "user",
        "username": "user", "account": "user",
        # group
        "g": "group", "grp": "group", "group-name": "group",
        # file / path
        "f": "file", "path": "file", "filepath": "file",
        "filename": "file", "target": "file",
        # directory
        "d": "directory", "dir": "directory", "folder": "directory",
        # source / destination
        "src": "source", "dst": "destination", "dest": "destination",
        # mode / permissions
        "m": "mode", "perm": "mode", "permissions": "mode",
        # network
        "port": "port", "iface": "interface", "nic": "interface",
        "if": "interface", "conn": "connection",
        # home
        "h": "home", "homedir": "home", "home_dir": "home",
        "home-dir": "home",
        # hostname / system
        "hostname": "hostname", "host": "hostname",
        "deployment": "deployment", "chassis": "chassis",
        "location": "location", "icon": "icon",
        # misc
        "uid": "uid", "gid": "gid", "shell": "shell",
        "alias": "alias", "command": "command", "cmd": "command",
        "members": "members", "member": "members",
    }

    def _apply_template(self, template_name: str, bindings: dict[str, str]) -> Optional[str]:
        """Apply a template with the given variable bindings."""
        template = self.templates.get(template_name)
        if not template:
            return None

        # Convert PDDL variable names to template placeholders
        # PDDL: ?pkg -> template: {package}
        normalized_bindings = {}
        for var_name, value in bindings.items():
            key = var_name.lstrip("?").replace("-", "_")
            normalized_key = self._KEY_MAPPINGS.get(key, key)
            normalized_bindings[normalized_key] = value

        # Also store under the raw stripped key in case template uses it
        for var_name, value in bindings.items():
            raw = var_name.lstrip("?").replace("-", "_")
            if raw not in normalized_bindings:
                normalized_bindings[raw] = value

        try:
            return template.format(**normalized_bindings)
        except KeyError:
            # Fallback: fill what we can, then use unused values for the rest
            import re as _re
            result = template
            used_keys = set()
            for key, value in normalized_bindings.items():
                if f"{{{key}}}" in result:
                    result = result.replace(f"{{{key}}}", value)
                    used_keys.add(key)

            if "{" not in result:
                return result

            # Fill remaining placeholders with unused binding values
            unused_values = [
                v for k, v in normalized_bindings.items()
                if k not in used_keys
            ]
            for val in unused_values:
                placeholder = _re.search(r"\{(\w+)\}", result)
                if placeholder:
                    result = result.replace(
                        f"{{{placeholder.group(1)}}}", val, 1
                    )

            if "{" not in result:
                return result

            logger.warning(f"Missing binding for template {template_name}: {result}")
            return None

    def _match_pattern(self, action_name: str) -> Optional[str]:
        """Try to match action name to a template using patterns."""
        # Check cache first
        if action_name in self._pattern_cache:
            return self._pattern_cache[action_name]

        # Define patterns
        patterns = [
            # Package patterns
            (r"(apt_)?install[_-]?(package|pkg)?", "install_package"),
            (r"(apt_)?remove[_-]?(package|pkg)?", "remove_package"),
            (r"(apt_)?purge[_-]?(package|pkg)?", "purge_package"),
            (r"(apt_)?update[_-]?(list|cache)?", "update_package_list"),
            (r"(apt_)?upgrade[_-]?(packages|all)?", "upgrade_packages"),

            # Service patterns
            (r"(systemctl_)?start[_-]?(service|svc)?", "start_service"),
            (r"(systemctl_)?stop[_-]?(service|svc)?", "stop_service"),
            (r"(systemctl_)?restart[_-]?(service|svc)?", "restart_service"),
            (r"(systemctl_)?enable[_-]?(service|svc)?", "enable_service"),
            (r"(systemctl_)?disable[_-]?(service|svc)?", "disable_service"),
            (r"(systemctl_)?reload[_-]?(service|svc)?", "reload_service"),

            # User patterns
            (r"(useradd_)?create[_-]?(user|account)?", "create_user"),
            (r"(userdel_)?delete[_-]?(user|account)?", "delete_user"),
            (r"lock[_-]?(user|account)?", "lock_user"),
            (r"unlock[_-]?(user|account)?", "unlock_user"),
            (r"add[_-]?user[_-]?to[_-]?group", "add_user_to_group"),

            # Group patterns
            (r"(groupadd_)?create[_-]?group", "create_group"),
            (r"(groupdel_)?delete[_-]?group", "delete_group"),

            # File patterns
            (r"(touch_)?create[_-]?file", "create_file"),
            (r"(rm_)?delete[_-]?file", "delete_file"),
            (r"(mkdir_)?create[_-]?(directory|dir)", "create_directory"),
            (r"(rmdir_)?delete[_-]?(directory|dir)", "delete_directory"),
            (r"(chmod_)?set[_-]?(file_)?permissions?", "set_file_permissions"),
            (r"(chown_)?set[_-]?(file_)?owner", "set_file_owner"),
            (r"(cp_)?copy[_-]?file", "copy_file"),
            (r"(mv_)?move[_-]?file", "move_file"),

            # Firewall patterns
            (r"(ufw_)?allow[_-]?port", "allow_port"),
            (r"(ufw_)?deny[_-]?port", "deny_port"),
            (r"(ufw_)?enable[_-]?firewall", "enable_firewall"),
            (r"(ufw_)?disable[_-]?firewall", "disable_firewall"),
        ]

        for pattern, template_name in patterns:
            if re.match(pattern, action_name, re.IGNORECASE):
                self._pattern_cache[action_name] = template_name
                return template_name

        self._pattern_cache[action_name] = None
        return None

    def _infer_command(self, action: GroundedAction) -> Optional[str]:
        """
        Try to infer a command from action name and parameters.

        Uses common naming conventions:
        - verb_noun pattern (e.g., start_service, create_user)
        - utility_action pattern (e.g., apt_install, systemctl_start)
        """
        name = action.name.lower()
        bindings = {k.lstrip("?"): v for k, v in action.bindings.items()}

        def _get(key: str, *fallbacks: str, default: str = "") -> str:
            for k in (key, *fallbacks):
                if k in bindings:
                    return bindings[k]
            return default or (next(iter(bindings.values()), "") if bindings else "")

        # Package management (apt)
        if name.startswith("apt_") or "_package" in name:
            pkg = _get("package", "p", "pkg")
            if "install" in name:
                return f"apt-get install -y {pkg}"
            elif "remove" in name:
                return f"apt-get remove -y {pkg}"
            elif "purge" in name:
                return f"apt-get purge -y {pkg}"
            elif "update" in name:
                return "apt-get update"
            elif "upgrade" in name:
                return f"apt-get upgrade -y"
            elif "downgrade" in name:
                return f"apt-get install -y --allow-downgrades {pkg}"
            elif "autoremove" in name:
                return "apt-get autoremove -y"
            elif "clean" in name:
                return "apt-get clean"
            elif "hold" in name:
                return f"apt-mark hold {pkg}"
            elif "source" in name:
                return f"apt-get source {pkg}"
            elif "cache" in name:
                return f"apt-cache show {pkg}"
            elif "search" in name:
                return f"apt-cache search {pkg}"

        # Snap package management
        if name.startswith("snap_"):
            pkg = _get("package", "snap", "p")
            sub = name[5:]  # strip "snap_"
            if "install" in sub:
                return f"snap install {pkg}"
            elif "remove" in sub:
                return f"snap remove {pkg}"
            elif "refresh" in sub:
                return f"snap refresh {pkg}"
            elif "revert" in sub:
                return f"snap revert {pkg}"
            elif "enable" in sub:
                return f"snap enable {pkg}"
            elif "disable" in sub:
                return f"snap disable {pkg}"
            elif "connect" in sub:
                return f"snap connect {_get('plug')} {_get('slot')}"
            elif "info" in sub or "list" in sub or "changes" in sub:
                return f"snap {sub.replace('_', ' ')}"
            elif "debug" in sub:
                return f"snap debug {sub.replace('debug_', '').replace('_', '-')}"
            elif "try" in sub:
                return f"snap try {_get('directory', 'path')}"
            else:
                return f"snap {sub.replace('_', ' ')} {pkg}".strip()

        # Service management (systemctl)
        if name.startswith("systemctl_") or "_service" in name:
            service = _get("service", "s", "svc", "unit")
            if "start" in name:
                return f"systemctl start {service}"
            elif "stop" in name:
                return f"systemctl stop {service}"
            elif "restart" in name:
                return f"systemctl restart {service}"
            elif "reload" in name:
                return f"systemctl reload {service}"
            elif "enable" in name:
                return f"systemctl enable {service}"
            elif "disable" in name:
                return f"systemctl disable {service}"
            elif "mask" in name:
                return f"systemctl mask {service}"
            elif "unmask" in name:
                return f"systemctl unmask {service}"
            elif "status" in name:
                return f"systemctl status {service}"

        # Process management (pgrep)
        if name.startswith("pgrep"):
            pattern = _get("pattern", "process", "name")
            if "full" in name:
                return f"pgrep -f {pattern}"
            elif "exact" in name:
                return f"pgrep -x {pattern}"
            elif "count" in name:
                return f"pgrep -c {pattern}"
            elif "newest" in name:
                return f"pgrep -n {pattern}"
            elif "oldest" in name:
                return f"pgrep -o {pattern}"
            elif "list_name" in name:
                return f"pgrep -l {pattern}"
            elif "list_full" in name or "list_processes_full" in name:
                return f"pgrep -af {pattern}"
            elif "inverse" in name:
                return f"pgrep -v {pattern}"
            elif "lightweight" in name:
                return f"pgrep -w {pattern}"
            elif "user" in name:
                return f"pgrep -u {_get('user', 'u')} {pattern}"
            elif "group" in name:
                return f"pgrep -G {_get('group', 'g')} {pattern}"
            elif "terminal" in name:
                return f"pgrep -t {_get('terminal', 't')} {pattern}"
            elif "parent" in name:
                return f"pgrep -P {_get('parent', 'ppid')} {pattern}"
            elif "session" in name:
                return f"pgrep -s {_get('session', 'sid')} {pattern}"
            else:
                return f"pgrep {pattern}"

        # Process management (pkill)
        if name.startswith("pkill"):
            pattern = _get("pattern", "process", "name")
            if "send_signal" in name:
                signal = _get("signal", "sig")
                base = f"pkill -{signal} " if signal else "pkill "
                if "full" in name:
                    return f"{base}-f {pattern}"
                elif "exact" in name:
                    return f"{base}-x {pattern}"
                elif "user" in name:
                    return f"{base}-u {_get('user', 'u')} {pattern}"
                elif "group" in name:
                    return f"{base}-G {_get('group', 'g')} {pattern}"
                elif "newest" in name:
                    return f"{base}-n {pattern}"
                elif "oldest" in name:
                    return f"{base}-o {pattern}"
                elif "parent" in name:
                    return f"{base}-P {_get('parent', 'ppid')} {pattern}"
                elif "session" in name:
                    return f"{base}-s {_get('session', 'sid')} {pattern}"
                elif "terminal" in name:
                    return f"{base}-t {_get('terminal', 't')} {pattern}"
                else:
                    return f"{base}{pattern}"
            elif "echo" in name:
                return f"pkill -e {pattern}"
            elif "full" in name:
                return f"pkill -f {pattern}"
            else:
                return f"pkill {pattern}"

        # Process listing (ps)
        if name.startswith("ps_"):
            if "list_processes" in name:
                return "ps aux"
            elif "list_threads" in name:
                return "ps -eLf"
            elif "format" in name:
                return "ps L"
            elif "version" in name:
                return "ps --version"
            elif "debug" in name:
                return "ps --info"
            elif "wide" in name:
                return "ps auxww"

        # Hostname management (hostnamectl)
        if name.startswith("hostnamectl"):
            sub = name[len("hostnamectl_"):] if name.startswith("hostnamectl_") else ""
            hostname = _get("hostname", "name")
            if sub in ("hostname", "static", "pretty", "transient"):
                flag = f"--{sub}" if sub != "hostname" else ""
                return f"hostnamectl set-hostname {flag} {hostname}".strip()
            elif "chassis" in sub:
                return f"hostnamectl set-chassis {_get('chassis')}"
            elif "deployment" in sub:
                return f"hostnamectl set-deployment {_get('deployment')}"
            elif "location" in sub:
                return f"hostnamectl set-location {_get('location')}"
            elif "icon" in sub:
                return f"hostnamectl set-icon-name {_get('icon')}"
            elif "status" in sub:
                return "hostnamectl status"
            elif "version" in sub:
                return "hostnamectl --version"
            elif "json" in sub:
                return "hostnamectl status --json=short"
            elif "help" in sub:
                return "hostnamectl --help"
            else:
                return f"hostnamectl {sub.replace('_', ' ')}".strip()

        # Time/date management (timedatectl)
        if name.startswith("timedatectl"):
            sub = name[len("timedatectl_"):] if name.startswith("timedatectl_") else ""
            if "set_timezone" in sub:
                return f"timedatectl set-timezone {_get('timezone')}"
            elif "set_time" in sub:
                return f"timedatectl set-time {_get('time')}"
            elif "set_ntp" in sub:
                return f"timedatectl set-ntp {_get('enabled', 'value')}"
            elif "set_local_rtc" in sub:
                return f"timedatectl set-local-rtc {_get('enabled', 'value')}"
            elif "list_timezones" in sub:
                return "timedatectl list-timezones"
            elif "show" in sub:
                return "timedatectl show"
            elif "status" in sub or "timesync" in sub:
                return "timedatectl timesync-status"
            elif "ntp" in sub:
                return f"timedatectl ntp-servers {_get('interface')} {_get('server')}"
            elif "revert" in sub:
                return "timedatectl revert"
            else:
                return f"timedatectl {sub.replace('_', '-')}".strip()

        # Journal management (journalctl)
        if name.startswith("journal"):
            if name == "journalctl" or name == "journalctl_filter":
                return "journalctl --no-pager -n 50"
            sub = name[len("journal_"):] if name.startswith("journal_") else name
            if "rotate" in sub:
                return "journalctl --rotate"
            elif "vacuum_time" in sub:
                return f"journalctl --vacuum-time={_get('time', 'value')}"
            elif "vacuum_size" in sub:
                return f"journalctl --vacuum-size={_get('size', 'value')}"
            elif "vacuum_files" in sub:
                return f"journalctl --vacuum-files={_get('count', 'value')}"
            elif "flush" in sub:
                return "journalctl --flush"
            elif "sync" in sub:
                return "journalctl --sync"
            elif "verify" in sub:
                return "journalctl --verify"
            elif "disk_usage" in sub:
                return "journalctl --disk-usage"
            elif "catalog" in sub:
                if "list" in sub:
                    return "journalctl --list-catalog"
                elif "update" in sub:
                    return "journalctl --update-catalog"
                elif "dump" in sub:
                    return "journalctl --dump-catalog"
            elif "header" in sub:
                return "journalctl --header"
            elif "setup_keys" in sub:
                return "journalctl --setup-keys"
            elif "boot" in sub or "invocation" in sub:
                return "journalctl --list-boots"
            elif "relinquish" in sub:
                return "journalctl --relinquish-var"
            else:
                return f"journalctl --{sub.replace('_', '-')}"

        # Network manager (nmcli)
        if name.startswith("nmcli"):
            sub = name[len("nmcli_"):] if name.startswith("nmcli_") else ""
            if "success" in sub or "error" in sub or "timeout" in sub or "not_found" in sub or "not_running" in sub or "failed" in sub or "invalid" in sub:
                return "nmcli general status"
            else:
                return f"nmcli {sub.replace('_', ' ')}".strip()

        # Change operations
        if name.startswith("change_"):
            sub = name[7:]  # strip "change_"
            if "owner" in sub and "group" in sub:
                return f"chown {_get('user', 'owner')}:{_get('group')} {_get('file', 'path')}"
            elif "owner" in sub:
                flag = ""
                if "recursive" in sub:
                    flag = "-R "
                elif "no_dereference" in sub:
                    flag = "-h "
                elif "silent" in sub:
                    flag = "-f "
                elif "verbose" in sub:
                    flag = "-v "
                return f"chown {flag}{_get('user', 'owner')} {_get('file', 'path')}"
            elif "ownership" in sub:
                return f"chown {_get('user', 'owner')}:{_get('group')} {_get('file', 'path')}"
            elif "group" in sub:
                return f"chgrp {_get('group')} {_get('file', 'path')}"
            elif "permissions" in sub or "file_mode" in sub or "mode" in sub:
                return f"chmod {_get('mode', 'permissions')} {_get('file', 'path')}"
            elif "home_directory" in sub:
                return f"usermod -d {_get('directory', 'home')} {_get('user')}"
            elif "login_name" in sub:
                return f"usermod -l {_get('new_name', 'login')} {_get('user')}"
            elif "user_shell" in sub or "shell" in sub:
                return f"chsh -s {_get('shell')} {_get('user')}"
            elif "user_password" in sub or "password" in sub:
                return f"echo '{_get('user')}:{_get('password')}' | chpasswd"
            elif "user_uid" in sub or "user_id" in sub:
                return f"usermod -u {_get('uid', 'id')} {_get('user')}"
            elif "primary_group" in sub:
                return f"usermod -g {_get('group')} {_get('user')}"
            elif "supplementary_groups" in sub:
                return f"usermod -G {_get('groups', 'group')} {_get('user')}"
            elif "crontab" in sub:
                return f"chown {_get('user', 'owner')} /var/spool/cron/crontabs/{_get('user', 'owner')}"
            elif "timestamp" in sub:
                return f"touch -t {_get('timestamp', 'time')} {_get('file', 'path')}"
            elif "apt_options" in sub or "config_options" in sub:
                return "apt-get update"

        # Set operations
        if name.startswith("set_"):
            sub = name[4:]  # strip "set_"
            if "file_permissions" in sub or "permissions" in sub:
                return f"chmod {_get('mode', 'permissions')} {_get('file', 'path')}"
            elif "file_owner" in sub or "owner" in sub:
                return f"chown {_get('user', 'owner')}:{_get('group')} {_get('file', 'path')}"
            elif "hostname" in sub:
                return f"hostnamectl set-hostname {_get('hostname', 'name')}"
            elif "timezone" in sub:
                return f"timedatectl set-timezone {_get('timezone')}"
            elif "wide_output" in sub:
                return "ps auxww"
            elif "locale" in sub:
                return f"localectl set-locale {_get('locale', 'lang', default='C')}"
            elif "terminal" in sub:
                return f"export TERM={_get('terminal', 'term', default='xterm')}"
            elif "user_uid" in sub or "uid" in sub:
                return f"usermod -u {_get('uid', 'id')} {_get('user')}"
            elif "user_gid" in sub or "gid" in sub:
                return f"usermod -g {_get('gid', 'group')} {_get('user')}"
            elif "user_shell" in sub or "login_shell" in sub:
                return f"usermod -s {_get('shell')} {_get('user')}"
            elif "user_home" in sub or "home_dir" in sub:
                return f"usermod -d {_get('home', 'directory')} {_get('user')}"
            elif "user_comment" in sub or "gecos" in sub:
                return f"usermod -c {_get('comment', 'gecos')} {_get('user')}"
            elif "user_expiry" in sub or "expiredate" in sub:
                return f"usermod -e {_get('date', 'expiry')} {_get('user')}"
            elif "ntp" in sub:
                return f"timedatectl set-ntp {_get('enabled', default='true')}"
            else:
                return "true"  # safe no-op for other set_ actions

        # Modify operations
        if name.startswith("modify_"):
            sub = name[7:]
            if "user" in sub:
                return f"usermod {_get('user')}"
            elif "group" in sub:
                return f"groupmod {_get('group')}"
            elif "nis" in sub or "network" in sub:
                return "true"  # no-op for NIS/network modify
            else:
                return "true"

        # Ignore/skip/acknowledge operations (no-ops by design)
        if name.startswith("ignore_") or name.startswith("skip_") or name.startswith("acknowledge_"):
            return "true"

        # Configure operations
        if name.startswith("configure_"):
            sub = name[10:]  # strip "configure_"
            if "apt" in sub:
                return "apt-get update"
            elif "firewall" in sub:
                return "ufw status"
            elif "connection" in sub or "ct_" in sub or "netfilter" in sub:
                return "iptables -L -n"
            elif "color" in sub:
                return "true"  # no-op for color config
            else:
                return "true"  # safe no-op for config actions

        # Show/display/list operations (read-only)
        if name.startswith("show_") or name.startswith("display_") or name.startswith("list_"):
            prefix = name.split("_", 1)[0]
            sub = name[len(prefix) + 1:]
            if "package" in sub:
                return f"dpkg -l {_get('package', 'p')}"
            elif "service" in sub:
                return "systemctl list-units --type=service --no-pager"
            elif "user" in sub:
                return "cat /etc/passwd"
            elif "group" in sub:
                return "cat /etc/group"
            elif "process" in sub:
                return "ps aux"
            elif "interface" in sub or "network" in sub:
                return "ip addr show"
            elif "route" in sub:
                return "ip route show"
            elif "rule" in sub:
                return "iptables -L -n"
            elif "connection" in sub:
                return "nmcli connection show"
            elif "boot" in sub:
                return "journalctl --list-boots"
            elif "timezone" in sub:
                return "timedatectl list-timezones"
            elif "unit" in sub:
                return "systemctl list-units --no-pager"
            elif "socket" in sub:
                return "ss -tuln"
            elif "file" in sub or "dir" in sub:
                return f"ls -la {_get('path', 'directory', 'file')}"
            else:
                return "true"

        # Enable/disable operations (when not caught by service patterns)
        if name.startswith("enable_"):
            sub = name[7:]
            if "ntp" in sub:
                return "timedatectl set-ntp true"
            elif "firewall" in sub:
                return "ufw --force enable"
            else:
                return f"systemctl enable {_get('service', 'unit', 'name')}"

        if name.startswith("disable_"):
            sub = name[8:]
            if "ntp" in sub:
                return "timedatectl set-ntp false"
            elif "firewall" in sub:
                return "ufw disable"
            else:
                return f"systemctl disable {_get('service', 'unit', 'name')}"

        # Run operations
        if name.startswith("run_"):
            sub = name[4:]
            if "login_shell" in sub:
                return f"su - {_get('user')}"
            elif "shell" in sub:
                return f"su {_get('user')}"
            elif "snap_command" in sub:
                return f"snap run {_get('snap', 'package')}"
            elif "nice_command" in sub:
                return f"nice {_get('command')}"
            elif "useradd" in sub or "userdel" in sub:
                return "true"  # hook scripts
            elif "debug" in sub:
                return "true"
            elif "command" in sub:
                return _get("command")
            else:
                return "true"

        # Apply operations
        if name.startswith("apply_"):
            sub = name[6:]
            if "preset" in sub:
                return f"systemctl preset {_get('service', 'unit')}"
            elif "unit_change" in sub:
                return "systemctl daemon-reload"
            elif "configuration" in sub or "changes" in sub:
                return "true"
            elif "filter" in sub or "masq" in sub or "socket" in sub:
                return "iptables -L -n"
            else:
                return "true"

        # Edit operations
        if name.startswith("edit_"):
            return "true"  # editing is interactive, treat as no-op

        # Acquire/release lock
        if "acquire_lock" in name:
            return "true"
        if "release_lock" in name:
            return "true"

        # User management (fallback)
        if "_user" in name or name.startswith("user"):
            user = _get("user", "u")
            if "create" in name or "add" in name:
                return f"useradd {user}"
            elif "delete" in name or "remove" in name:
                return f"userdel {user}"
            elif "lock" in name:
                return f"usermod -L {user}"
            elif "unlock" in name:
                return f"usermod -U {user}"

        # Group management (fallback)
        if "_group" in name or name.startswith("group"):
            group = _get("group", "g")
            if "create" in name or "add" in name:
                return f"groupadd {group}"
            elif "delete" in name or "remove" in name:
                return f"groupdel {group}"

        # File operations (fallback)
        if "_file" in name or "_directory" in name:
            path = _get("file", "directory", "path")
            if "create" in name:
                if "directory" in name or "dir" in name:
                    return f"mkdir -p {path}"
                else:
                    return f"touch {path}"
            elif "delete" in name or "remove" in name:
                if "directory" in name or "dir" in name:
                    return f"rm -rf {path}"
                else:
                    return f"rm -f {path}"
            elif "copy" in name:
                return f"cp {_get('source', 'src')} {_get('destination', 'dest')}"
            elif "move" in name:
                return f"mv {_get('source', 'src')} {_get('destination', 'dest')}"

        # IP/network operations
        if name.startswith("add_ip") or name.startswith("add_ipv"):
            return f"ip addr add {_get('address', 'addr')} dev {_get('interface', 'dev')}"
        if name.startswith("add_route") or name.startswith("add_fwd"):
            return f"ip route add {_get('route', 'network')} via {_get('gateway', 'via')}"
        if name.startswith("add_vlan"):
            return f"nmcli connection add type vlan con-name {_get('name')} dev {_get('interface')}"
        if name.startswith("add_dns"):
            return f"resolvectl dns {_get('interface', 'dev')} {_get('server', 'dns')}"

        # Iptables/firewall operations
        if "iptables" in name or name.startswith("add_rule") or name.startswith("add_flow"):
            chain = _get("chain", "table")
            return f"iptables -A {chain} {_get('rule', 'match')}"

        # Netdev operations
        if name.startswith("netdev_"):
            return f"ip link {name[7:].replace('_', ' ')}"

        # Allocation operations (subuid/subgid)
        if "subgid" in name or "subuid" in name or "subordinate" in name:
            user = _get("user", "u")
            if "gid" in name or "group" in name:
                return f"usermod --add-subgids {_get('range', '100000-165535')} {user}"
            else:
                return f"usermod --add-subuids {_get('range', '100000-165535')} {user}"

        # Allow/deny operations
        if name.startswith("allow_"):
            sub = name[6:]
            if "downgrade" in sub:
                return "true"  # apt config flag
            elif "traffic" in sub or "port" in sub:
                return f"ufw allow {_get('port', 'rule')}"
            else:
                return "true"  # apt config flags are no-ops

        # Add operations (catchall for remaining add_* patterns)
        if name.startswith("add_"):
            sub = name[4:]
            if "user" in sub and "group" in sub:
                return f"usermod -aG {_get('group')} {_get('user')}"
            elif "element" in sub or "set" in sub or "map" in sub:
                return f"nft add {sub.replace('_', ' ')}"
            elif "counter" in sub:
                return "true"
            elif "quota" in sub:
                return "true"
            elif "requires" in sub or "wants" in sub:
                return f"systemctl add-wants {_get('target')} {_get('unit')}"
            elif "architecture" in sub:
                return f"dpkg --add-architecture {_get('arch', 'architecture')}"

        # Remove operations (catchall)
        if name.startswith("remove_"):
            sub = name[7:]
            if "package" in sub:
                return f"apt-get remove -y {_get('package', 'p')}"
            elif "user" in sub:
                return f"userdel {_get('user')}"
            elif "group" in sub:
                return f"groupdel {_get('group')}"
            elif "file" in sub:
                return f"rm -f {_get('file', 'path')}"
            elif "directory" in sub or "dir" in sub:
                return f"rm -rf {_get('directory', 'path')}"
            elif "rule" in sub:
                return f"iptables -D {_get('chain')} {_get('rule')}"

        # Delete operations (catchall)
        if name.startswith("delete_"):
            sub = name[7:]
            if "user" in sub:
                return f"userdel {_get('user')}"
            elif "group" in sub:
                return f"groupdel {_get('group')}"
            elif "file" in sub:
                return f"rm -f {_get('file', 'path')}"
            elif "directory" in sub or "dir" in sub:
                return f"rm -rf {_get('directory', 'path')}"
            elif "rule" in sub:
                return f"iptables -D {_get('chain')} {_get('rule')}"
            elif "connection" in sub:
                return f"nmcli connection delete {_get('name', 'connection')}"

        # Copy/move operations (catchall)
        if name.startswith("copy_"):
            return f"cp {_get('source', 'src')} {_get('destination', 'dest')}"
        if name.startswith("move_"):
            return f"mv {_get('source', 'src')} {_get('destination', 'dest')}"

        # Update operations
        if name.startswith("update_"):
            sub = name[7:]
            if "package" in sub:
                return "apt-get update"
            elif "catalog" in sub:
                return "journalctl --update-catalog"
            else:
                return "true"

        # Acknowledge/abort/no-op operations
        if name.startswith("acknowledge_") or name.startswith("abort_") or name.startswith("no_"):
            return "true"

        # Groupadd variants
        if name.startswith("groupadd"):
            return f"groupadd {_get('group', 'name')}"

        return None

    def register_template(self, action_name: str, template: str):
        """Register a custom action template."""
        self.templates[action_name.lower()] = template

    def get_all_templates(self) -> dict[str, str]:
        """Get all registered templates."""
        return self.templates.copy()

    def can_concretize(self, action: GroundedAction) -> bool:
        """Check if an action can be concretized."""
        return self.concretize(action) is not None


class EffectVerifier:
    """
    Verifies that PDDL action effects match actual environment changes.
    """

    def __init__(self, docker_executor):
        self.executor = docker_executor

    def verify_effects(
        self,
        action: GroundedAction,
        expected_effects: list[str]
    ) -> tuple[list[str], list[str]]:
        """
        Verify expected effects against actual environment state.

        Returns:
            (matched_effects, mismatched_effects)
        """
        matched = []
        mismatched = []

        for effect in expected_effects:
            # Parse the effect
            is_negative = effect.strip().startswith("(not")
            predicate = self._extract_predicate(effect)

            if not predicate:
                continue

            pred_name = predicate[0]
            pred_args = predicate[1:]

            # Build bindings for predicate check
            check_bindings = {}
            for i, arg in enumerate(pred_args):
                if arg.startswith("?"):
                    # Look up in action bindings
                    value = action.bindings.get(arg, arg)
                    check_bindings[f"arg{i}"] = value
                else:
                    check_bindings[f"arg{i}"] = arg

            # Verify predicate
            holds = self.executor.verify_predicate(pred_name, check_bindings)

            expected_to_hold = not is_negative
            if holds == expected_to_hold:
                matched.append(effect)
            else:
                mismatched.append(effect)

        return matched, mismatched

    def _extract_predicate(self, effect: str) -> Optional[list[str]]:
        """Extract predicate name and arguments from an effect expression."""
        # Remove (not ...) wrapper if present
        effect = effect.strip()
        if effect.startswith("(not"):
            effect = effect[4:].strip().rstrip(")")

        # Parse (predicate_name arg1 arg2 ...)
        match = re.match(r'\((\w+)([^)]*)\)', effect)
        if match:
            pred_name = match.group(1)
            args_str = match.group(2).strip()
            args = args_str.split() if args_str else []
            return [pred_name] + args

        return None
