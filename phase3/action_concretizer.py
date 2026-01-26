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

    def _apply_template(self, template_name: str, bindings: dict[str, str]) -> Optional[str]:
        """Apply a template with the given variable bindings."""
        template = self.templates.get(template_name)
        if not template:
            return None

        # Convert PDDL variable names to template placeholders
        # PDDL: ?pkg -> template: {package}
        normalized_bindings = {}
        for var_name, value in bindings.items():
            # Remove ? prefix and normalize
            key = var_name.lstrip("?")

            # Map common variations
            key_mappings = {
                "p": "package",
                "pkg": "package",
                "s": "service",
                "svc": "service",
                "u": "user",
                "usr": "user",
                "g": "group",
                "grp": "group",
                "f": "file",
                "d": "directory",
                "dir": "directory",
                "src": "source",
                "dst": "destination",
                "dest": "destination",
                "m": "mode",
                "port": "port",
                "iface": "interface",
            }

            normalized_key = key_mappings.get(key, key)
            normalized_bindings[normalized_key] = value

        try:
            return template.format(**normalized_bindings)
        except KeyError as e:
            logger.warning(f"Missing binding for template {template_name}: {e}")
            # Try partial formatting
            result = template
            for key, value in normalized_bindings.items():
                result = result.replace(f"{{{key}}}", value)
            return result if "{" not in result else None

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

        # Common verb patterns
        if name.startswith("apt_") or "_package" in name:
            if "install" in name:
                return f"apt-get install -y {bindings.get('package', bindings.get('p', ''))}"
            elif "remove" in name:
                return f"apt-get remove -y {bindings.get('package', bindings.get('p', ''))}"
            elif "update" in name:
                return "apt-get update"
            elif "upgrade" in name:
                return "apt-get upgrade -y"

        if name.startswith("systemctl_") or "_service" in name:
            service = bindings.get("service", bindings.get("s", ""))
            if "start" in name:
                return f"systemctl start {service}"
            elif "stop" in name:
                return f"systemctl stop {service}"
            elif "restart" in name:
                return f"systemctl restart {service}"
            elif "enable" in name:
                return f"systemctl enable {service}"
            elif "disable" in name:
                return f"systemctl disable {service}"

        if "_user" in name or name.startswith("user"):
            user = bindings.get("user", bindings.get("u", ""))
            if "create" in name or "add" in name:
                return f"useradd {user}"
            elif "delete" in name or "remove" in name:
                return f"userdel {user}"
            elif "lock" in name:
                return f"usermod -L {user}"
            elif "unlock" in name:
                return f"usermod -U {user}"

        if "_group" in name or name.startswith("group"):
            group = bindings.get("group", bindings.get("g", ""))
            if "create" in name or "add" in name:
                return f"groupadd {group}"
            elif "delete" in name or "remove" in name:
                return f"groupdel {group}"

        if "_file" in name or "_directory" in name:
            path = bindings.get("file", bindings.get("directory", bindings.get("path", "")))
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
