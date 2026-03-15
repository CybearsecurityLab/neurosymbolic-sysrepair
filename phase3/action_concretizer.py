"""
Action Concretizer for Phase 3: PDDL Action to Bash Command Conversion

Translates grounded PDDL actions into executable bash commands using:
1. Phase 1 metadata templates (from manpage extraction, zero latency)
2. LLM-based concretization (qwen3.5:32b, cached after first call)
3. Return None if both fail

Also contains EffectVerifier for post-execution effect checking.
"""

import json
import re
import logging
from pathlib import Path
from typing import Optional

from .config import PREDICATE_CHECKS
from .models import GroundedAction

logger = logging.getLogger("Phase3.ActionConcretizer")

# ─── LLM Prompt Constants ────────────────────────────────────────────

CONCRETIZE_SYSTEM_MSG = (
    "You are a Linux command translator for Ubuntu 25.10. "
    "Given a PDDL action description and concrete parameter values, "
    "output ONLY a single bash command with the actual values substituted in. "
    "No explanation, no markdown, no backticks, no thinking. Just the raw command.\n"
    "Available tools: iproute2, iptables, net-tools, passwd, adduser, "
    "coreutils, snapd, ufw, nftables, procps, login, kmod, acl.\n"
    "Example: if action is install_package with package=curl, output: apt-get install -y curl"
)


class ActionConcretizer:
    """
    Converts grounded PDDL actions into executable bash commands.

    3-tier approach:
    1. Phase 1 templates — extracted from manpages, high confidence
    2. LLM concretization — for actions without Phase 1 data, cached
    3. Return None — if LLM fails or returns invalid command
    """

    def __init__(
        self,
        phase1_metadata_path: str = "",
        llm_client=None,
        llm_model: str = "qwen3.5:35b",
        llm_max_tokens: int = 256,
        llm_temperature: float = 0.0,
        cache_path: str = "",
    ):
        # Phase 1 metadata index: action_name -> {command_template, source_utility, ...}
        self._phase1_index: dict[str, dict] = {}
        if phase1_metadata_path and Path(phase1_metadata_path).exists():
            self._phase1_index = self._load_phase1_metadata(phase1_metadata_path)
            logger.info(
                f"Loaded Phase 1 metadata: {len(self._phase1_index)} actions "
                f"with command templates"
            )

        # LLM client for Tier 2 concretization
        self._llm = llm_client
        self._llm_model = llm_model
        self._llm_max_tokens = llm_max_tokens
        self._llm_temperature = llm_temperature

        # Persistent cache: action_name -> command template string
        self._cache_path = cache_path
        self._cache: dict[str, str] = {}
        if cache_path:
            self._cache = self._load_cache(cache_path)
            if self._cache:
                logger.info(f"Loaded concretizer cache: {len(self._cache)} entries")

        # Stats
        self._stats = {"phase1_hits": 0, "cache_hits": 0, "llm_hits": 0, "failures": 0}

    # ─── Main Interface ──────────────────────────────────────────────

    def concretize(self, action: GroundedAction) -> Optional[str]:
        """
        Convert a grounded PDDL action to a bash command.

        Returns:
            Bash command string or None if cannot concretize
        """
        action_name = action.name.lower()
        normalized = self._normalize_bindings(action.bindings)

        # Check cache first (fastest path)
        if action_name in self._cache:
            result = self._fill_template(self._cache[action_name], normalized)
            if result:
                self._stats["cache_hits"] += 1
                return result

        # Tier 1: Phase 1 template (no LLM, high confidence)
        result = self._try_phase1_template(action_name, normalized)
        if result:
            # Cache the template form for future calls
            template = self._extract_template_form(result, normalized)
            self._cache[action_name] = template
            self._stats["phase1_hits"] += 1
            return result

        # Tier 2: LLM concretization
        result = self._try_llm_concretize(action_name, action, normalized)
        if result:
            template = self._extract_template_form(result, normalized)
            self._cache[action_name] = template
            self._save_cache()
            self._stats["llm_hits"] += 1
            return result

        # Tier 3: Can't concretize
        self._stats["failures"] += 1
        logger.debug(f"Could not concretize action: {action_name}")
        return None

    def get_stats(self) -> dict:
        """Return concretization statistics."""
        return dict(self._stats)

    # ─── KEY_MAPPINGS: PDDL param names → canonical names ────────────

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
        # firewall / nft
        "r": "rule", "chain": "chain", "table": "table",
        "rule": "rule", "rulenum": "number",
        # generic value-like params
        "dscp": "value", "ecn": "value", "proto": "protocol",
        "protocol": "protocol",
        # link
        "link": "file", "rfile": "reference",
        # days (chage/passwd)
        "days": "days",
        # tunnel
        "tunnel": "tunnel",
        # process
        "pattern": "pattern", "process": "process", "name": "name",
        # namespace
        "ns": "namespace", "namespace": "namespace",
        # module
        "module": "module", "mod": "module",
        # key/value for sysctl
        "key": "key", "parameter": "key", "val": "value",
        "value": "value",
        # layout (localectl)
        "layout": "layout", "keymap": "layout",
        # locale
        "locale": "locale", "lang": "locale",
        # setting (netplan)
        "setting": "setting",
        # priority (nice)
        "priority": "priority", "n": "priority",
        # signal
        "signal": "signal", "sig": "signal",
        # acl
        "acl": "acl",
        # date
        "date": "date", "expiry": "date",
        # comment/gecos
        "comment": "comment", "gecos": "comment",
        # suffix
        "suffix": "suffix",
        # release
        "release": "release",
        # range
        "range": "range",
        # format
        "format": "format",
        # user aliases (su/sudo actions)
        "target_user": "user", "caller": "user",
        "old_login": "user", "new_login": "user",
        # process aliases
        "pr": "process", "pp": "process", "pid": "process",
        # firewall chain rename
        "o_old": "chain", "o_new": "new_chain",
        # socket / query
        "st": "state", "family": "family", "session": "session",
        "map_id": "value",
        # backup
        "backup": "file",
        # chage days/values
        "inactive": "value", "expire_date": "date",
        # reference
        "reference": "reference", "ref": "reference",
        # object (generic)
        "obj": "object", "o": "object",
    }

    # ─── PDDL Object Name → Real System Value ───────────────────────

    @staticmethod
    def _object_to_value(pddl_name: str) -> str:
        """
        Convert a PDDL object name back to a real system value.

        PDDL object naming conventions from Phase 1/2:
          user_root          → root
          user__apt           → _apt       (double underscore = leading underscore)
          group_docker       → docker
          service_cron_service → cron.service
          package_apt        → apt
          configuration_file__etc_debconf_conf → /etc/debconf.conf
          process_systemd    → systemd
          port_6_53          → 53  (just the port number)
        """
        name = pddl_name

        # Configuration files: configuration_file__path_to_file_ext
        if name.startswith("configuration_file_"):
            path = name[len("configuration_file_"):]
            if path.startswith("_"):
                path = path[1:]
            parts = path.split("_")
            if len(parts) >= 2:
                ext = parts[-1]
                dir_and_name = parts[:-1]
                file_path = "/" + "/".join(dir_and_name) + "." + ext
                return file_path
            return "/" + path.replace("_", "/")

        # Service names: service_foo_service → foo.service
        if name.startswith("service_") and name.endswith("_service"):
            svc = name[len("service_"):-len("_service")]
            return svc + ".service"
        if name.startswith("service_"):
            return name[len("service_"):]

        # User names: user_root → root, user__apt → _apt
        if name.startswith("user_"):
            user = name[len("user_"):]
            return user

        # Group names: group_root → root
        if name.startswith("group_"):
            return name[len("group_"):]

        # Package names: package_apt → apt
        if name.startswith("package_"):
            return name[len("package_"):]

        # Process names: process_systemd → systemd
        if name.startswith("process_"):
            return name[len("process_"):]

        # Port names: port_6_53 → 53 (protocol_port)
        if name.startswith("port_"):
            parts = name[len("port_"):].split("_")
            if len(parts) >= 2:
                return parts[-1]
            return parts[0]

        # No prefix recognized — return as-is
        return name

    # ─── Binding Normalization ───────────────────────────────────────

    def _normalize_bindings(self, bindings: dict[str, str]) -> dict[str, str]:
        """
        Normalize PDDL bindings to canonical names with real values.

        Input:  {"?pkg": "package_apt", "?u": "user_root"}
        Output: {"package": "apt", "user": "root"}
        """
        normalized = {}
        for var_name, pddl_value in bindings.items():
            key = var_name.lstrip("?").replace("-", "_")
            canonical = self._KEY_MAPPINGS.get(key, key)
            value = self._object_to_value(pddl_value)
            normalized[canonical] = value
        return normalized

    # ─── Tier 1: Phase 1 Template ────────────────────────────────────

    def _load_phase1_metadata(self, path: str) -> dict[str, dict]:
        """Build action_name -> metadata index from Phase 1 output."""
        try:
            with open(path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to load Phase 1 metadata: {e}")
            return {}

        index = {}
        for action in data.get("actions", []):
            name = action.get("name", "").lower()
            if name:
                index[name] = {
                    "command_template": action.get("command_template", ""),
                    "source_utility": action.get("source_utility", ""),
                    "parameters": action.get("parameters", []),
                    "requires_root": action.get("requires_root", False),
                }
        return index

    def _try_phase1_template(
        self, action_name: str, normalized_bindings: dict
    ) -> Optional[str]:
        """Try to concretize using Phase 1 command template."""
        meta = self._phase1_index.get(action_name)
        if not meta or not meta.get("command_template"):
            return None

        template = meta["command_template"]
        placeholders = re.findall(r"\{(\w+)\}", template)

        if not placeholders:
            return template  # Fixed command like "apt-get update"

        # Substitute using normalized bindings (name match + canonical lookup)
        result = template
        unfilled = []
        for ph in placeholders:
            if ph in normalized_bindings:
                result = result.replace(f"{{{ph}}}", normalized_bindings[ph])
            else:
                # Try canonical form: {src} → KEY_MAPPINGS["src"] = "source" → bindings["source"]
                canonical = self._KEY_MAPPINGS.get(ph, ph)
                if canonical != ph and canonical in normalized_bindings:
                    result = result.replace(f"{{{ph}}}", normalized_bindings[canonical])
                else:
                    unfilled.append(ph)

        if not unfilled:
            return result

        # No positional fallback — unfilled placeholders mean this template
        # doesn't match the PDDL parameter names → fall through to LLM
        logger.debug(
            f"Phase 1 template mismatch for {action_name}: "
            f"unfilled={unfilled}, bindings={list(normalized_bindings.keys())}"
        )
        return None

    # ─── Tier 2: LLM Concretization ─────────────────────────────────

    def _try_llm_concretize(
        self,
        action_name: str,
        action: GroundedAction,
        normalized_bindings: dict,
    ) -> Optional[str]:
        """Use LLM to generate a bash command for this action."""
        if not self._llm:
            return None

        prompt = self._build_llm_prompt(action_name, action, normalized_bindings)

        try:
            response = self._llm.chat.completions.create(
                model=self._llm_model,
                messages=[
                    {"role": "system", "content": CONCRETIZE_SYSTEM_MSG},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=self._llm_max_tokens,
                temperature=self._llm_temperature,
            )

            content = None
            if response.choices:
                content = getattr(response.choices[0].message, "content", None)

            if not content:
                logger.debug(f"LLM returned empty for concretize({action_name})")
                return None

            command = self._clean_llm_response(content)
            logger.debug(
                f"LLM raw for {action_name}: {content[:150]!r} → cleaned: {command!r}"
            )
            if self._validate_command(command):
                return command

            logger.info(
                f"LLM command failed validation for {action_name}: {command[:100]!r}"
            )
            return None

        except Exception as e:
            logger.warning(f"LLM concretization failed for {action_name}: {e}")
            return None

    def _build_llm_prompt(
        self,
        action_name: str,
        action: GroundedAction,
        normalized_bindings: dict,
    ) -> str:
        """Build a constrained prompt for LLM concretization."""
        parts = [f"Action: {action_name}"]

        # Parameters with types
        if action.action.parameters:
            if isinstance(action.action.parameters[0], (list, tuple)):
                params_str = ", ".join(
                    f"{p[0].lstrip('?')} (type: {p[1]})"
                    for p in action.action.parameters
                )
            else:
                params_str = ", ".join(str(p) for p in action.action.parameters)
            parts.append(f"Parameters: {params_str}")

        # Current bindings with real values
        if normalized_bindings:
            bindings_str = ", ".join(
                f"{k}={v}" for k, v in normalized_bindings.items()
            )
            parts.append(f"Current values: {bindings_str}")

        # Phase 1 context if available (source utility is very helpful)
        meta = self._phase1_index.get(action_name)
        if meta:
            if meta.get("source_utility"):
                parts.append(f"Source utility: {meta['source_utility']}")
            if meta.get("command_template"):
                parts.append(
                    f"Partial template: {meta['command_template']}"
                )

        # PDDL effects help the LLM understand intent
        if action.action.effects:
            effects = action.action.effects[:5]
            parts.append(f"Expected effects: {', '.join(effects)}")

        parts.append(
            "\nOutput ONLY the bash command with actual values filled in. "
            "Do NOT use placeholders. Use the concrete values provided above."
        )

        return "\n".join(parts)

    def _clean_llm_response(self, content: str) -> str:
        """Clean LLM response: strip thinking tags, markdown, whitespace."""
        content = content.strip()
        # Strip thinking tags (Qwen3, DeepSeek-R1)
        content = re.sub(r"<think>.*?</think>\s*", "", content, flags=re.DOTALL)
        # Strip markdown fences
        content = re.sub(r"^```\w*\s*\n?", "", content)
        content = re.sub(r"\n?\s*```\s*$", "", content)
        content = content.strip()
        # Take first non-empty line only
        for line in content.split("\n"):
            line = line.strip()
            if line:
                return line
        return ""

    def _validate_command(self, command: str) -> bool:
        """Validate LLM-generated command for safety and format."""
        if not command or not command.strip():
            return False
        command = command.strip()
        if len(command) > 512:
            return False
        if command == "true":
            return False
        # Reject obvious non-commands
        if command.startswith("#") or command.startswith("//"):
            return False
        return True

    # ─── Template / Cache Helpers ────────────────────────────────────

    def _fill_template(self, template: str, bindings: dict) -> Optional[str]:
        """Fill a cached template with binding values (name match only)."""
        result = template
        placeholders = re.findall(r"\{(\w+)\}", template)

        if not placeholders:
            return template  # Fixed command

        for ph in placeholders:
            if ph in bindings:
                result = result.replace(f"{{{ph}}}", bindings[ph])

        if "{" in result:
            return None  # Can't fill all placeholders — no positional fallback
        return result

    def _extract_template_form(self, concrete: str, bindings: dict) -> str:
        """
        Convert a concrete command back to template form for caching.

        E.g., "chage -M 90 root" with {days: "90", user: "root"}
              → "chage -M {days} {user}"
        """
        template = concrete
        # Sort by value length descending to avoid partial replacements
        for key, value in sorted(bindings.items(), key=lambda x: -len(x[1])):
            if value and value in template:
                template = template.replace(value, f"{{{key}}}", 1)
        return template

    def _load_cache(self, path: str) -> dict[str, str]:
        """Load cache from disk."""
        try:
            if Path(path).exists():
                with open(path) as f:
                    return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to load concretizer cache: {e}")
        return {}

    def _save_cache(self):
        """Save cache to disk."""
        if not self._cache_path:
            return
        try:
            Path(self._cache_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self._cache_path, "w") as f:
                json.dump(self._cache, f, indent=2)
        except OSError as e:
            logger.warning(f"Failed to save concretizer cache: {e}")


# ═════════════════════════════════════════════════════════════════════
# Effect Verifier (unchanged — verifies PDDL effects against Docker)
# ═════════════════════════════════════════════════════════════════════


class EffectVerifier:
    """
    Verifies that PDDL action effects match actual environment changes.

    Only verifies predicates that have entries in PREDICATE_CHECKS.
    Predicates without checks are skipped (not counted as match or mismatch).
    """

    def __init__(self, docker_executor):
        self.executor = docker_executor
        # Pre-compute: for each predicate template, extract named params in order
        self._template_params: dict[str, list[str]] = {}
        for pred_name, template in PREDICATE_CHECKS.items():
            params = re.findall(r"\{(\w+)\}", template)
            # Deduplicate while preserving order
            seen = set()
            ordered = []
            for p in params:
                if p not in seen:
                    seen.add(p)
                    ordered.append(p)
            self._template_params[pred_name] = ordered

    def verify_effects(
        self,
        action: GroundedAction,
        expected_effects: list[str],
    ) -> tuple[list[str], list[str]]:
        """
        Verify expected effects against actual environment state.

        Only checks predicates in PREDICATE_CHECKS. Unchecked predicates
        are skipped entirely — they don't count as matched or mismatched.

        Returns:
            (matched_effects, mismatched_effects)
        """
        matched = []
        mismatched = []

        for effect in expected_effects:
            is_negative = effect.strip().startswith("(not")
            predicate = self._extract_predicate(effect)

            if not predicate:
                continue

            pred_name = predicate[0]
            pred_args = predicate[1:]

            # Skip predicates we can't verify — they add no signal
            if pred_name not in PREDICATE_CHECKS:
                continue

            # Build named bindings matching the template's {param} keys
            template_params = self._template_params.get(pred_name, [])
            check_bindings = {}
            for i, arg in enumerate(pred_args):
                if arg.startswith("?"):
                    value = action.bindings.get(arg, arg)
                else:
                    value = arg
                # Convert PDDL object names to real values
                value = ActionConcretizer._object_to_value(value)
                # Map to the named template parameter
                if i < len(template_params):
                    check_bindings[template_params[i]] = value
                # Also add positional key as fallback
                check_bindings[f"arg{i}"] = value

            # Verify predicate in the real environment
            holds = self.executor.verify_predicate(pred_name, check_bindings)

            expected_to_hold = not is_negative
            if holds == expected_to_hold:
                matched.append(effect)
            else:
                mismatched.append(effect)

        return matched, mismatched

    def _extract_predicate(self, effect: str) -> Optional[list[str]]:
        """Extract predicate name and arguments from an effect expression."""
        effect = effect.strip()
        if effect.startswith("(not"):
            effect = effect[4:].strip().rstrip(")")

        match = re.match(r"\((\w+)([^)]*)\)", effect)
        if match:
            pred_name = match.group(1)
            args_str = match.group(2).strip()
            args = args_str.split() if args_str else []
            return [pred_name] + args

        return None
