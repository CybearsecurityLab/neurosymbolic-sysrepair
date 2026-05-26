import hashlib
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Any

from phase1.common.config import get_base_predicates
from phase1.common.logger import log
from common.models import (
    LLMExtractionConfig,
    ActionSchema,
    PDDLType,
    ActionParameter,
)
from common.pddl_rules import PDDL_SYNTAX_GUIDE


def _infer_type_for_variable(var_name: str) -> PDDLType:
    """Infer the PDDL type of a variable from its name, matching sanitizer logic."""
    _TYPE_HINTS = {
        "p": PDDLType.PACKAGE, "pkg": PDDLType.PACKAGE, "package": PDDLType.PACKAGE,
        "s": PDDLType.SERVICE, "svc": PDDLType.SERVICE, "service": PDDLType.SERVICE,
        "u": PDDLType.USER, "user": PDDLType.USER,
        "g": PDDLType.GROUP, "group": PDDLType.GROUP,
        "f": PDDLType.FILE, "file": PDDLType.FILE, "src": PDDLType.FILE, "dst": PDDLType.FILE,
        "d": PDDLType.DIRECTORY, "dir": PDDLType.DIRECTORY,
        "port": PDDLType.PORT,
        "rule": PDDLType.FIREWALL_RULE,
        "proc": PDDLType.PROCESS, "process": PDDLType.PROCESS, "cmd": PDDLType.PROCESS,
        "cfg": PDDLType.CONFIG_FILE, "config": PDDLType.CONFIG_FILE,
        "iface": PDDLType.INTERFACE, "interface": PDDLType.INTERFACE,
        "repo": PDDLType.REPOSITORY, "repository": PDDLType.REPOSITORY,
    }
    # Try exact match first, then check if var_name contains a known hint
    lower = var_name.lower().rstrip("0123456789")
    if lower in _TYPE_HINTS:
        return _TYPE_HINTS[lower]
    for hint, pddl_type in _TYPE_HINTS.items():
        if hint in lower:
            return pddl_type
    return PDDLType.OBJECT


def _is_minimax_model(model_id: str) -> bool:
    """MiniMax models emit <think> reasoning + fenced JSON that defeats
    langextract's parser ordering. Other models don't, so the sanitizer
    is gated on this check."""
    return "minimax" in (model_id or "").lower()


_THINK_CLOSE_RE = re.compile(r"</think\s*>", re.IGNORECASE)
_THINK_OPEN_RE = re.compile(r"<think\s*>", re.IGNORECASE)
_FENCE_RE = re.compile(r"```(?:json|yaml)?\s*([\s\S]*?)```", re.IGNORECASE)
_CTRL_TOKEN_RE = re.compile(
    r"<\|?\s*(?:end_turn|begin(?:ning)?_of_sentence|end_of_sentence|eot_id|im_end|im_start)\s*\|?>",
    re.IGNORECASE,
)


def _sanitize_minimax_output(raw: str) -> str:
    """Strip <think> reasoning, markdown fences, and stray control tokens so
    only the JSON payload remains for langextract to parse.

    langextract strips fences *before* think-tags, so a ```json fence that
    follows a <think> block survives into json.loads(). We pre-clean here.
    """
    if not raw:
        return raw
    s = raw

    # 1. Drop reasoning. Prefer everything after the final </think>; if the
    #    block was never closed, keep whatever precedes the dangling <think>.
    m = None
    for m in _THINK_CLOSE_RE.finditer(s):
        pass
    if m:
        s = s[m.end():]
    elif _THINK_OPEN_RE.search(s):
        s = _THINK_OPEN_RE.split(s, 1)[0]

    # 2. Unwrap a ```json ... ``` (or bare ```) fence if present.
    fence = _FENCE_RE.search(s)
    if fence:
        s = fence.group(1)

    # 3. Remove leftover chat-template control tokens.
    s = _CTRL_TOKEN_RE.sub("", s).strip()

    # 4. Last resort: clip to the outermost JSON object/array.
    if s and s[0] not in "{[":
        starts = [i for i in (s.find("{"), s.find("[")) if i != -1]
        if starts:
            s = s[min(starts):]
    if s and s[-1] not in "}]":
        end = max(s.rfind("}"), s.rfind("]"))
        if end != -1:
            s = s[: end + 1]
    return s.strip()


class _SanitizingModel:
    """Wraps a langextract language model, cleaning each raw output before
    langextract's resolver parses it. Delegates everything else to the inner
    model. Only used for MiniMax (see _is_minimax_model)."""

    def __init__(self, inner):
        self._inner = inner

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def infer(self, batch_prompts, **kwargs):
        for batch in self._inner.infer(batch_prompts=batch_prompts, **kwargs):
            cleaned = []
            for scored in batch:
                if getattr(scored, "output", None):
                    scored = type(scored)(
                        score=scored.score,
                        output=_sanitize_minimax_output(scored.output),
                    )
                cleaned.append(scored)
            yield cleaned


class ManPageParser:
    """
    Hybrid action extractor combining regex patterns and LLM extraction.

    Uses langextract with Ollama for LLM-based extraction to capture
    actions that regex patterns might miss, then deduplicates results.
    """

    TARGET_UTILITIES = {
        "package_management": ["apt-get", "apt", "dpkg", "snap"],
        "service_management": ["systemctl", "journalctl"],
        "file_operations": ["cp", "mv", "rm", "chmod", "chown", "mkdir", "touch"],
        "network": ["iptables", "ip", "ss", "netstat"],
        "privilege": ["sudo", "su"],
        "user_management": ["useradd", "usermod", "userdel", "groupadd"],
    }

    PATTERNS = {
        "requires_root": [
            r"must be root",
            r"requires? (?:root|superuser)",
            r"only (?:root|superuser)",
            r"permission denied",
            r"EACCES",
        ],
        "precondition_indicators": [
            r"requires?\s+(.+?)(?:\.|,|$)",
            r"must (?:be|have|exist)\s+(.+?)(?:\.|,|$)",
            r"depends? on\s+(.+?)(?:\.|,|$)",
        ],
        "effect_indicators": [
            r"creates?\s+(.+?)(?:\.|,|$)",
            r"removes?\s+(.+?)(?:\.|,|$)",
            r"modif(?:y|ies)\s+(.+?)(?:\.|,|$)",
            r"starts?\s+(.+?)(?:\.|,|$)",
            r"stops?\s+(.+?)(?:\.|,|$)",
        ],
    }

    # LLM extraction prompt template
    LLM_EXTRACTION_PROMPT = """
Extract system administration actions from this man page documentation.
For each action, identify:
1. action_name: A snake_case name for the action (e.g., install_package, start_service)
2. parameters: List of parameters with their types (package, service, user, group, file, directory, port, interface, firewall_rule, process)
3. preconditions: What must be true before the action can execute
4. effects: What changes after the action executes
5. command_template: The shell command pattern
6. requires_root: Whether sudo/root is needed (true/false)

Focus on actions that modify system state (install, remove, start, stop, create, delete, modify).
Skip read-only or query commands.
"""

    # Examples for few-shot learning with langextract
    LLM_EXTRACTION_EXAMPLES = [
        {
            "input": "apt-get install - Install packages. Requires network access. Must be run as root.",
            "output": {
                "actions": [
                    {
                        "action_name": "install_package",
                        "parameters": [{"name": "pkg", "type": "package"}],
                        "preconditions": ["package not installed", "network available"],
                        "effects": ["package installed"],
                        "command_template": "apt-get install -y {pkg}",
                        "requires_root": True,
                    }
                ]
            },
        },
        {
            "input": "systemctl start <service> - Start a systemd service. Service must exist.",
            "output": {
                "actions": [
                    {
                        "action_name": "start_service",
                        "parameters": [{"name": "svc", "type": "service"}],
                        "preconditions": ["service exists", "service not running"],
                        "effects": ["service running"],
                        "command_template": "systemctl start {svc}",
                        "requires_root": True,
                    }
                ]
            },
        },
    ]

    def __init__(
        self,
        llm_config: Optional[LLMExtractionConfig] = None,
        known_predicates: Optional[list[str]] = None,
        shell=None,
    ):
        self.cached_manpages: dict[str, str] = {}
        self.detected_variants: dict[str, str] = {}
        self.llm_config = llm_config or LLMExtractionConfig()
        self._llm_available = self._check_llm_availability()
        self.examples = self._build_examples()  # Build LangExtract objects
        self.known_predicates = known_predicates or get_base_predicates()
        # Shell runner: defaults to the host (legacy). Pass a ContainerShellRunner
        # to fetch man pages / --help from inside a scenario container.
        if shell is None:
            from common.shell import HostShellRunner
            shell = HostShellRunner()
        self.shell = shell

    def _check_llm_availability(self) -> bool:
        """Check if LLM server is available via OpenAI-compatible API."""
        if not self.llm_config.enabled:
            return False

        try:
            import langextract
        except ImportError:
            log("  LLM: langextract not installed (pip install langextract)")
            return False

        # Only probe /health for local vLLM servers. Remote OpenAI-compatible
        # APIs (MiniMax, OpenAI, etc.) don't expose it.
        base_url = self.llm_config.model_url.replace("/v1", "")
        if "localhost" in base_url or "127.0.0.1" in base_url:
            try:
                import urllib.request
                urllib.request.urlopen(f"{base_url}/health", timeout=5)
            except Exception as e:
                log(f"  LLM extraction disabled: {e}")
                return False

        log(f"  LLM: Using model '{self.llm_config.model_id}' at {self.llm_config.model_url}")
        return True

    # 3. REPLACE _build_examples method
    def _build_examples(self):
        """Constructs lx.data.ExampleData objects for the LLM.

        CRITICAL: extraction_text MUST be an exact substring of text for proper alignment.
        """
        if not self._llm_available:
            return []
        import langextract as lx

        return [
            lx.data.ExampleData(
                text="apt-get install packages. Requires network access. Must be run as root.",
                extractions=[
                    lx.data.Extraction(
                        extraction_class="action",
                        extraction_text="install packages",  # Exact substring match
                        attributes={
                            "action_name": "install_package",
                            "parameters": "pkg:package",
                            "preconditions": "(not (package_installed ?pkg)), (network_available)",
                            "effects": "(package_installed ?pkg)",
                            "command_template": "apt-get install -y {pkg}",
                            "requires_root": "true",
                        },
                    )
                ],
            ),
            lx.data.ExampleData(
                text="systemctl start service. Start a systemd service. Service must exist.",
                extractions=[
                    lx.data.Extraction(
                        extraction_class="action",
                        extraction_text="start service",  # Exact substring match
                        attributes={
                            "action_name": "start_service",
                            "parameters": "svc:service",
                            "preconditions": "(service_exists ?svc), (not (service_running ?svc))",
                            "effects": "(service_running ?svc)",
                            "command_template": "systemctl start {svc}",
                            "requires_root": "true",
                        },
                    )
                ],
            ),
            lx.data.ExampleData(
                text="chmod changes file permissions to make it executable.",
                extractions=[
                    lx.data.Extraction(
                        extraction_class="action",
                        extraction_text="changes file permissions",  # Exact substring match
                        attributes={
                            "action_name": "change_permissions",
                            "parameters": "f:file",
                            "preconditions": "(file_exists ?f)",
                            "effects": "(file_executable ?f)",
                            "command_template": "chmod {mode} {f}",
                            "requires_root": "false",
                        },
                    )
                ],
            ),
        ]

    # 4. REPLACE _extract_with_llm method
    def _extract_with_llm(self, utility: str, text: str) -> list[ActionSchema]:
        """Extract actions using langextract with OpenAI-compatible API (vLLM)."""
        if not self._llm_available:
            return []

        try:
            import langextract as lx
            from langextract.factory import ModelConfig

            log(f"    [DEBUG] {utility}: Sending {len(text)} chars to LLM...")

            # 2. BUILD PROMPT - Simpler, more explicit guidance
            prompt = f"""
You are an expert PDDL 3.1 domain modeler. Extract system administration actions from the text below.

{PDDL_SYNTAX_GUIDE}

VOCABULARY PREFERENCE:
The following predicates already exist in the system. USE THEM if applicable:
{self._format_predicates(self.known_predicates)}

INSTRUCTION:
1. If an action affects a known predicate, use it.
2. If an action requires a NEW concept (e.g., "masking" a service), INVENT a new predicate following the Naming Conventions rules above.
3. Extract actions with their preconditions and effects.

OUTPUT FORMAT (strict):
Each extraction must be a JSON object with exactly these keys:
  "action": A SHORT PLAIN-TEXT STRING copied verbatim from the source text that describes the action (e.g., "install packages", "start service"). This MUST be a simple string, NEVER a dict, list, or object.
  "action_attributes": A dict/object with these string-valued keys:
     - "action_name": snake_case string (e.g., "install_package", "start_service")
     - "parameters": comma-separated "name:type" string (types: package, service, user, group, file, directory, port, interface, firewall_rule, process)
     - "preconditions": PDDL predicates as a single string: "(pred1 ?x), (pred2 ?y)"
     - "effects": PDDL predicates as a single string: "(pred3 ?x)"
     - "command_template": shell command with {{var}} placeholders
     - "requires_root": "true" or "false"

CRITICAL RULES:
- The "action" value MUST be a plain string (a short phrase from the text), NOT a dict or list.
- The "action_attributes" value MUST be a dict with string key-value pairs, NOT a list.
- Extract only actions that modify system state (skip read-only/query commands)."""

            # 3. CONFIGURE MODEL via langextract's factory.
            # Using ModelConfig with explicit provider="openai" routes through
            # the OpenAI-compatible code path without GPT-specific auto-routing
            # (required for OpenAI-compatible servers like MiniMax / vLLM).
            # 0 means "no cap" — let reasoning models think as long as they need.
            provider_kwargs = {
                "api_key": self.llm_config.api_key,
                "base_url": self.llm_config.model_url,
                "temperature": self.llm_config.temperature,
            }
            cap = getattr(self.llm_config, "max_tokens", 0)
            if cap and cap > 0:
                provider_kwargs["max_tokens"] = cap

            model_config = ModelConfig(
                model_id=self.llm_config.model_id,
                provider="openai",
                provider_kwargs=provider_kwargs,
            )

            # 4. EXECUTE EXTRACTION
            extract_kwargs = dict(
                text_or_documents=text,
                prompt_description=prompt,
                examples=self.examples,
                show_progress=True,
                use_schema_constraints=False,
            )
            if _is_minimax_model(self.llm_config.model_id):
                # MiniMax wraps JSON in fences after a <think> block, which
                # langextract can't unwrap. Build the model ourselves and
                # wrap it so we sanitize raw output before parsing.
                from langextract.factory import create_model
                model = _SanitizingModel(create_model(model_config))
                result = lx.extract(model=model, **extract_kwargs)
            else:
                result = lx.extract(config=model_config, **extract_kwargs)

            # 5. DEBUG: Check what we got back
            if not result or not hasattr(result, "extractions"):
                log(f"    [DEBUG] {utility}: No result or no extractions attribute")
                return []

            if not result.extractions:
                log(f"    [DEBUG] {utility}: Result has empty extractions list")
                return []

            log(f"    [DEBUG] {utility}: Got {len(result.extractions)} raw extractions")

            # 1. PARSE RESULTS (Convert raw LLM output to ActionSchema objects)
            # We MUST call this first to get the ActionSchema objects
            raw_actions = self._parse_llm_result(result, utility)

            # 2. SANITIZE AND VALIDATE (Filter the ActionSchema objects)
            valid_actions = []
            for action in raw_actions:
                # Helper to remove artifacts like {user} or [file]
                def clean_str(s):
                    return re.sub(r"[{}[\]]", "", s).strip()

                # Apply cleanup
                action.preconditions = [clean_str(p) for p in action.preconditions]
                action.effects = [clean_str(e) for e in action.effects]

                # Auto-fix Unbound Variables: add missing params instead of dropping
                defined_vars = set()
                for param in action.parameters:
                    defined_vars.add(f"?{param.name}")

                # Also allow ?actor which is implicitly added later for root actions
                if action.requires_root:
                    defined_vars.add("?actor")

                is_valid = True
                for condition in action.preconditions + action.effects:
                    used_vars = re.findall(r"\?[a-zA-Z0-9_-]+", condition)
                    for var in used_vars:
                        if var not in defined_vars:
                            var_name = var.lstrip("?")
                            inferred_type = _infer_type_for_variable(var_name)
                            action.parameters.append(ActionParameter(var_name, inferred_type))
                            defined_vars.add(var)
                            log(
                                f"    [INFO] Auto-fixed action '{action.name}': added parameter ?{var_name} - {inferred_type.value}"
                            )

                # Filter out empty effects
                if not action.effects:
                    is_valid = False

                if is_valid:
                    valid_actions.append(action)

            return valid_actions

        except Exception as e:
            log(f"    [ERROR] LLM extraction failed for {utility}: {e}")
            return []

    def _parse_llm_result(self, result: Any, utility: str) -> list[ActionSchema]:
        """Convert AnnotatedDocument to ActionSchema."""
        actions = []
        if not result or not hasattr(result, "extractions"):
            return []

        for ext in result.extractions:
            try:
                # Validate attributes is a dict (LLM sometimes returns a list despite instructions)
                if not hasattr(ext, "attributes") or ext.attributes is None:
                    continue
                if not isinstance(ext.attributes, dict):
                    log(
                        f"    [WARNING] Skipping extraction with non-dict attributes: {type(ext.attributes)}"
                    )
                    continue

                attrs = ext.attributes

                # Parse Name
                name = (
                    attrs.get("action_name", "unknown_action")
                    .strip()
                    .replace(" ", "_")
                    .lower()
                )

                # Parse Parameters (expected format: "name:type")
                params = []
                param_str = attrs.get("parameters", "")
                if param_str:
                    # Handle comma separation if multiple
                    for p in param_str.split(","):
                        parts = p.strip().split(":")
                        if len(parts) == 2:
                            p_name, p_type = parts[0].strip(), parts[1].strip().lower()
                            # Map string type to Enum
                            pddl_type = getattr(PDDLType, p_type.upper(), PDDLType.FILE)
                            params.append(ActionParameter(p_name, pddl_type))

                if not params:
                    params = [ActionParameter("obj", PDDLType.FILE)]

                # Parse Preconditions/Effects (comma separated strings)
                preconditions = [
                    x.strip()
                    for x in attrs.get("preconditions", "").split(",")
                    if x.strip()
                ]
                effects = [
                    x.strip() for x in attrs.get("effects", "").split(",") if x.strip()
                ]

                # Root requirement
                requires_root = (
                    str(attrs.get("requires_root", "false")).lower() == "true"
                )
                command = attrs.get("command_template", f"{utility} {{args}}")

                # Normalize template placeholders to KEY_MAPPINGS-compatible names
                for p in params:
                    old_name = p.name
                    # The placeholder in the template should match the param name
                    # Ensure it's in the template; if not, check if the type name is used instead
                    if f'{{{old_name}}}' not in command and f'{{{p.pddl_type.value}}}' in command:
                        command = command.replace(f'{{{p.pddl_type.value}}}', f'{{{old_name}}}')

                actions.append(
                    ActionSchema(
                        name=name,
                        parameters=params,
                        preconditions=preconditions,
                        effects=effects,
                        command_template=command,
                        requires_root=requires_root,
                        source_utility=utility,
                        extraction_method="llm",
                    )
                )
            except Exception as e:
                log(f"    Failed to convert extraction: {e}")
                continue

        return actions

    def _compute_action_hash(self, action: ActionSchema) -> str:
        """Compute a hash for action deduplication based on semantic content."""
        # Normalize for comparison
        norm_name = action.name.lower().strip()
        norm_params = tuple(
            sorted((p.name, p.pddl_type.value) for p in action.parameters)
        )
        norm_preconds = tuple(sorted(p.lower().strip() for p in action.preconditions))
        norm_effects = tuple(sorted(e.lower().strip() for e in action.effects))

        content = f"{norm_name}|{norm_params}|{norm_preconds}|{norm_effects}"
        return hashlib.md5(content.encode()).hexdigest()

    def _convert_llm_action(self, raw: dict, utility: str) -> Optional[ActionSchema]:
        """Convert raw LLM output to ActionSchema."""
        if not isinstance(raw, dict):
            return None

        name = raw.get("action_name", "").strip()
        if not name:
            return None

        # Sanitize action name
        name = re.sub(r"[^a-zA-Z0-9_]", "_", name).lower()

        # Parse parameters
        parameters = []
        raw_params = raw.get("parameters", [])
        if isinstance(raw_params, list):
            for p in raw_params:
                if isinstance(p, dict):
                    param_name = p.get("name", "p")
                    param_type_str = p.get("type", "object").lower()

                    # Map to PDDLType
                    type_map = {
                        "package": PDDLType.PACKAGE,
                        "service": PDDLType.SERVICE,
                        "user": PDDLType.USER,
                        "group": PDDLType.GROUP,
                        "file": PDDLType.FILE,
                        "directory": PDDLType.DIRECTORY,
                        "config": PDDLType.CONFIG_FILE,
                        "configuration_file": PDDLType.CONFIG_FILE,
                        "port": PDDLType.PORT,
                        "interface": PDDLType.INTERFACE,
                        "firewall_rule": PDDLType.FIREWALL_RULE,
                        "process": PDDLType.PROCESS,
                    }
                    pddl_type = type_map.get(param_type_str, PDDLType.FILE)
                    parameters.append(ActionParameter(param_name, pddl_type))

        if not parameters:
            # Default parameter based on utility category
            parameters = [ActionParameter("obj", PDDLType.FILE)]

        # Parse preconditions
        preconditions = []
        raw_preconds = raw.get("preconditions", [])
        if isinstance(raw_preconds, list):
            for pre in raw_preconds:
                pddl_pre = self._convert_to_pddl_predicate(
                    pre, parameters, is_precondition=True
                )
                if pddl_pre:
                    preconditions.append(pddl_pre)

        # Parse effects
        effects = []
        raw_effects = raw.get("effects", [])
        if isinstance(raw_effects, list):
            for eff in raw_effects:
                pddl_eff = self._convert_to_pddl_predicate(
                    eff, parameters, is_precondition=False
                )
                if pddl_eff:
                    effects.append(pddl_eff)

        # Ensure we have at least one effect
        if not effects:
            effects = [f"(action_completed ?{parameters[0].name})"]

        return ActionSchema(
            name=name,
            parameters=parameters,
            preconditions=preconditions,
            effects=effects,
            command_template=raw.get("command_template", f"{utility} {{args}}"),
            requires_root=raw.get("requires_root", False),
            source_utility=utility,
            extraction_method="llm",
        )

    def _format_predicates(self, preds: list[str]) -> str:
        """Helper to format predicates for the LLM prompt."""
        if not preds:
            return "- (none known)"
        # deduplicate and sort
        unique = sorted(list(set(preds)))
        return "\n".join([f"- {p}" for p in unique])

    def _convert_to_pddl_predicate(
        self, text: str, params: list, is_precondition: bool
    ) -> Optional[str]:
        if not isinstance(text, str):
            return None

        # 1. Clean wrappers
        clean_text = text.strip("() ").lower()
        # 2. Handle {VAR} templates
        clean_text = re.sub(r"\{([^}]+)}", r"?\1", clean_text)

        parts = clean_text.split()
        if not parts:
            return None

        # 3. Merge non-variable parts to fix "no file modifications" -> "no_file_modifications"
        pred_parts = []
        args = []

        # The first token is always part of the name
        pred_parts.append(parts[0])

        for p in parts[1:]:
            if p.startswith("?"):
                args.append(p)
            else:
                pred_parts.append(p)

        final_name = "_".join(pred_parts)
        # 4. Remove illegal characters
        final_name = re.sub(r"[^a-z0-9_-]", "_", final_name)

        return f"({final_name} {' '.join(args)})"

    def fetch_manpage(self, utility: str) -> Optional[str]:
        if utility in self.cached_manpages:
            return self.cached_manpages[utility]
        try:
            res = self.shell.run(f"man {utility} 2>/dev/null | col -b", timeout=30)
            if res.ok and res.stdout:
                self.cached_manpages[utility] = res.stdout
                self._detect_variants(utility, res.stdout)
                return res.stdout
        except Exception:
            pass
        return None

    def _detect_variants(self, utility: str, content: str):
        if utility == "sudo" and "sudo-rs" in content.lower():
            self.detected_variants["sudo"] = "sudo-rs"
        if utility in ["cp", "mv", "rm", "ls"] and "uutils" in content.lower():
            self.detected_variants[utility] = "uutils"

    def fetch_help_output(self, utility: str) -> Optional[str]:
        try:
            cmd = f"{utility} help --all" if utility == "snap" else f"{utility} --help"
            res = self.shell.run(cmd, timeout=10)
            return res.stdout or res.stderr
        except Exception:
            return None

    def extract_actions_from_utility(self, utility: str) -> list[ActionSchema]:
        all_actions = []
        manpage = self.fetch_manpage(utility)
        help_text = self.fetch_help_output(utility)
        combined_text = (manpage or "") + "\n" + (help_text or "")

        if not combined_text.strip():
            return []

        requires_root = any(
            re.search(p, combined_text, re.IGNORECASE)
            for p in self.PATTERNS["requires_root"]
        )

        # Regex Phase
        regex_actions = self._extract_with_regex(utility, combined_text, requires_root)
        for a in regex_actions:
            a.extraction_method = "regex"
        all_actions.extend(regex_actions)

        # LLM Phase
        if self._llm_available:
            llm_actions = self._extract_with_llm(utility, combined_text)
            all_actions.extend(llm_actions)

        return self._deduplicate_actions(all_actions)

    def _deduplicate_actions(self, actions: list) -> list:
        """
        Deduplicate actions and filter out invalid ones.
        """
        STOP_PREFIXES = {
            "show",
            "list",
            "display",
            "print",
            "search",
            "query",
            "check",
            "verify",
            "help",
            "version",
            "info",
            "man",
            "debug",
            "verbose",
            "explain",
            "monitor",
            "watch",
            "get",
            "dump",
            "validate",
            "assess",
            "audit",
            "status",
            "compare",
            "report",
            "test",
            "find",
            "resolve",
            "assert",
        }

        TRIVIAL_EFFECT_SUBSTRINGS = [
            "displayed",
            "shown",
            "listed",
            "printed",
            "visible",
            "info_available",
            "help_shown",
            "version_shown",
        ]

        final_actions = {}

        for action in actions:
            # --- FILTER 1: Read-Only Name Check ---
            parts = action.name.split("_")
            verb = parts[0].lower() if parts else action.name.lower()
            if verb in STOP_PREFIXES:
                continue

            # --- FILTER 2: Empty Effects ---
            if not action.effects:
                continue

            # --- FILTER 3: Trivial Effects ---
            is_trivial = all(
                any(sub in eff.lower() for sub in TRIVIAL_EFFECT_SUBSTRINGS)
                for eff in action.effects
            )
            if is_trivial:
                continue

            # --- FILTER 4: Auto-fix Unbound Variables ---
            defined_vars = {f"?{p.name}" for p in action.parameters}
            if action.requires_root:
                defined_vars.add("?actor")

            for condition in action.preconditions + action.effects:
                used_vars = set(re.findall(r"\?[a-zA-Z0-9_-]+", condition))
                unbound = used_vars - defined_vars
                for var in unbound:
                    var_name = var.lstrip("?")
                    inferred_type = _infer_type_for_variable(var_name)
                    action.parameters.append(ActionParameter(var_name, inferred_type))
                    defined_vars.add(var)
                    log(
                        f"    [INFO] Auto-fixed '{action.name}': added parameter ?{var_name} - {inferred_type.value}"
                    )

            # --- FILTER 5: Raw Paths in Conditions (NEW) ---
            has_raw_path = False
            for condition in action.preconditions + action.effects:
                # Check for raw filesystem paths
                if re.search(
                    r"[^?]\s*/[a-zA-Z]", condition
                ) or condition.strip().startswith("/"):
                    log(
                        f"    [WARN] Dropping '{action.name}': contains raw path in condition"
                    )
                    has_raw_path = True
                    break

            if has_raw_path:
                continue

            # --- FILTER 6: Malformed Predicate Names ---
            has_malformed = False
            for eff in action.effects:
                match = re.match(r"\(?\s*(not\s+)?\(?\s*([a-zA-Z_][a-zA-Z0-9_-]*)", eff)
                if match:
                    pred_name = match.group(2)
                    if pred_name.startswith("?") or pred_name in ["and", "or", "not"]:
                        has_malformed = True
                        break

            if has_malformed:
                continue

            # --- Deduplication ---
            if action.name not in final_actions:
                final_actions[action.name] = action
            else:
                existing = final_actions[action.name]
                if (
                    existing.extraction_method == "llm"
                    and action.extraction_method == "regex"
                ):
                    final_actions[action.name] = action

        return list(final_actions.values())

    def extract_all_actions(self) -> list[ActionSchema]:
        """Main entry point for extraction.

        Uses parallel workers when max_workers > 1 for faster LLM extraction.
        """
        all_actions = []
        max_workers = self.llm_config.max_workers
        log(f"  LLM extraction: {'enabled' if self._llm_available else 'disabled'}")
        if max_workers > 1:
            log(f"  Parallel workers: {max_workers}")

        # Flatten utilities list with their categories for parallel processing
        utility_tasks = []
        for category, utilities in self.TARGET_UTILITIES.items():
            for utility in utilities:
                utility_tasks.append((category, utility))

        if max_workers > 1 and self._llm_available:
            # Parallel extraction
            all_actions = self._extract_parallel(utility_tasks, max_workers)
        else:
            # Sequential extraction (original behavior)
            for category, utility in utility_tasks:
                try:
                    actions = self.extract_actions_from_utility(utility)
                    all_actions.extend(actions)
                    regex_c = sum(1 for a in actions if a.extraction_method == "regex")
                    llm_c = sum(1 for a in actions if a.extraction_method == "llm")
                    log(
                        f"    {utility}: {len(actions)} actions (regex:{regex_c}, llm:{llm_c})"
                    )
                except Exception as e:
                    log(f"    {utility}: FAILED - {e}")

        return self._deduplicate_actions(all_actions)

    def _extract_parallel(
        self, utility_tasks: list[tuple[str, str]], max_workers: int
    ) -> list[ActionSchema]:
        """Extract actions from utilities in parallel using ThreadPoolExecutor.

        Args:
            utility_tasks: List of (category, utility) tuples
            max_workers: Number of parallel workers

        Returns:
            List of extracted ActionSchema objects
        """
        all_actions = []
        current_category = None

        def extract_task(task: tuple[str, str]) -> tuple[str, str, list[ActionSchema], Optional[str]]:
            """Worker function for parallel extraction."""
            category, utility = task
            try:
                actions = self.extract_actions_from_utility(utility)
                return (category, utility, actions, None)
            except Exception as e:
                return (category, utility, [], str(e))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_task = {
                executor.submit(extract_task, task): task for task in utility_tasks
            }

            # Process results as they complete
            for future in as_completed(future_to_task):
                category, utility, actions, error = future.result()

                # Log category header if changed
                if category != current_category:
                    log(f"\n  Processing {category}...")
                    current_category = category

                if error:
                    log(f"    {utility}: FAILED - {error}")
                else:
                    all_actions.extend(actions)
                    regex_c = sum(1 for a in actions if a.extraction_method == "regex")
                    llm_c = sum(1 for a in actions if a.extraction_method == "llm")
                    log(
                        f"    {utility}: {len(actions)} actions (regex:{regex_c}, llm:{llm_c})"
                    )

        return all_actions

    def _extract_with_regex(
        self, utility: str, text: str, requires_root: bool
    ) -> list[ActionSchema]:
        """Original regex-based extraction (preserved from original code)."""
        actions = []

        # Route to specific extractors based on utility
        if utility in ["apt-get", "apt"]:
            actions.extend(self._extract_apt_actions(text, requires_root))
        elif utility == "dpkg":
            actions.extend(self._extract_dpkg_actions(text, requires_root))
        elif utility == "snap":
            actions.extend(self._extract_snap_actions(text, requires_root))
        elif utility == "systemctl":
            actions.extend(self._extract_systemctl_actions(text, requires_root))
        elif utility in ["cp", "mv", "rm", "chmod", "chown"]:
            actions.extend(self._extract_file_actions(utility, text, requires_root))
        elif utility in ["mkdir", "touch"]:
            actions.extend(self._extract_create_actions(utility, text, requires_root))
        elif utility == "iptables":
            actions.extend(self._extract_iptables_actions(text, requires_root))
        elif utility == "ip":
            actions.extend(self._extract_ip_actions(text, requires_root))
        elif utility == "sudo":
            actions.extend(self._extract_sudo_actions(text))
        elif utility in ["useradd", "usermod", "userdel"]:
            actions.extend(self._extract_user_actions(utility, text, requires_root))
        elif utility == "groupadd":
            actions.extend(self._extract_group_actions(text, requires_root))

        return actions

    # Include all the original _extract_* methods from the original ManPageParser
    # (apt, dpkg, snap, systemctl, file, create, iptables, ip, sudo, user, group)
    # These are preserved exactly as in the original implementation

    def _extract_apt_actions(
        self, text: str, requires_root: bool
    ) -> list[ActionSchema]:
        """Extract package management actions."""
        return [
            ActionSchema(
                name="install_package",
                parameters=[ActionParameter("pkg", PDDLType.PACKAGE)],
                preconditions=["(not (package_installed ?pkg))", "(network_available)"],
                effects=["(package_installed ?pkg)"],
                command_template="apt-get install -y {pkg}",
                requires_root=True,
                source_utility="apt-get",
            ),
            ActionSchema(
                name="remove_package",
                parameters=[ActionParameter("pkg", PDDLType.PACKAGE)],
                preconditions=["(package_installed ?pkg)"],
                effects=["(not (package_installed ?pkg))"],
                command_template="apt-get remove -y {pkg}",
                requires_root=True,
                source_utility="apt-get",
            ),
            ActionSchema(
                name="update_package",
                parameters=[ActionParameter("pkg", PDDLType.PACKAGE)],
                preconditions=["(package_installed ?pkg)", "(network_available)"],
                effects=["(not (package_outdated ?pkg))", "(not (vulnerable ?pkg))"],
                command_template="apt-get install --only-upgrade -y {pkg}",
                requires_root=True,
                source_utility="apt-get",
            ),
        ]

    def _extract_dpkg_actions(
        self, text: str, requires_root: bool
    ) -> list[ActionSchema]:
        return [
            ActionSchema(
                name="install_local_package",
                parameters=[
                    ActionParameter("pkg", PDDLType.PACKAGE),
                    ActionParameter("deb_file", PDDLType.FILE),
                ],
                preconditions=[
                    "(not (package_installed ?pkg))",
                    "(file_exists ?deb_file)",
                ],
                effects=["(package_installed ?pkg)"],
                command_template="dpkg -i {deb_file}",
                requires_root=True,
                source_utility="dpkg",
            ),
            ActionSchema(
                name="configure_package",
                parameters=[ActionParameter("pkg", PDDLType.PACKAGE)],
                preconditions=["(package_installed ?pkg)"],
                effects=["(package_configured ?pkg)"],
                command_template="dpkg --configure {pkg}",
                requires_root=True,
                source_utility="dpkg",
            ),
        ]

    def _extract_snap_actions(
        self, text: str, requires_root: bool
    ) -> list[ActionSchema]:
        return [
            ActionSchema(
                name="install_snap",
                parameters=[ActionParameter("pkg", PDDLType.PACKAGE)],
                preconditions=["(not (package_installed ?pkg))", "(network_available)"],
                effects=["(package_installed ?pkg)"],
                command_template="snap install {pkg}",
                requires_root=True,
                source_utility="snap",
            ),
            ActionSchema(
                name="remove_snap",
                parameters=[ActionParameter("pkg", PDDLType.PACKAGE)],
                preconditions=["(package_installed ?pkg)"],
                effects=["(not (package_installed ?pkg))"],
                command_template="snap remove {pkg}",
                requires_root=True,
                source_utility="snap",
            ),
            ActionSchema(
                name="refresh_snap",
                parameters=[ActionParameter("pkg", PDDLType.PACKAGE)],
                preconditions=["(package_installed ?pkg)", "(network_available)"],
                effects=["(not (package_outdated ?pkg))"],
                command_template="snap refresh {pkg}",
                requires_root=True,
                source_utility="snap",
            ),
            ActionSchema(
                name="revert_snap",
                parameters=[ActionParameter("pkg", PDDLType.PACKAGE)],
                preconditions=["(package_installed ?pkg)"],
                effects=["(package_reverted ?pkg)"],
                command_template="snap revert {pkg}",
                requires_root=True,
                source_utility="snap",
            ),
            ActionSchema(
                name="enable_snap",
                parameters=[ActionParameter("pkg", PDDLType.PACKAGE)],
                preconditions=[
                    "(package_installed ?pkg)",
                    "(not (package_enabled ?pkg))",
                ],
                effects=["(package_enabled ?pkg)"],
                command_template="snap enable {pkg}",
                requires_root=True,
                source_utility="snap",
            ),
            ActionSchema(
                name="disable_snap",
                parameters=[ActionParameter("pkg", PDDLType.PACKAGE)],
                preconditions=["(package_installed ?pkg)", "(package_enabled ?pkg)"],
                effects=["(not (package_enabled ?pkg))"],
                command_template="snap disable {pkg}",
                requires_root=True,
                source_utility="snap",
            ),
        ]

    def _extract_systemctl_actions(
        self, text: str, requires_root: bool
    ) -> list[ActionSchema]:
        return [
            ActionSchema(
                name="start_service",
                parameters=[ActionParameter("svc", PDDLType.SERVICE)],
                preconditions=["(service_exists ?svc)", "(not (service_running ?svc))"],
                effects=["(service_running ?svc)"],
                command_template="systemctl start {svc}",
                requires_root=True,
                source_utility="systemctl",
            ),
            ActionSchema(
                name="stop_service",
                parameters=[ActionParameter("svc", PDDLType.SERVICE)],
                preconditions=["(service_running ?svc)"],
                effects=["(not (service_running ?svc))"],
                command_template="systemctl stop {svc}",
                requires_root=True,
                source_utility="systemctl",
            ),
            ActionSchema(
                name="restart_service",
                parameters=[
                    ActionParameter("svc", PDDLType.SERVICE),
                    ActionParameter("cfg", PDDLType.CONFIG_FILE),
                ],
                preconditions=[
                    "(service_exists ?svc)",
                    "(configures ?cfg ?svc)",
                    "(file_exists ?cfg)",
                ],
                effects=["(service_running ?svc)", "(config_applied ?svc)"],
                command_template="systemctl restart {svc}",
                requires_root=True,
                source_utility="systemctl",
            ),
            ActionSchema(
                name="enable_service",
                parameters=[ActionParameter("svc", PDDLType.SERVICE)],
                preconditions=["(service_exists ?svc)"],
                effects=["(service_enabled ?svc)"],
                command_template="systemctl enable {svc}",
                requires_root=True,
                source_utility="systemctl",
            ),
            ActionSchema(
                name="disable_service",
                parameters=[ActionParameter("svc", PDDLType.SERVICE)],
                preconditions=["(service_enabled ?svc)"],
                effects=["(not (service_enabled ?svc))"],
                command_template="systemctl disable {svc}",
                requires_root=True,
                source_utility="systemctl",
            ),
        ]

    def _extract_file_actions(
        self, utility: str, text: str, requires_root: bool
    ) -> list[ActionSchema]:
        actions = []
        is_uutils = self.detected_variants.get(utility) == "uutils"
        suffix = f" ({'uutils' if is_uutils else 'coreutils'})"

        if utility == "cp":
            actions.append(
                ActionSchema(
                    name="copy_file",
                    parameters=[
                        ActionParameter("src", PDDLType.FILE),
                        ActionParameter("dst", PDDLType.FILE),
                    ],
                    preconditions=["(file_exists ?src)", "(not (file_exists ?dst))"],
                    effects=["(file_exists ?dst)"],
                    command_template="cp {src} {dst}",
                    requires_root=False,
                    source_utility=f"cp{suffix}",
                )
            )
        elif utility == "mv":
            actions.append(
                ActionSchema(
                    name="move_file",
                    parameters=[
                        ActionParameter("src", PDDLType.FILE),
                        ActionParameter("dst", PDDLType.FILE),
                    ],
                    preconditions=["(file_exists ?src)"],
                    effects=["(not (file_exists ?src))", "(file_exists ?dst)"],
                    command_template="mv {src} {dst}",
                    requires_root=False,
                    source_utility=f"mv{suffix}",
                )
            )
        elif utility == "rm":
            actions.append(
                ActionSchema(
                    name="delete_file",
                    parameters=[ActionParameter("f", PDDLType.FILE)],
                    preconditions=["(file_exists ?f)", "(not (file_critical ?f))"],
                    effects=["(not (file_exists ?f))"],
                    command_template="rm {f}",
                    requires_root=False,
                    source_utility=f"rm{suffix}",
                )
            )
        elif utility == "chmod":
            actions.append(
                ActionSchema(
                    name="change_permissions",
                    parameters=[ActionParameter("f", PDDLType.FILE)],
                    preconditions=["(file_exists ?f)"],
                    effects=["(file_writable ?f)"],
                    command_template="chmod {mode} {f}",
                    requires_root=False,
                    source_utility=f"chmod{suffix}",
                )
            )
        elif utility == "chown":
            actions.append(
                ActionSchema(
                    name="change_owner",
                    parameters=[
                        ActionParameter("f", PDDLType.FILE),
                        ActionParameter("u", PDDLType.USER),
                    ],
                    preconditions=["(file_exists ?f)", "(user_exists ?u)"],
                    effects=["(file_owned_by ?f ?u)"],
                    command_template="chown {u} {f}",
                    requires_root=True,
                    source_utility=f"chown{suffix}",
                )
            )
        return actions

    def _extract_create_actions(
        self, utility: str, text: str, requires_root: bool
    ) -> list[ActionSchema]:
        actions = []
        is_uutils = self.detected_variants.get(utility) == "uutils"
        suffix = f" ({'uutils' if is_uutils else 'coreutils'})"

        if utility == "mkdir":
            actions.append(
                ActionSchema(
                    name="create_directory",
                    parameters=[ActionParameter("d", PDDLType.DIRECTORY)],
                    preconditions=["(not (file_exists ?d))"],
                    effects=["(file_exists ?d)"],
                    command_template="mkdir -p {d}",
                    requires_root=False,
                    source_utility=f"mkdir{suffix}",
                )
            )
        elif utility == "touch":
            actions.append(
                ActionSchema(
                    name="create_file",
                    parameters=[ActionParameter("f", PDDLType.FILE)],
                    preconditions=["(not (file_exists ?f))"],
                    effects=["(file_exists ?f)"],
                    command_template="touch {f}",
                    requires_root=False,
                    source_utility=f"touch{suffix}",
                )
            )
        return actions

    def _extract_iptables_actions(
        self, text: str, requires_root: bool
    ) -> list[ActionSchema]:
        return [
            ActionSchema(
                name="block_traffic",
                parameters=[ActionParameter("rule", PDDLType.FIREWALL_RULE)],
                preconditions=["(not (firewall_rule_exists ?rule))"],
                effects=["(firewall_rule_exists ?rule)", "(traffic_blocked ?rule)"],
                command_template="iptables -A INPUT -s {src} -j DROP",
                requires_root=True,
                source_utility="iptables",
            ),
            ActionSchema(
                name="allow_traffic",
                parameters=[ActionParameter("rule", PDDLType.FIREWALL_RULE)],
                preconditions=["(traffic_blocked ?rule)"],
                effects=["(not (traffic_blocked ?rule))"],
                command_template="iptables -D INPUT -s {src} -j DROP",
                requires_root=True,
                source_utility="iptables",
            ),
            ActionSchema(
                name="open_port",
                parameters=[ActionParameter("p", PDDLType.PORT)],
                preconditions=["(not (port_allowed ?p))"],
                effects=["(port_allowed ?p)"],
                command_template="iptables -A INPUT -p tcp --dport {p} -j ACCEPT",
                requires_root=True,
                source_utility="iptables",
            ),
        ]

    def _extract_ip_actions(self, text: str, requires_root: bool) -> list[ActionSchema]:
        return [
            ActionSchema(
                name="enable_interface",
                parameters=[ActionParameter("iface", PDDLType.INTERFACE)],
                preconditions=[
                    "(interface_exists ?iface)",
                    "(not (interface_up ?iface))",
                ],
                effects=["(interface_up ?iface)"],
                command_template="ip link set {iface} up",
                requires_root=True,
                source_utility="ip",
            ),
            ActionSchema(
                name="disable_interface",
                parameters=[ActionParameter("iface", PDDLType.INTERFACE)],
                preconditions=["(interface_up ?iface)"],
                effects=["(not (interface_up ?iface))"],
                command_template="ip link set {iface} down",
                requires_root=True,
                source_utility="ip",
            ),
        ]

    def _extract_sudo_actions(self, text: str) -> list[ActionSchema]:
        is_sudo_rs = self.detected_variants.get("sudo") == "sudo-rs"
        preconditions = ["(user_exists ?u)", "(can_escalate ?u)"]
        if is_sudo_rs:
            preconditions.append("(not (requires_env_preservation ?cmd))")

        return [
            ActionSchema(
                name="execute_privileged",
                parameters=[
                    ActionParameter("u", PDDLType.USER),
                    ActionParameter("cmd", PDDLType.PROCESS),
                ],
                preconditions=preconditions,
                effects=["(executed_as_root ?cmd)"],
                command_template="sudo --reset-timestamp {cmd}"
                if is_sudo_rs
                else "sudo {cmd}",
                requires_root=False,
                source_utility="sudo-rs" if is_sudo_rs else "sudo",
            )
        ]

    def _extract_user_actions(
        self, utility: str, text: str, requires_root: bool
    ) -> list[ActionSchema]:
        actions = []
        if utility == "useradd":
            actions.append(
                ActionSchema(
                    name="create_user",
                    parameters=[ActionParameter("u", PDDLType.USER)],
                    preconditions=["(not (user_exists ?u))"],
                    effects=["(user_exists ?u)"],
                    command_template="useradd {u}",
                    requires_root=True,
                    source_utility="useradd",
                )
            )
        elif utility == "usermod":
            actions.extend(
                [
                    ActionSchema(
                        name="add_user_to_group",
                        parameters=[
                            ActionParameter("u", PDDLType.USER),
                            ActionParameter("g", PDDLType.GROUP),
                        ],
                        preconditions=[
                            "(user_exists ?u)",
                            "(group_exists ?g)",
                            "(not (member_of ?u ?g))",
                        ],
                        effects=["(member_of ?u ?g)"],
                        command_template="usermod -aG {g} {u}",
                        requires_root=True,
                        source_utility="usermod",
                    ),
                    ActionSchema(
                        name="lock_user",
                        parameters=[ActionParameter("u", PDDLType.USER)],
                        preconditions=["(user_exists ?u)", "(not (user_locked ?u))"],
                        effects=["(user_locked ?u)"],
                        command_template="usermod -L {u}",
                        requires_root=True,
                        source_utility="usermod",
                    ),
                    ActionSchema(
                        name="unlock_user",
                        parameters=[ActionParameter("u", PDDLType.USER)],
                        preconditions=["(user_exists ?u)", "(user_locked ?u)"],
                        effects=["(not (user_locked ?u))"],
                        command_template="usermod -U {u}",
                        requires_root=True,
                        source_utility="usermod",
                    ),
                ]
            )
        elif utility == "userdel":
            actions.append(
                ActionSchema(
                    name="delete_user",
                    parameters=[ActionParameter("u", PDDLType.USER)],
                    preconditions=["(user_exists ?u)", "(not (user_critical ?u))"],
                    effects=["(not (user_exists ?u))"],
                    command_template="userdel {u}",
                    requires_root=True,
                    source_utility="userdel",
                )
            )
        return actions

    def _extract_group_actions(
        self, text: str, requires_root: bool
    ) -> list[ActionSchema]:
        return [
            ActionSchema(
                name="create_group",
                parameters=[ActionParameter("g", PDDLType.GROUP)],
                preconditions=["(not (group_exists ?g))"],
                effects=["(group_exists ?g)"],
                command_template="groupadd {g}",
                requires_root=True,
                source_utility="groupadd",
            )
        ]


# Factory function to create the hybrid parser with configuration
def create_hybrid_parser(
    model_id: str = "gemma-4-31b",
    model_url: str = "http://localhost:8001/v1",
    api_key: str = "vllm",
    enable_llm: bool = True,
    temperature: float = 0.0,
    known_predicates: list[str] = None,
    max_workers: int = 1,
    shell=None,
) -> ManPageParser:
    """
    Create a HybridManPageParser with the specified configuration.

    Args:
        max_workers: Number of parallel LLM extraction workers.
                     Increase based on GPU count and model size.
        shell: Optional ShellRunner; when None, uses the host. Pass a
               ContainerShellRunner to fetch docs from inside a container.
    """
    config = LLMExtractionConfig(
        model_id=model_id,
        model_url=model_url,
        api_key=api_key,
        enabled=enable_llm,
        temperature=temperature,
        max_workers=max_workers,
    )
    return ManPageParser(
        llm_config=config,
        known_predicates=known_predicates,
        shell=shell,
    )
