"""Phase 1.5 — Remediation Operator Miner.

General, suite-agnostic discovery of the PDDL remediation OPERATORS a scenario
needs, mined from system knowledge rather than hand-authored. This is the
symmetric counterpart to Phase 1's introspection (which mines the STATE): here
we mine the ACTION theory of the repair domain.

Pipeline (per scenario, no scenario-id / suite / benchmark-tool hardcoding):
  1. intent extraction  — one LLM pass over the scenario's own threat report
     yields abstract RemediationIntents (verb from a fixed security-remediation
     ontology, object kind, vulnerable-state text, remediated-state text,
     candidate tools, named entities).
  2. tool confirmation  — `command -v` each candidate tool (+ ontology fallback
     tools per verb) in the live container; harvest its man/--help as evidence.
  3. operator extraction — one LLM pass per confirmed (intent, tool) emits an
     intent-level STRIPS operator in the state-pair pattern (vulnerable-state
     precondition -> remediated-state positive effect), a command_template, and
     per-parameter grounding tags.
  4. lint               — deterministic soundness gate (no STRIPS no-op, effects
     delete the vulnerable precondition, template placeholders subset params,
     every param grounded, state-pair naming).

The fixed verb ontology is general incident-response taxonomy (NIST SP 800-61 /
CIS), frozen before evaluation; the miner never reads verify.sh or scenario ids.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field


# Fixed remediation-primitive ontology (verb -> fallback tool families).
# General security-remediation taxonomy, identical across all suites, frozen
# before evaluation. Constrains operator SHAPE, never targets.
REMEDIATION_ONTOLOGY: dict[str, list[str]] = {
    "remove_permission":   ["chmod", "setfacl"],
    "restrict_access":     ["chmod", "setfacl", "chown"],
    "revoke_grant":        ["mysql", "psql"],
    "remove_config_line":  ["sed", "visudo"],
    "set_config_directive": ["sed", "augtool", "tee"],
    "insert_directive_block": ["tee", "sed"],
    "reinstall_package":   ["apt-get", "dnf", "apk", "yum"],
    "upgrade_package":     ["apt-get", "dnf", "apk", "yum"],
    "remove_capability":   ["setcap"],
    "disable_service":     ["systemctl", "service"],
    "remove_file":         ["rm"],
    "lock_account":        ["usermod", "passwd"],
    "rotate_credential":   ["mysql", "passwd", "chpasswd"],
}

_VALID_GROUNDINGS = {
    "config_path", "audited_file", "package", "service", "db_principal",
    "setting_key", "value_token", "account", "capability",
}


@dataclass
class RemediationIntent:
    verb: str
    object_kind: str
    vulnerable_state: str
    remediated_state: str
    tool_candidates: list[str] = field(default_factory=list)
    named_entities: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# LLM helper (OpenAI-compatible; MiniMax strips <think> to reasoning_content,
# but we defensively strip it here too).
# ---------------------------------------------------------------------------

def _strip_think(text: str) -> str:
    return re.sub(r"<think>[\s\S]*?</think>", "", text or "", flags=re.IGNORECASE)


def _first_json(text: str):
    """Extract the first balanced top-level JSON object/array from an LLM reply.

    Scans for whichever of `{`/`[` appears FIRST (so a nested `parameters: [...]`
    array is not mistaken for the whole object), then balances that bracket.
    """
    text = _strip_think(text)
    text = re.sub(r"```(?:json)?", "", text)
    # first top-level opener by position
    oi = text.find("{")
    ai = text.find("[")
    starts = [(p, o, c) for p, o, c in ((oi, "{", "}"), (ai, "[", "]")) if p >= 0]
    if not starts:
        return None
    starts.sort()
    for start_pos, opener, closer in starts:
        depth, start = 0, -1
        for i in range(start_pos, len(text)):
            ch = text[i]
            if ch == opener:
                if depth == 0:
                    start = i
                depth += 1
            elif ch == closer and depth:
                depth -= 1
                if depth == 0 and start >= 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except Exception:
                        break
    return None


class _LLM:
    """Minimal OpenAI-compatible chat client for the two mining passes."""

    def __init__(self, model: str, base_url: str, api_key: str,
                 temperature: float = 0.1, max_tokens: int = 4096):
        from openai import OpenAI
        self._client = OpenAI(base_url=base_url, api_key=api_key or "vllm")
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

    def json(self, system: str, user: str):
        try:
            r = self._client.chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content": user}],
                temperature=self.temperature, max_tokens=self.max_tokens,
            )
            return _first_json(r.choices[0].message.content or "")
        except Exception as e:  # noqa: BLE001
            return {"_error": str(e)[:200]}


# ---------------------------------------------------------------------------
# Step 1: intent extraction
# ---------------------------------------------------------------------------

_INTENT_SYSTEM = (
    "You extract abstract SYSTEM-remediation intents from a vulnerability report. "
    "A system-repair agent edits config files, changes permissions/ownership, runs "
    "admin CLI commands (mysql, chmod, setcap, apt, visudo), manages services and "
    "packages. It does NOT edit application source code. For each distinct "
    "remediation the report calls for, emit one intent."
)


def _intent_prompt(threat_text: str) -> str:
    verbs = ", ".join(sorted(REMEDIATION_ONTOLOGY))
    return (
        "Allowed verbs (choose the closest for each remediation):\n"
        f"  {verbs}\n\n"
        "Vulnerability report:\n"
        f"{threat_text[:4000]}\n\n"
        "Return STRICT JSON: a list of objects, each:\n"
        '{"verb": "<one allowed verb>", "object_kind": "<what it acts on, e.g. '
        'suid_file, php_directive, db_grant, sudo_rule, package>", '
        '"vulnerable_state": "<one clause describing the insecure state>", '
        '"remediated_state": "<one clause describing the fixed state>", '
        '"tool_candidates": ["<cli tools the report names or implies>"], '
        '"named_entities": {"paths": [], "packages": [], "db_user": "", '
        '"service": "", "setting": ""}}\n'
        "Only intents achievable by system-level actions. No prose."
    )


def extract_intents(threat_text: str, llm: _LLM) -> list[RemediationIntent]:
    data = llm.json(_INTENT_SYSTEM, _intent_prompt(threat_text))
    out: list[RemediationIntent] = []
    if not isinstance(data, list):
        return out
    for d in data:
        if not isinstance(d, dict):
            continue
        verb = str(d.get("verb", "")).strip()
        if verb not in REMEDIATION_ONTOLOGY:
            # snap to the nearest ontology verb by token overlap
            vt = set(re.split(r"[^a-z]+", verb.lower()))
            best = max(REMEDIATION_ONTOLOGY,
                       key=lambda k: len(vt & set(k.split("_"))), default="")
            if not (set(best.split("_")) & vt):
                continue
            verb = best
        out.append(RemediationIntent(
            verb=verb,
            object_kind=str(d.get("object_kind", "")).strip(),
            vulnerable_state=str(d.get("vulnerable_state", "")).strip(),
            remediated_state=str(d.get("remediated_state", "")).strip(),
            tool_candidates=[str(t) for t in (d.get("tool_candidates") or [])],
            named_entities=d.get("named_entities") or {},
        ))
    return out


# ---------------------------------------------------------------------------
# Step 2: tool confirmation + doc harvest
# ---------------------------------------------------------------------------

def confirm_tools(intent: RemediationIntent, shell) -> list[str]:
    """Return the intent's tools (named + ontology fallback) that exist in the
    container. `shell` is any object with .run(cmd)->(rc, out) OR callable(cmd)."""
    candidates = list(dict.fromkeys(
        [t for t in intent.tool_candidates if t] + REMEDIATION_ONTOLOGY[intent.verb]))
    present = []
    for tool in candidates:
        base = tool.split()[0]
        rc, _ = _sh(shell, f"command -v {base} >/dev/null 2>&1 && echo yes")
        if "yes" in (_[0] if isinstance(_, tuple) else _ or ""):
            present.append(base)
    return present


def _sh(shell, cmd):
    """Adapt to either shell.run(cmd)->(rc,out) or shell(cmd)->str."""
    try:
        if hasattr(shell, "run"):
            r = shell.run(cmd)
            if isinstance(r, tuple):
                return r[0], (r[1] if len(r) > 1 else "")
            return 0, str(r)
        out = shell(cmd)
        return 0, str(out)
    except Exception:
        return 1, ""


def harvest_doc(tool: str, shell) -> str:
    _, man = _sh(shell, f"man {tool} 2>/dev/null | col -bx 2>/dev/null | head -80")
    man = man if isinstance(man, str) else (man[0] if man else "")
    if len(man.strip()) < 40:
        _, hlp = _sh(shell, f"{tool} --help 2>&1 | head -40")
        man = hlp if isinstance(hlp, str) else (hlp[0] if hlp else "")
    return (man or "")[:2000]


# ---------------------------------------------------------------------------
# Step 3: intent-level operator extraction
# ---------------------------------------------------------------------------

_OP_SYSTEM = (
    "You mine ONE intent-level PDDL remediation operator in the STATE-PAIR "
    "pattern: a vulnerable-state precondition and a remediated-state positive "
    "effect. The operator is INTENT-level (remove_suid_bit, not chmod_file)."
)


def _op_prompt(intent: RemediationIntent, doc: str, vocabulary: list[str]) -> str:
    return (
        "REMEDIATION INTENT (authoritative for semantics):\n"
        f"  verb: {intent.verb}   object_kind: {intent.object_kind}\n"
        f"  vulnerable state: {intent.vulnerable_state}\n"
        f"  remediated state: {intent.remediated_state}\n"
        f"  named entities: {json.dumps(intent.named_entities)}\n\n"
        "TOOL EVIDENCE (authoritative for command syntax):\n"
        f"{doc[:1200]}\n\n"
        "SHARED VOCABULARY — reuse these predicate names when applicable:\n"
        f"  {', '.join(vocabulary[:120])}\n\n"
        "Emit STRICT JSON for ONE operator:\n"
        '{"name": "<snake_case, verb-first, intent-level>", '
        '"parameters": [{"name": "<short>", "type": "<file|service|package|'
        'dbuser|account|setting|value|object>"}], '
        '"preconditions": ["(<vulnerable_state_predicate> ?p)"], '
        '"effects": ["(<remediated_state_predicate> ?p)", '
        '"(not (<vulnerable_state_predicate> ?p))"], '
        '"command_template": "<shell with {param} placeholders, NO literal '
        'paths/names/values>", '
        '"grounding": {"<param>": "<config_path|audited_file|package|service|'
        'db_principal|setting_key|value_token|account|capability>"}, '
        '"requires_root": true}\n'
        "HARD RULES: the positive effect predicate MUST NOT appear in "
        "preconditions (no STRIPS no-op). Effects MUST delete the vulnerable "
        "precondition. Template placeholders must be a subset of parameter "
        "names. Prefer a vocabulary predicate over a synonym. No prose. "
        "Only reference ?variables that are declared parameters (no free "
        "variables). For a package reinstall/upgrade, prefix the command with "
        "'apt-get update && ' so a stale/absent package index does not make it "
        "a silent no-op.\n"
        "GROUNDING maps each PARAMETER NAME to a CATEGORY from the fixed set "
        "{config_path, audited_file, package, service, db_principal, "
        "setting_key, value_token, account, capability}. It is the KIND of "
        "thing the parameter is, NOT a concrete value. Do NOT put real paths, "
        "usernames, or values anywhere — those are grounded at runtime.\n"
        'EXAMPLE (SUID file): {"name":"remove_suid_bit","parameters":'
        '[{"name":"f","type":"file"}],"preconditions":["(has_suid ?f)"],'
        '"effects":["(suid_removed ?f)","(not (has_suid ?f))"],'
        '"command_template":"chmod u-s,g-s {f}",'
        '"grounding":{"f":"audited_file"},"requires_root":true}\n'
        'EXAMPLE (db grant): {"name":"revoke_db_privilege","parameters":'
        '[{"name":"u","type":"dbuser"}],"preconditions":["(db_overprivileged ?u)"],'
        '"effects":["(db_privilege_revoked ?u)","(not (db_overprivileged ?u))"],'
        '"command_template":"mysql -e \\"REVOKE ...\\"",'
        '"grounding":{"u":"db_principal"},"requires_root":true}'
    )


def mine_operator(intent: RemediationIntent, doc: str, vocabulary: list[str],
                  llm: _LLM) -> dict | None:
    op = llm.json(_OP_SYSTEM, _op_prompt(intent, doc, vocabulary))
    if not isinstance(op, dict) or "name" not in op:
        return None
    op["extraction_method"] = "mined"
    op["source_utility"] = op.get("source_utility", intent.verb)
    # Enforce `apt-get update &&` on package reinstall/upgrade commands: a stale
    # or absent package index silently makes apt a no-op (exit 0, nothing done).
    tmpl = op.get("command_template", "") or ""
    if intent.verb in ("reinstall_package", "upgrade_package") and \
            "apt-get" in tmpl and "apt-get update" not in tmpl:
        op["command_template"] = "apt-get update && " + tmpl
    return op


# ---------------------------------------------------------------------------
# Step 4: mechanical lint
# ---------------------------------------------------------------------------

def _pred_name(s: str) -> str:
    m = re.match(r"\(\s*(?:not\s*\()?\s*([A-Za-z_][\w-]*)", s.strip())
    return m.group(1) if m else ""


def lint_operator(op: dict) -> tuple[bool, str]:
    if not isinstance(op, dict):
        return False, "not-a-dict"
    name = op.get("name", "")
    if not re.match(r"^[a-z][a-z0-9_]*$", name or ""):
        return False, "bad-name"
    params = op.get("parameters") or []
    pnames = {p.get("name") for p in params if isinstance(p, dict)}
    if not params:
        return False, "no-params"
    pre = [p for p in (op.get("preconditions") or []) if p.strip()]
    eff = [e for e in (op.get("effects") or []) if e.strip()]
    if not pre or not eff:
        return False, "empty-pre-or-eff"
    pos_eff = [e for e in eff if not e.strip().lower().startswith("(not")]
    neg_eff = [e for e in eff if e.strip().lower().startswith("(not")]
    if not pos_eff:
        return False, "no-positive-effect"
    def _norm(s):  # normalize whitespace for full-atom comparison
        return re.sub(r"\s+", " ", s.strip().lstrip("(").rstrip(")")).strip()
    pre_atoms = {_norm(p) for p in pre}
    pos_atoms = {_norm(e) for e in pos_eff}
    # (i) no STRIPS no-op: a positive effect ATOM (predicate+args) identical to a
    # precondition atom is a no-op. A same-NAME effect with DIFFERENT args (e.g.
    # setting_value_is k vnew vs vold) is a legitimate value change, not a no-op.
    if pos_atoms & pre_atoms:
        return False, "noop-positive-effect-identical-to-precondition"
    # (ii) effects delete a vulnerable precondition: either a (not <pre-atom>)
    # OR a same-name effect that supersedes a precondition (value change).
    pre_names = {_pred_name(p) for p in pre}
    neg_inner = {_norm(e[e.lower().find("(not") + 4:]) for e in neg_eff}
    supersede = {_pred_name(e) for e in pos_eff} & pre_names
    if not (neg_inner & pre_atoms) and not supersede:
        return False, "effects-do-not-change-or-delete-vulnerable-precondition"
    # (iii) template placeholders subset of params
    tmpl = op.get("command_template", "") or ""
    ph = set(re.findall(r"\{(\w+)\}", tmpl))
    if tmpl and not ph.issubset(pnames):
        return False, f"template-placeholder-not-a-param:{ph - pnames}"
    # (iv) every param grounded
    grounding = op.get("grounding") or {}
    if any(p not in grounding for p in pnames):
        return False, "param-missing-grounding"
    if any(g not in _VALID_GROUNDINGS for g in grounding.values()):
        return False, f"bad-grounding-tag:{set(grounding.values()) - _VALID_GROUNDINGS}"
    # (v) variable closure: every ?var in preconditions/effects must be a
    # declared parameter. A free variable (e.g. ?s never in :parameters) aborts
    # Fast Downward's translator with exit 31 -> surfaces as a spurious NO_PLAN.
    used_vars = set(re.findall(r"\?([A-Za-z_]\w*)", " ".join(pre + eff)))
    free = used_vars - {p for p in pnames if p}
    if free:
        return False, f"free-variable-not-a-param:{free}"
    return True, "ok"


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def mine_operators(threat_text: str, shell, llm: _LLM,
                   vocabulary: list[str] | None = None,
                   log=print) -> dict:
    """Return {"actions": [op,...], "predicates": [str,...], "intents": [...],
    "rejected": [(name, reason),...]}. `vocabulary` seeds the shared predicate
    names (canonical + phase-1 base); mined predicates are appended as we go."""
    vocab = list(vocabulary or [])
    intents = extract_intents(threat_text, llm)
    log(f"  [miner] extracted {len(intents)} remediation intents")
    actions, predicates, rejected = [], [], []
    seen_names = set()
    for it in intents:
        tools = confirm_tools(it, shell)
        if not tools:
            log(f"  [miner] intent {it.verb}/{it.object_kind}: no tool in container")
            continue
        doc = harvest_doc(tools[0], shell)
        op = mine_operator(it, doc, vocab, llm)
        if not op:
            rejected.append((it.verb, "extraction-empty"))
            continue
        ok, reason = lint_operator(op)
        if not ok:
            rejected.append((op.get("name", it.verb), reason))
            log(f"  [miner] rejected {op.get('name')}: {reason}")
            continue
        if op["name"] in seen_names:
            continue
        seen_names.add(op["name"])
        actions.append(op)
        # collect new predicates into vocabulary + output
        for pe in (op.get("preconditions", []) + op.get("effects", [])):
            nm = _pred_name(pe)
            if nm and nm not in {_pred_name(v) for v in vocab} and nm != "not":
                # render a typed predicate decl from the param types
                ptypes = {p["name"]: p["type"] for p in op["parameters"]}
                m = re.match(r"\(\s*(?:not\s*\()?\s*[A-Za-z_][\w-]*\s+\?(\w+)", pe)
                pv = m.group(1) if m else None
                typ = ptypes.get(pv, "object") if pv else "object"
                decl = f"({nm} ?{pv or 'x'} - {typ})"
                predicates.append(decl)
                vocab.append(decl)
        log(f"  [miner] mined operator: {op['name']}  {[p['name'] for p in op['parameters']]}")
    return {"actions": actions, "predicates": predicates,
            "intents": [i.__dict__ for i in intents], "rejected": rejected}
