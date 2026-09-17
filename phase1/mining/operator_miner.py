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

# The model reliably identifies the KIND of a parameter but names it with a
# natural synonym ("setting" for "setting_key", "value" for "value_token",
# "path"/"file" for a config path, etc). Rejecting those on a spelling
# technicality silently drops otherwise-sound operators (e.g. the nginx
# dotfile-deny block was lost to grounding-tag:{'setting'}). Canonicalize
# synonyms to the fixed ontology before the lint validates them.
_GROUNDING_ALIASES = {
    "setting": "setting_key", "setting_name": "setting_key",
    "directive": "setting_key", "key": "setting_key", "parameter": "setting_key",
    "option": "setting_key", "block": "value_token", "value": "value_token",
    "directive_block": "value_token", "content": "value_token",
    "path": "config_path", "config": "config_path", "config_file": "config_path",
    "conf_path": "config_path", "file_path": "config_path",
    "file": "audited_file", "target_file": "audited_file", "audit_file": "audited_file",
    "pkg": "package", "package_name": "package",
    "svc": "service", "daemon": "service", "unit": "service", "service_name": "service",
    "user": "account", "username": "account", "principal": "account", "uid": "account",
    "db_user": "db_principal", "dbuser": "db_principal", "grantee": "db_principal",
    "cap": "capability", "capabilities": "capability",
}


def _canonicalize_grounding(grounding: dict) -> dict:
    return {p: _GROUNDING_ALIASES.get(str(g).strip().lower(), str(g).strip().lower())
            for p, g in (grounding or {}).items()}


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
                 temperature: float = 0.1, max_tokens: int = 16000):
        # MiniMax-M2.7 (and peers) are REASONING models: <think> tokens are
        # billed against the SAME max_tokens budget as the answer. At 4096 the
        # model routinely spends the whole budget reasoning and emits zero JSON
        # (finish_reason='length', empty-after-</think>), silently dropping the
        # operator. Give the answer real headroom and retry with a larger budget
        # when the reply is truncated. This is why the miner produced no
        # operators for the config/insert-block scenarios.
        from openai import OpenAI
        self._client = OpenAI(base_url=base_url, api_key=api_key or "vllm")
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

    def json(self, system: str, user: str):
        # Escalate the token budget on truncation: reasoning length is not known
        # a priori, so a fixed cap can starve the JSON answer on verbose chains.
        for budget in (self.max_tokens, self.max_tokens * 2):
            try:
                r = self._client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "system", "content": system},
                              {"role": "user", "content": user}],
                    temperature=self.temperature, max_tokens=budget,
                )
                choice = r.choices[0]
                obj = _first_json(choice.message.content or "")
                if obj is not None:
                    return obj
                # No parseable JSON. If we were cut off mid-generation, a bigger
                # budget is the fix; otherwise a retry will not help.
                if getattr(choice, "finish_reason", None) != "length":
                    return None
            except Exception as e:  # noqa: BLE001
                return {"_error": str(e)[:200]}
        return None


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
        '"command_template": "<shell with {param} placeholders for the FILE '
        'PATH and SERVICE only; but for a config-directive or block-insertion '
        'operator you MUST write the CONCRETE remediation directive text '
        'literally (taken from the threat report), e.g. '
        '\\"grep -q \'location ~ /\\\\.\' {cfg} || echo \'location ~ /\\\\. { '
        'deny all; }\' >> {cfg}\\" -- the directive CONTENT is the fix and must '
        'be concrete; only the path/service are {params}>", '
        '"grounding": {"<param>": "<config_path|audited_file|package|service|'
        'db_principal|setting_key|value_token|account|capability>"}, '
        '"requires_root": true}\n'
        "HARD RULES: the positive effect predicate MUST NOT appear in "
        "preconditions (no STRIPS no-op). Effects MUST delete the vulnerable "
        "precondition. Template placeholders must be a subset of parameter "
        "names. Prefer a vocabulary predicate over a synonym. No prose. "
        "Only reference ?variables that are declared parameters (no free "
        "variables). CRITICAL: every argument inside a precondition/effect atom "
        "MUST be a ?variable -- NEVER a literal or bare constant. Write "
        "(setting_value_is ?k ?v), NEVER (setting_value_is dc_local_interfaces "
        "'0.0.0.0') and NEVER (enabled yes). Concrete values (0.0.0.0, no, the "
        "directive text) appear ONLY in command_template, never in the PDDL. "
        "For a package reinstall/upgrade, prefix the command with "
        "'apt-get update && ' so a stale/absent package index does not make it "
        "a silent no-op.\n"
        "GROUNDING maps each PARAMETER NAME to a CATEGORY from the fixed set "
        "{config_path, audited_file, package, service, db_principal, "
        "setting_key, value_token, account, capability}. It is the KIND of "
        "thing the parameter is, NOT a concrete value. Do NOT put real file "
        "PATHS or SERVICE names inline (those are {params} grounded at runtime); "
        "but the remediation DIRECTIVE TEXT itself (the config line/block being "
        "written, the SQL REVOKE, etc.) MUST be concrete in the template -- it "
        "is the fix, and it comes from the threat report, not from runtime.\n"
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
    # Canonicalize grounding-tag synonyms (setting->setting_key, value->value_token,
    # path->config_path, ...) so a natural-language tag is not rejected by the lint.
    if op.get("grounding"):
        op["grounding"] = _canonicalize_grounding(op["grounding"])
    # Infer a grounding tag for any parameter the model left ungrounded, from the
    # parameter's declared TYPE. The lint rejects an operator if any param lacks a
    # grounding ("param-missing-grounding"), which silently drops otherwise-sound
    # config-edit operators (e.g. samba). The type carries the KIND already, so
    # this is a mechanical completion, not a guess. General; no app specifics.
    _TYPE_TO_GROUNDING = {
        "file": "config_path", "service": "service", "package": "package",
        "dbuser": "db_principal", "account": "account", "setting": "setting_key",
        "value": "value_token", "capability": "capability", "object": "config_path",
    }
    grounding = op.get("grounding") or {}
    for p in (op.get("parameters") or []):
        nm = p.get("name") if isinstance(p, dict) else None
        if nm and nm not in grounding:
            grounding[nm] = _TYPE_TO_GROUNDING.get(
                str(p.get("type", "")).lower(), "value_token")
    op["grounding"] = grounding
    # Enforce `apt-get update &&` on package reinstall/upgrade commands: a stale
    # or absent package index silently makes apt a no-op (exit 0, nothing done).
    tmpl = op.get("command_template", "") or ""
    if intent.verb in ("reinstall_package", "upgrade_package") and \
            "apt-get" in tmpl and "apt-get update" not in tmpl:
        op["command_template"] = "apt-get update && " + tmpl
    # State-pair completion: the model reliably emits the remediated-state
    # POSITIVE effect but often forgets the paired DELETION of the vulnerable
    # precondition, which the soundness lint (correctly) rejects
    # ("effects-do-not-change-or-delete-vulnerable-precondition"). That drops an
    # otherwise-sound operator and forces problem-gen to fall back to a fictional
    # config edit. Mechanically complete the pair: if no effect deletes or
    # supersedes a precondition, add (not <vulnerable precondition>). Only the
    # vulnerable precondition is deleted -- benign CONTEXT preconditions
    # (file_exists, service_running, ...) are never negated -- so the repair
    # never removes a fact the operator still needs.
    _CONTEXT = {"file_exists", "file_writable", "config_file", "service_exists",
                "service_running", "service_installed", "package_installed",
                "is_file", "exists", "readable", "writable", "present"}
    pre = [p for p in (op.get("preconditions") or []) if isinstance(p, str) and p.strip()]
    eff = [e for e in (op.get("effects") or []) if isinstance(e, str) and e.strip()]
    neg_names = {_pred_name(e[e.lower().find("(not") + 4:])
                 for e in eff if e.strip().lower().startswith("(not")}
    pos_names = {_pred_name(e) for e in eff if not e.strip().lower().startswith("(not")}
    pre_names = {_pred_name(p) for p in pre}
    if not (pre_names & (neg_names | pos_names)):
        # no precondition is deleted or superseded -> add (not <vuln pre>) for
        # the first non-context precondition (the vulnerable-state atom).
        for p in pre:
            if _pred_name(p) and _pred_name(p) not in _CONTEXT:
                eff.append(f"(not {p.strip()})")
                op["effects"] = eff
                break
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
    # Reject LITERAL arguments in predicate atoms. Concrete values belong ONLY in
    # the command_template; a literal in a precondition/effect (e.g. quoted
    # `'0.0.0.0'`, or a bare constant `yes` used as an object) produces invalid
    # PDDL that FAILS the whole merged-domain validation -- discarding EVERY
    # operator for that scenario (samba/exim/bind mined None for exactly this).
    # Every atom argument must be a ?variable. General; protects the merge.
    for atom in pre + eff:
        inner = atom.strip()
        if inner.lower().startswith("(not"):
            inner = inner[inner.lower().find("(not") + 4:]
        toks = re.findall(r"[^()\s]+", inner)  # [pred, arg1, arg2, ...]
        for t in toks[1:]:
            if t == "-" or t.startswith("?"):
                continue
            return False, f"literal-in-predicate:{t[:20]}"
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

    # (vi) no DEAD parameters. The mirror of (v): a parameter declared but used
    # in no precondition and no effect still has to be bound for the operator to
    # ground, so if the problem declares no object of that type the operator has
    # ZERO groundings and its goal becomes unreachable. Fast Downward then emits
    # a proof of unsolvability, which reads as "no valid plan exists" when a
    # perfectly good plan does.
    #
    # Observed on ccdc-15: mined set_config_directive carried `?svc - service`,
    # referenced nowhere, against a problem declaring no service object. Adding
    # the object by hand yields the plan immediately. Also on
    # vulnhub set_postgresql_listen_address_localhost, same shape.
    #
    # A parameter that names nothing the operator reasons about is not carrying
    # meaning; dropping the operator is safer than emitting one that can never
    # fire, because the planner cannot tell the difference between an operator
    # with no groundings and one that does not exist.
    dead = {p for p in pnames if p and p not in used_vars}
    if dead:
        return False, f"dead-parameter-unused-in-pre-and-eff:{dead}"
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
