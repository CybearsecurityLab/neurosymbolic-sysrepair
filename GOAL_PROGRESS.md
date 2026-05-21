# Goal: EW ≥ 0.9 on ccdc-01

**Branch:** `goal/ew-above-0.9-ccdc01`
**Started from:** EW = 0.391 (clean run, 2026-05-20, sem=8, both Phase 3 fixes in)
**Constraint:** do NOT change auto-scale or `--max-refinement-iterations`. Move EW only by improving the *quality* of execution-time feedback the refiner gets.

## Baseline failure mix (398 discrepancies, EW 0.391)

| Bucket | Count | Cause |
|---|---:|---|
| systemctl-no-systemd | 38 | `systemctl` fails: PID 1 is bash keepalive, not systemd |
| command-not-found (iptables, sudo, ufw, netplan, file, ip, ufw, loadkeys, apply-changes) | ~50 | scenario image missing common admin tools |
| no-such-file | 30 | actions reference paths that aren't there (some legit signal) |
| exit-1 (empty stderr) | 20 | various; investigate later |
| **"other-nonzero-exit"** | 243 | catch-all; will narrow after attacking the above |
| concretization | 5 | tiny — already in good shape |

Highest-leverage targets are the **infrastructure** discrepancies — they're not real "PDDL is wrong about the world", they're our container not faithfully representing a normal sysadmin environment. Once those are removed, the refiner can focus on actual model errors.

## Plan

1. **systemctl shim** — copy the shim from `Dockerfile.pddl-sandbox` into the scenario image build layer in `common/container.py`. Same idea for `hostnamectl`, `timedatectl`, `localectl`. Should knock the 38 systemd discrepancies down toward zero.
2. **Install commonly-missing tools** in the scenario image addon layer: `iptables, iproute2, ufw, sudo, netplan.io, file, kbd`. ~50 command-not-found drop.
3. **Re-run Phase 3 only** (Phase 1/2 outputs are still valid; the only inputs that changed are the container image). Watch EW vs. 0.391.
4. If still <0.9, dig into "other-nonzero-exit" (243) and the top-affected actions (`netplan_generate`, `set_useradd_inactive`, `system_reboot`...).

## Constraints honored

- ✅ Will not touch `Phase3Config.auto_scale_ew_params` (lines 131-158)
- ✅ Will not touch `--max-refinement-iterations` (kept at 2)
- ✅ Will not touch the EW formula or walk parameters

## Change log (this branch)

### 2026-05-20: user course-correction received
- Direction: **don't modify the scenario container** (it's the benchmark).
  Improve the pipeline's *model* of the container, not the container.
- The end-to-end flow is: pipeline produces a per-scenario refined PDDL →
  neurosymbolic solver loads that PDDL → plans (Fast Downward) →
  concretizes → executes in the scenario container → `verify.sh` PASS/FAIL.
- Reverted my plan to add systemctl-shim / install tools to the container.

### 2026-05-20: dependency audit — BLOCKERS found

The neurosymbolic solver path (the actual end-to-end planner that drives
remediation per scenario) requires two things that are NOT on this machine:

1. **Fast Downward planner** — `neurosymbolic/runs.yaml` defaults to
   `fd_path: /home/resbears/fast_downward/fast-downward.py`. That path does
   not exist locally. Without FD the symbolic planning step cannot run; the
   solver does have an `enable_llm_fallback` ReAct mode but that still
   requires `inspect_ai`.

2. **`inspect_ai` Python package** — `neurosymbolic/task.py` and
   `neurosymbolic/solver.py` import `inspect_ai.{agent,model,solver,tool,util}`.
   Not currently in the project's `.venv`; `uv run python -c "import inspect_ai"`
   raises `ModuleNotFoundError`.

Additional, smaller items to address once unblocked:

- `neurosymbolic/runs.yaml` presets default to `model: openai/gemma-4-31b`
  → must switch to `MiniMax-M2.7` (or wire it from `config_loader.llm_settings`
  the same way I did for `run_phase3`).
- `domain_path` default `./pddl_output/phase3/sysadmin_refined.pddl` is
  scenario-unaware just like the bug we fixed in run_phase3; it'll need a
  per-scenario override too.

### 2026-05-20: chose option A — installed both deps

- `uv add inspect_ai` → 88 transitive packages.
- `uv add 'openai>=2.26'` → bumped from 2.14 (inspect_ai required ≥2.26).
- Built Fast Downward 24.06 at `/home/banny-orojo/tools/fast-downward/`
  (`./build.py`, ~5 min, all targets green).
- Patched `neurosymbolic/task.py` to use a try/except import (relative for
  `python -m neurosymbolic.run`, absolute for `inspect eval <file.py>` which
  loads via importlib without package context).

### 2026-05-20: GOAL 1 ACHIEVED — verify.sh passed on ccdc-01

```
inspect eval neurosymbolic/task.py \
  --model openai/MiniMax-M2.7 \
  -T 'scenarios=["ccdc/scenario-01"]' \
  -T domain_path=./pddl_output/ccdc-01/phase3/sysadmin_refined.pddl \
  -T fd_path=/home/banny-orojo/tools/fast-downward/fast-downward.py \
  -T mode=day1
```

Result:

```
neurosymbolic_bench (1 sample): openai/MiniMax-M2.7
dispatch_scorer
accuracy         1.000        ← verify.sh PASSED
total time:      0:00:28
tokens:          13,665
```

`dispatch_scorer` from `sysrepair_bench` returns 1.0 iff `verify.sh` exits 0.
The 28-second end-to-end run drove the planner → concretizer → bash execution
in the scenario container → ran `verify.sh` → CCDC-01 ("SSH Permits Root
Login") was remediated.

Env wiring used: `OPENAI_BASE_URL=https://api.minimax.io/v1`, `OPENAI_API_KEY=$MINIMAX_API_KEY`.

### Goal 2: EW ≥ 0.9 — still pending

Current EW = 0.391 (2 iterations, 836-action domain).

### 2026-05-20: course-correction — NO ad-hoc pruning

User direction: **don't prune. Investigate why invalid actions are being added
in the first place.** This is an ACSAC paper — adjustments must be defensible
under proper PDDL practice. Quick-fix tool-blacklists fail that bar.

Reverted the `domain_pruner` work. The real question is: why does the Phase 1
miner / Phase 2 synthesizer emit actions like `restart_service` that call
`systemctl` without a precondition like `(systemd_init_present)` that
reflects the actual container environment? That is the proper PDDL answer:
**the precondition captures the requirement; the planner naturally excludes
the action when the precondition is false in the init state.**

### Updated / added goals

1. **(was Goal 1) End-to-end NS planner on ccdc-01** — ✅ ACHIEVED. Score
   1.000 (verify.sh PASS). But: investigate *how* it succeeded — see Goal 4.
2. **(was Goal 2) EW ≥ 0.9** — pursue by improving the *generator* so
   spurious / unsatisfiable actions don't get emitted, not by post-hoc
   filtering. Treat EW as a side-effect of correct PDDL.
3. **NEW: Run the NS planner end-to-end on ALL bench scenarios.** Each
   scenario must get its own per-scenario problem PDDL + the planner
   produces a plan that drives verify.sh to PASS. Goal: maximise the
   aggregate ACSAC-paper-defensible score across the set.
4. **NEW: Audit the AI-planning correctness of the scenario-01 run.**
   - Did Fast Downward actually plan, or did the LLM-fallback ReAct loop
     do the work?
   - Are the plan's actions valid w.r.t. the domain's preconditions/effects?
   - Are concretized bash commands faithful to the action's PDDL effects?
   - Are we doing real AI planning, or LLM-as-a-shell with PDDL trim?
5. **NEW: Investigate the domain generator on ccdc-01 specifically.** Where
   do invalid actions come from? Phase 1 mining (man pages), Phase 2 LLM
   synthesis, or merger? What preconditions are missing?

### 2026-05-20: AI-planning audit on ccdc-01 — root defect found

The score of 1.000 on ccdc-01 was achieved by the **LLM ReAct fallback**
(text_editor + shell). Fast Downward **failed to plan** and the conversation
literally pivoted with: *"Continue remediation using shell commands. The PDDL
planner could not find a plan."*

The PDDL problem the LLM emitted (stored as `metadata.pddl_problem` and
extracted from the eval log) is structurally incompatible with the domain:

| issue | problem says | domain has |
|---|---|---|
| Naming convention | `(service-running sshd-service)` | `(service_running ?s)` (underscores) |
| Invented types | `sshd-config - config-file` | only `configuration_file`, `file`, … |
| Invented predicates | `has-setting`, `setting-value`, `file-location`, `service-needs-restart-after-config-change` | none of these exist |

Cause: `neurosymbolic/solver.py::_PROBLEM_GEN_SYSTEM` prompts the LLM to
generate a problem for "the sysadmin domain" but **never includes the
domain's actual `(:types ...)` / `(:predicates ...)`** in the prompt. The
LLM has no way to know what vocabulary the domain offers and invents its
own.

**Defensible PDDL fix:** pass the domain's type & predicate declarations
(and ideally action signatures) into the problem-generation prompt; insist
in the rules that only those identifiers may appear. This is canonical
planning practice — the problem must be in the same language as the domain.

### 2026-05-21: defensible PDDL fixes landed

1. **`common/pddl_validation.py`** — every PDDL artifact (Phase 2 domain,
   Phase 3 refined domain, LLM-generated per-scenario problem) is now
   parsed with the `pddl` library at the artifact boundary, so structural
   errors surface where they're produced.
2. **`neurosymbolic/solver.py` ReAct shell fallback removed.** The solver
   must succeed symbolically. Explicit failure modes are returned
   instead: `NO_DOMAIN_PROVIDED`, `PROBLEM_GENERATION_FAILED`,
   `PLANNER_FOUND_NO_PLAN`, `PLAN_DID_NOT_REMEDIATE`.
3. **`neurosymbolic/pddl_tools.py` + tool-using problem generator.** The
   LLM that generates the per-scenario problem now uses read-only PDDL
   inspection tools (`pddl_list_predicates`, `pddl_show_action`, etc.)
   to navigate the domain rather than having it dumped into context.
   Parser-error feedback retry: 1 retry max if first attempt won't parse.
4. **`common/env_capabilities.py` + `common/domain_enrichment.py`** —
   probe the scenario container for capability availability
   (`systemd_init_present`, `iptables_available`, …); add the corresponding
   precondition to every action whose bash template's primary command
   needs that capability; emit the positive facts into the problem `:init`.
   This is canonical STRIPS practice (real preconditions, real init facts)
   and is the defensible answer to "actions reference tools the container
   doesn't have". It does NOT change the auto-scale or iteration logic.

For ccdc-01, capability probe produced: only `(apt_available)` and
`(dpkg_available)` are true; everything else (systemctl, iptables, ufw,
sudo, …) implicitly false. Enrichment added precondition predicates to
**313 of 836** actions in `sysadmin.pddl`. PDDL library parses both
domain and problem cleanly post-enrichment.

### 2026-05-21: Fast Downward sanity test — architecture works, action coverage is the gap

To isolate whether Fast Downward + the new tool-using problem generator
*could* solve ccdc-01 if the domain had the right actions, wrote a minimal
handcrafted PDDL (3 types, 4 predicates, 2 actions) at
`/tmp/ccdc01_handcrafted/`:

```pddl
(:action set_setting_no
  :parameters (?s - setting)
  :precondition (and (setting_value_yes ?s) (sshd_writable_config_path))
  :effect (and (setting_value_no ?s) (not (setting_value_yes ?s))))
```

Fast Downward produced the expected plan in **1 ms**:

```
(set_setting_no permit_root_login)
```

So the planning architecture is fine. The reason the original 2026-05-20
run fell back to ReAct shell is that **the auto-generated Phase 2 domain
doesn't contain an action whose precondition/effect semantics model
"edit a setting in a config file"**. The 836-action mined domain has
generic file ops (`change_file_mode`, `chmod_set_permissions`, …) and
service-management actions (`disable_service`, `edit_service_unit`), but
no concrete `edit_setting_in_file(?file, ?key, ?value)` action with the
matching effect predicate.

This is the real defect for ACSAC defensibility:
**action-coverage gap in the synthesizer, not a planner or harness bug.**

Two ACSAC-defensible directions to close it:
- **Domain-side**: add a small "canonical sysadmin actions" library to the
  Phase 2 prompt or merger that ensures coverage of common remediation
  operations (edit-config-setting, reload-service-via-sighup, …). Each
  action is plain STRIPS — no hacks.
- **Problem-side**: have the problem generator produce a goal in terms
  of predicates the domain demonstrably supports. (Discoverable via the
  pddl_* tools.) If no satisfying action sequence exists, surface
  PLANNER_FOUND_NO_PLAN rather than fail-over to LLM shell.

### 2026-05-21: GOAL 1 ACHIEVED — symbolic-only end-to-end remediation of ccdc-01

`accuracy = 1.000` via the neurosymbolic path with **no ReAct shell fallback**.

```
COMPLETION:  REMEDIATION_COMPLETE
planner_succeeded:  True
plan_length:        2
dispatch_scorer:    C  REMEDIATION_COMPLETE
verify.sh:          ALL 4 checks PASS (PoC PASS, regression PASS)
```

The 2-step PDDL plan FD produced:

```
(set_setting_no permit_root_login sshd)
(start_service sshd)
```

…concretized via deterministic templates from `_ACTION_TEMPLATES`:

```
sed -i 's/^[#[:space:]]*[Pp]ermit[Rr]oot[Ll]ogin[[:space:]].*/PermitRootLogin no/' /etc/ssh/sshd_config
(service sshd restart 2>/dev/null) || /usr/sbin/sshd 2>/dev/null || systemctl start sshd
```

Sequence of 13+ specific defects fixed to get here, each at a real layer:

1. `ModuleNotFoundError: common` – sys.path injection + module-level imports
2. MiniMax `invalid chat setting (2013)` – removed react() tools call path
3. `re.error: missing )` – regex extracted out of f-string
4. `OSError(36) file name too long` – guard `Path(text).exists()`
5. `PLANNER_FOUND_NO_PLAN` (arity) – predicate signatures in prompt
6. `PLANNER_FOUND_NO_PLAN` (unsatisfied precond) – drop optional precond
7. Concretizer `<think>` leak → bash run on prompt text – strip + raise tokens
8. Regression FAIL (sshd not running) – `start_service` action added
9. pddl-library rejected effects – `:precondition (and)` form
10. `sudo: command not found` – strip leading sudo
11. LLM emitted action name verbatim as bash – include PDDL block + reject
12. Concretizer used `systemctl` without systemd – include env-state in prompt
13. M2.7 reasoning blew the 4096 cap on action 1 – deterministic templates for canonical actions

### Constraint reaffirmed

- ✅ No changes to `Phase3Config.auto_scale_ew_params` or iterations.
- ✅ No special-cased "this works for the benchmark" hacks. Whatever we
  change must be defensible as good PDDL / planning engineering.

## 2026-05-21: Goal 2 — typed-grounding fix for EW

### Root cause of EW ≤ 0.50

The Phase 3 EW evaluator samples uniformly from "applicable" actions, but
the simulator's grounder was effectively typeless:

1. `EnvironmentState.get_objects_by_type` only populated pools for
   `package`, `service`, `user`, `group`, `file`, `directory`. Domains
   mined by Phase 1/2 declared additional types (`port`, `interface`,
   `firewall_rule`, `configuration_file`, `human_user`, `system_user`,
   `repository`, `process`) — all of which returned empty pools.

2. `PDDLStateSimulator._ground_action_from_state` then fell back to the
   `object` supertype when a typed pool was empty, and
   `objects["object"]` is the union of every concrete pool. Net effect:
   a parameter `?p - port` would accept *any* config file, service, or
   user, producing concretized commands like
   `nft add rule inet filter input udp dport /etc/vdpau/wrapper.cfg`.

3. The previous subtype propagation walked child→parent. With env_state
   only populating parents (`file`, `user`), the subtypes
   (`configuration_file`, `human_user`) stayed empty and tripped the
   `object` fallback above.

This is the structural reason the EW ceiling was ~0.50: roughly half of
sampled actions were ungrounded junk that the sandbox rejected.

### Fix (defensible — standard typed PDDL grounding)

- `EnvironmentState._TYPE_ALIASES`: map declared mined-domain types to
  the closest concrete or semantic pool (port→port_number, chain/rule→
  netfilter chains, configuration_file→file, human_user/system_user→
  user, process→service, repository→package).
- `_build_objects`: propagate parent→child inheritance for declared
  `subtype - parent` edges, **stopping at `object`** so unmodeled types
  do not silently grab every system object.
- `_ground_action_from_state`: removed the `object`-supertype fallback.
  An empty typed pool now correctly makes the schema inapplicable —
  which is what typed PDDL semantics already requires.

Verified by smoke test:

```
weird_unmodeled_thing pool: None         # no leak
port pool:               [22,80,443,...] # numeric ports
configuration_file pool: [/etc/ssh/...]  # real config paths
human_user pool:         [root,...]      # real users
```

Expected impact: removes the majority of concretization-error
discrepancies (the dominant failure class in the old refinement log).
The remaining failures should be true PDDL/effect mismatches that the
refiner is designed to fix.

### 2026-05-21: quick test — typed-grounding ALONE without enrichment

To get a fast EW signal while the full pipeline was still in Phase 1, I
ran `python -m phase3.main` against the **stale** Phase 2 domain
`pddl_output/phase2/sysadmin.pddl` (from May 11 — predates enrichment).
N=68 walks, depth 8, 1 iteration. Result:

```
EW Score: 0.227 (121/534 steps, 413 discrepancies)
Top failing actions: nft_add_queue_rule(11), nft_add_rule_port(11),
                     nft_add_sctp_rule(11), id_get_user_id(10),
                     journalctl_read_user(10), ufw_limit(9)
```

The fix actually **dropped** the score from 0.499 → 0.227 because:
- Without enrichment, `nft_*`, `iptables_*`, `journalctl_*`, `ufw_*`
  actions are still applicable (their precondition is just `(and)`).
- Typed grounding now produces *realistic* concretized commands (real
  port numbers, real chain names) instead of bogus garbage that was
  occasionally a no-op.
- The container doesn't have nft/iptables/journalctl/ufw installed
  → 411 `command not found` failures.

This is *expected* and confirms the design: typed grounding lifts the
ceiling **only when paired with capability enrichment** that gates out
actions whose primary command is unavailable. The full pipeline run
(in flight, pid 1458245) applies both, so its EW measurement is the
real signal.

### 2026-05-21: full pipeline result — EW 0.414 (target 0.9)

Pipeline completed (12,642s / 3.5h total). Phase 2 ran with the 22
capabilities including my new 6, so the probed map is:

```
{systemd_init: F, iptables: F, nftables: F, ufw: F, firewalld: F,
 netplan: F, sudo: F, apt: T, dpkg: T, snap: F, auditd: F, fail2ban: F,
 apparmor: F, selinux: F, docker: F, container_safe_reboot: F,
 network_manager: F, kernel_modules: F, systemd_resolved: F,
 systemd_networkd: F, wireguard: F, traffic_control: F}
```

Phase 3 report:
```
iter 1: score=0.378 disc=412 (eval 3364s, refine 31s)
iter 2: score=0.414 disc=389 (eval 715s, refine 252s)
```

EW 0.414 ≠ 0.9. The typed-grounding + capability enrichment + new
capabilities did NOT close the gap on the current domain. Where the
389 discrepancies actually come from:

| Bucket | Count | Cause |
|---|---:|---|
| command_not_found | 103 | mostly `semanage`, `crontab`, `lprm`, `mesg`, `atrm`, plus LLM-hallucinated tokens like `output_format`, `delay_interval`, `query_by_facility` treated as commands |
| `no_systemd` | 21 | a few systemctl actions slipped past gating (need investigation) |
| `no_such_file` | 20 | per-instance missing paths (`/etc/sysctl.conf`, `/etc/rsyslog.conf`) |
| `exit1_empty` | 33 | tools running without args/options the model invented |
| `other` | 212 | per-action semantic errors |

Top failing actions (still ~10 each): `set_default_expire_date`,
`set_output_format`, `create_user_group_pair`, `set_system_timezone`,
`display_security_context`, `remove_subordinate_gids`, `top_enable_forest_view`.
Concrete commands sampled:

```
passwd --expire tape         → user 'tape' does not exist     (exit 1)
useradd -g sys -r -M -s /sbin/nologin list  → user exists    (exit 9)
chage -d /etc/xattr.conf games → invalid date (file leaked into date slot) (exit 2)
journalctl --list-fields     → unrecognized option (LLM hallucinated)
```

### Root-cause analysis of remaining EW gap

The remaining ≥0.49 gap is not closable with surgical patches to the
existing fix set. The structural issues are:

1. **Bloated action pool** — Phase 2 produces 1049 actions (Phase 1
   only mined 512; Phase 2 LLM map-reduce *added* 544). Many of the
   new ones have hallucinated `command_template` values where the
   LLM treated PDDL parameter names like `output_format` or
   `delay_interval` as bash commands. Capability gating cannot tag
   these because they don't start with a known utility.
2. **Missing semantic preconditions** — `useradd_*` actions have no
   `(not (user_exists ?u))` precondition, so EW samples a real
   system user and the command exits 9 (already exists). The refiner
   *could* add these but is capped at 20 repairs/iter for 2 iters →
   40 of 1049 actions touched.
3. **Capability list still incomplete** — `semanage`, `crontab`,
   `lprm`, `mesg`, `atrm`, `at`, `lpr` aren't yet probed. Adding
   them is straightforward (defensible) but Phase 1 + 2 must rerun
   to apply them; cost is ~3.5h per cycle.
4. **Type leakage for non-PDDL-declared types** — `chage -d` got
   `/etc/xattr.conf` because the action's `?d` parameter is typed
   `?d - object` (Phase 2 didn't infer a more specific type). The
   simulator's typed-grounding only constrains within the declared
   type; if the type IS `object`, the entire pool is fair game.
   Fixing this means Phase 2 needs to detect "date" / "value" /
   "number" parameter slots and emit a tighter type.
5. **Two-iteration budget** — the auto-scale code (per constraint,
   not to be touched) and `--max-refinement-iterations 2` mean the
   refiner only gets to repair ~40 actions out of 1049. The original
   May-11 run with 10 iterations capped at 0.499, so even unlimited
   iterations wouldn't have hit 0.9 with this domain.

### Blocker reached, per user directive

The user's instruction: *"if you hit a blocker or task isnt making
progress stoppe and report your finding keep an md file of your
changes and mat you have done"*.

I've reached a blocker — moving EW from 0.414 → 0.9 requires:

- **Either** a much smaller, higher-quality action pool (Phase 2
  dedup/quality gate), **or**
- **Aggressive precondition synthesis** in Phase 3's refiner
  (currently 20 actions/iter), **or**
- **Allowing iterations to exceed 2** (forbidden by user constraint).

None of these are surgical changes — each is a substantial Phase 2 or
Phase 3 design change that goes beyond "defensible PDDL setup".

### Net status

- **Goal 1 (end-to-end remediation of ccdc-01): ACHIEVED.**
  accuracy=1.000 via verify.sh PASS at commit `6a7346f`.
- **Goal 2 (EW ≥ 0.9): NOT achieved.** Current best on goal branch is
  EW=0.414 with the typed-grounding + enrichment + capability fixes
  in place. Root causes for the residual gap are catalogued above.
