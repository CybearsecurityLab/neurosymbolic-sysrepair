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

### Constraint reaffirmed

- ✅ No changes to `Phase3Config.auto_scale_ew_params` or iterations.
- ✅ No special-cased "this works for the benchmark" hacks. Whatever we
  change must be defensible as good PDDL / planning engineering.
