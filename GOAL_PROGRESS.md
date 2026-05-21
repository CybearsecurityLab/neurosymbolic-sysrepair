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

Within the constraint (no auto-scale/iterations changes), the lever is
domain quality going **into** Phase 3. With a cleaner starting domain, the
same 2 iterations and the same auto-scaled walks will converge higher.
Concrete plan:

1. Inspect this run's discrepancy log to find actions that *always* fail
   (e.g. `netplan_generate`, `system_reboot`, ones depending on absent tools).
2. Prune those from `sysadmin.pddl` between Phase 2 output and Phase 3 input.
3. Re-run Phase 3 only; measure EW.

Step 1 is pure analysis of the data we already have.
