# Ac

A neurosymbolic pipeline that learns a PDDL domain of system-administration
actions from a live host, then uses Fast Downward + an LLM fallback to repair
compromised systems on the [sysrepair-bench](https://github.com/) benchmark suite via Inspect AI.

## Setup

```bash
sudo bash scripts/setup.sh
uv sync
```

This installs osquery and the Python environment (Python >= 3.12).
Fast Downward must be available separately; set its path in
`neurosymbolic/runs.yaml` (`fd_path`).

## Run the Neurosymbolic Solver on Inspect AI

The solver wraps `sysrepair-bench` scenarios with a PDDL-planning agent and is
launched through Inspect AI. Presets live in
[neurosymbolic/runs.yaml](neurosymbolic/runs.yaml).

```bash
python -m neurosymbolic.run <preset>
```

Available presets:

| Preset                   | Purpose                                                                      |
| ------------------------ | ---------------------------------------------------------------------------- |
| `smoke`                  | Quick smoke test on a single CCDC scenario.                                  |
| `day1`                   | Full briefing on all benchmarks (ccdc, meta2, meta3/ubuntu, vulnhub, meta4). |
| `zero_day`               | Blind discovery mode across all benchmarks.                                  |
| `ccdc_day1`              | CCDC-only day-1 run (50 scenarios, fast iteration).                          |
| `ablation_no_refinement` | Day-1 with the unrefined Phase-2 domain.                                     |
| `ablation_no_planner`    | Day-1 with the planner disabled (LLM fallback only).                         |
| `ablation_no_fallback`   | Day-1 with the planner only (no LLM recovery).                               |

Examples:

```bash
python -m neurosymbolic.run smoke
python -m neurosymbolic.run day1
python -m neurosymbolic.run zero_day
```

Defaults (model, message/time/token limits, planner path, fallback toggle, etc.)
are set under `defaults:` in `runs.yaml` and merged with each preset; override by
editing that file.

Logs are written to `./logs/neurosymbolic/` by default.
