"""Classify every NeuroPlan failure in a log directory: model failure, or no
plan exists, or a defect in our own pipeline.

WHY THIS IS NOT JUST aggregate_e2e.py
-------------------------------------
`aggregate_e2e.py` reports Validate / Plan / Execute, which is the right shape
for a paper table and the wrong shape for deciding what to fix. In particular
it scores `PLANNER_FOUND_NO_PLAN` as **Validate 1**, and that single completion
string covers at least four distinct events:

    the translator refused the domain      (FD exit 30, 31)
    the problem was proved unsolvable      (FD exit 10, 11)
    the search gave up incomplete          (FD exit 12)
    the search ran out of time or memory   (FD exit 22, 23, 24, or a timeout)

Only the second is "no plan exists". The first is a bug in this pipeline, and
it previously earned a Validate point on every scenario it touched, which reads
in a results table as a planner that understood the domain and correctly
declined. That is the opposite of what happened.

Fast Downward's return code is recorded by `solver.py` in
`sample.metadata["fd_returncode"]`, so this reads it back and splits the bucket.
Logs written before that instrumentation existed show `fd_returncode` as None
and are reported as UNINSTRUMENTED rather than guessed at.

Usage
-----
    python triage.py logs_bench_ccdc
    python triage.py logs_bench_ccdc --csv triage_ccdc.csv
"""
from __future__ import annotations

import argparse
import csv
import glob
import os
import sys
from pathlib import Path
from collections import Counter

sys.path.insert(0, os.environ.get(
    'SYSREPAIR_INSPECT',
    str(Path(__file__).resolve().parent.parent / 'sysrepair-bench' / 'inspect_eval')))
import sysrepair_bench.task  # noqa: F401,E402  (registers the sandbox provider)
from inspect_ai.log import read_eval_log  # noqa: E402

# Fast Downward driver exit codes (driver/returncodes.py).
FD = {
    0: "SUCCESS", 1: "PLAN_FOUND_OOM", 2: "PLAN_FOUND_OOT",
    3: "PLAN_FOUND_OOM_OOT",
    10: "TRANSLATE_UNSOLVABLE", 11: "SEARCH_UNSOLVABLE",
    12: "SEARCH_UNSOLVED_INCOMPLETE", 13: "SEARCH_UNSOLVABLE_WITHIN_BOUND",
    20: "TRANSLATE_OOM", 21: "TRANSLATE_OOT",
    22: "SEARCH_OOM", 23: "SEARCH_OOT", 24: "SEARCH_OOM_OOT",
    30: "TRANSLATE_CRITICAL_ERROR", 31: "TRANSLATE_INPUT_ERROR",
    32: "SEARCH_CRITICAL_ERROR", 33: "SEARCH_INPUT_ERROR",
    34: "SEARCH_UNSUPPORTED",
    35: "DRIVER_CRITICAL_ERROR", 36: "DRIVER_INPUT_ERROR",
    37: "DRIVER_UNSUPPORTED",
}

# The verdict each case supports. These are the categories worth acting on.
PASS = "PASS"
MODEL = "MODEL FAILURE"              # a plan was produced; the repair was wrong
NO_PLAN = "NO PLAN EXISTS"           # the domain cannot express this repair
PIPELINE = "PIPELINE DEFECT"         # our PDDL never reached or passed the planner
BUDGET = "BUDGET"                    # time or memory, not a capability statement
UNKNOWN = "UNINSTRUMENTED"


def classify(completion: str, md: dict, oracle: str | None = None,
             limit: str | None = None) -> tuple[str, str]:
    """Return (verdict, detail).

    THE ORACLE IS CHECKED FIRST, AND IT OUTRANKS THE COMPLETION STRING.
    They disagree. On ccdc/scenario-01 the solver ended with
    `PLAN_DID_NOT_REMEDIATE`, because its own in-sandbox verify did not pass,
    while `dispatch_scorer` returned `C` with both the security and the
    regression gate satisfied. The dispatch scorer is the benchmark's arbiter
    and is what `aggregate_e2e.py` counts, so classifying on the completion
    alone would report a passing scenario as a model failure.
    """
    if oracle == "C":
        return PASS, ("oracle passed"
                      if completion == "REMEDIATION_COMPLETE"
                      else f"oracle passed; solver self-report was {completion}")
    if completion == "REMEDIATION_COMPLETE":
        # The reverse disagreement: the solver believes it finished and the
        # oracle does not. The oracle wins.
        return MODEL, "solver reported complete, oracle rejected it"
    if completion == "PLAN_DID_NOT_REMEDIATE":
        return MODEL, "plan executed, oracle rejected the result"
    if completion == "NO_DOMAIN_PROVIDED":
        return PIPELINE, "domain missing or rejected by the validator"
    if completion == "PROBLEM_GENERATION_FAILED":
        return MODEL, "the model could not emit a parseable problem"
    if completion == "PLANNER_FOUND_NO_PLAN":
        if md.get("fd_timed_out"):
            return BUDGET, "planner wall-clock timeout"
        rc = md.get("fd_returncode")
        if rc is None:
            return UNKNOWN, "no fd_returncode in this log; predates the instrumentation"
        name = FD.get(rc, f"exit {rc}")
        if rc in (10, 11, 13):
            return NO_PLAN, f"proved unsolvable ({name})"
        if rc == 12:
            # SEARCH_UNSOLVED_INCOMPLETE. The search gave up without proving
            # anything, so it is not evidence that no plan exists. Only 10, 11
            # and 13 are proofs.
            return BUDGET, f"search gave up without a proof ({name})"
        if rc in (20, 21, 22, 23, 24):
            return BUDGET, name
        if rc in (30, 31, 32, 33, 34, 35, 36, 37):
            return PIPELINE, f"planner refused our input ({name})"
        return UNKNOWN, name
    if not completion:
        # An episode killed by its wall-clock budget never reaches the
        # completion assignment, so it arrives here with an empty string. That
        # is a BUDGET outcome, not broken PDDL: scenario-21 had already planned
        # (fd_returncode 0) and ran out of time during execution. Calling it a
        # pipeline defect understates how much of the corpus is interpretable.
        if limit == "time":
            return BUDGET, "episode hit its wall-clock limit before finishing"
        return PIPELINE, "episode ended with no completion and no limit recorded"
    return PIPELINE, f"unrecognised completion {completion!r}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("logdir")
    ap.add_argument("--csv", help="also write a per-scenario CSV here")
    a = ap.parse_args()

    rows = []
    for f in sorted(glob.glob(f"{a.logdir}/*.eval")):
        try:
            log = read_eval_log(f)
        except Exception as e:  # noqa: BLE001
            print(f"skip {f}: {str(e)[:60]}", file=sys.stderr)
            continue
        for s in (log.samples or []):
            comp = (s.output.completion if s.output else "") or ""
            md = s.metadata or {}
            sc = (s.scores or {}).get("dispatch_scorer")
            lim = getattr(s, "limit", None)
            verdict, detail = classify(
                comp, md, getattr(sc, "value", None) if sc else None,
                getattr(lim, "type", None) if lim else None)
            rows.append({
                "scenario": str(s.id),
                "verdict": verdict,
                "completion": comp,
                "detail": detail,
                "fd_returncode": md.get("fd_returncode"),
                "plan_length": md.get("plan_length"),
                "mined_operators": len(md.get("mined_operators") or []),
                "oracle": getattr(sc, "value", None) if sc else None,
            })

    if not rows:
        print(f"no samples found in {a.logdir}")
        return 1

    counts = Counter(r["verdict"] for r in rows)
    n = len(rows)
    print(f"{a.logdir}: {n} scenarios\n")
    for v in (PASS, MODEL, NO_PLAN, PIPELINE, BUDGET, UNKNOWN):
        if counts.get(v):
            print(f"  {v:<16} {counts[v]:>4}  ({counts[v] / n:.0%})")
    print()

    interp = n - counts.get(PIPELINE, 0) - counts.get(UNKNOWN, 0)
    print(f"Interpretable as a statement about the benchmark: {interp}/{n}")
    if counts.get(PIPELINE):
        print(f"  {counts[PIPELINE]} scenario(s) failed inside our own pipeline "
              f"and say nothing about NeuroPlan's capability.")
    if counts.get(UNKNOWN):
        print(f"  {counts[UNKNOWN]} scenario(s) predate the fd_returncode "
              f"instrumentation and cannot be split; re-run to classify.")

    print("\n--- per scenario ---")
    for r in sorted(rows, key=lambda r: (r["verdict"], r["scenario"])):
        print(f"  {r['scenario']:<28} {r['verdict']:<16} "
              f"{r['completion']:<26} {r['detail']}")

    if a.csv:
        with open(a.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        print(f"\nwrote {a.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
