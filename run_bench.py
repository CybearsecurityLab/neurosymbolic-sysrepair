"""Run NeuroPlan over a whole SysRepair-Bench suite, one suite at a time.

WHY THIS EXISTS ALONGSIDE run_e2e.py
------------------------------------
`run_e2e.py` resolves each scenario's domain out of a `pddl_*` directory of
PER-SCENARIO domains built by the Phase 1-3 pipeline. That is the right thing
when those domains exist, but they exist for only two suites:

    pddl_domains_vulnhub_full  30/30
    pddl_ccdc_validate         11/50
    meta2, meta3, meta4, hivestorm   none

Rebuilding them for the whole corpus is a multi-day job per suite. The solver's
own Phase-1.5 operator miner is explicitly suite-agnostic (see
`solver.py`, "Suite-agnostic; the hand-authored canonical operators are the
verified cache/seed"), so the global refined domain plus per-scenario mining
reaches every suite today. That is what `--domain global` does, and it is the
default here.

`run_e2e.py` is left untouched: `run_ccdc_e2e_when_built.sh` and
`run_final30b.sh` call it and must keep their exact behaviour.

WHAT ELSE THIS ADDS
-------------------
* Every suite, including `meta3/ubuntu`, `meta4` and `hivestorm`.
* Scenario ids are ENUMERATED FROM DISK, not assumed to be 01..N. hivestorm ids
  are `01-debian9`, `02-ubuntu1604`, ... and would be missed by a numeric range.
* One `inspect_eval` per scenario in its own subprocess, so a scenario whose
  container will not build cannot abort the rest of the suite. A single
  whole-suite task aborts on the first setup failure, before `fail_on_error`
  is ever consulted.
* Resume. A completed scenario drops a marker in `<logdir>/.done/` and is
  skipped on the next invocation, so a run killed by quota or walltime picks up
  where it stopped instead of restarting.
* hivestorm defaults to zero_day: it ships no threat briefing, so a day-1 arm
  would be a duplicate of the zero-day one.

Solver settings (model, plan_timeout, time_limit, mode, max_connections) match
`run_e2e.py` so rows stay comparable across suites. Do not tune them for one
suite.

Usage
-----
    python run_bench.py --suite ccdc --all
    python run_bench.py --suite ccdc --scenario 01
    python run_bench.py --suite meta4 --all --workers 2
    LOGDIR=./logs_bench_ccdc python run_bench.py --suite ccdc --all
"""
from __future__ import annotations

import argparse
import concurrent.futures
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent / "sysrepair-bench"

# Suite name -> directory under the benchmark repo holding scenario-* dirs.
SUITES = {
    "ccdc": "ccdc",
    "meta2": "meta2",
    "meta3/ubuntu": "meta3/ubuntu",
    "vulnhub": "vulnhub",
    "hivestorm": "hivestorm",
    "meta4": "meta4",
}

# hivestorm publishes no threat.md, so both arms would receive an identical
# prompt. It is scored zero-day only.
ZERO_DAY_ONLY = {"hivestorm"}

GLOBAL_DOMAIN = HERE / "pddl_output" / "phase3" / "sysadmin_refined.pddl"
GLOBAL_DOMAIN_FD = HERE / "pddl_output" / "phase3" / "sysadmin_refined_fd.pddl"

# Per-scenario domain directories, when --domain per-scenario is asked for.
PER_SCENARIO_DIRS = {
    "vulnhub": "pddl_domains_vulnhub_full/vulnhub-{nn}/",
    "ccdc": "pddl_ccdc_validate/ccdc-{nn}/",
    "meta2": "pddl_domains_meta2_full/meta2-{nn}/",
}


def scenario_ids(suite: str) -> list[str]:
    """Every scenario id present on disk for this suite, sorted naturally."""
    root = BENCH / SUITES[suite]
    ids = [p.name.removeprefix("scenario-") for p in root.glob("scenario-*") if p.is_dir()]

    def key(s: str):
        head = s.split("-", 1)[0]
        return (int(head) if head.isdigit() else 10**9, s)

    return sorted(ids, key=key)


def fd_clean(src: Path, dst: Path) -> Path:
    """Rewrite a domain into a form Fast Downward's translator accepts.

    An unclean domain aborts the translator, which the solver reports as
    NO_PLAN. That is indistinguishable in the logs from "the domain genuinely
    cannot express this repair", and the two have opposite meanings for the
    failure triage, so the cleaner runs before any scenario does.

    THE CLEANER CAN MAKE A DOMAIN WORSE. Its arity padder mints parameters
    named `?_pad_0`, and a PDDL name may not begin with an underscore, so
    `assert_valid_domain` rejects the result. `solver.py` responds by dropping
    the domain entirely and every scenario returns NO_DOMAIN_PROVIDED, which
    reads in the logs as a total planner failure rather than as a broken input.
    The global refined domain hits this 105 times; the 30 per-scenario vulnhub
    domains do not hit it at all, which is why it went unnoticed.

    So: clean, then validate, and keep the cleaned copy only if it is at least
    as valid as the original.
    """
    sys.path.insert(0, str(HERE))
    from phase3.planner_wrapper import RandomWalkGenerator  # noqa: E402
    from neurosymbolic.solver import assert_valid_domain  # noqa: E402

    try:
        from phase3.planner_wrapper import PlannerConfig
        gen = RandomWalkGenerator(PlannerConfig())
    except Exception:
        gen = RandomWalkGenerator()

    raw = src.read_text()
    cleaned = gen._validate_pddl_for_fd(raw)
    if assert_valid_domain(cleaned, source="run_bench.fd_clean").ok:
        dst.write_text(cleaned)
        return dst
    if assert_valid_domain(raw, source="run_bench.raw").ok:
        print(f"[setup] WARNING: FD cleaner made {src.name} invalid; "
              f"using the uncleaned domain instead", flush=True)
        return src
    raise SystemExit(
        f"FATAL: {src} is invalid both before and after FD cleaning. "
        f"Refusing to run, because the solver would silently report every "
        f"scenario as NO_DOMAIN_PROVIDED.")


# Set once in main() to whichever global domain actually validates.
RESOLVED_GLOBAL: Path = GLOBAL_DOMAIN


def resolve_domain(suite: str, nn: str, mode: str, fd: bool) -> Path | None:
    if mode == "global":
        return RESOLVED_GLOBAL
    tpl = PER_SCENARIO_DIRS.get(suite)
    if not tpl:
        return None
    base = HERE / tpl.format(nn=nn)
    src = base / "sysadmin.pddl"
    if not src.exists():
        return None
    return fd_clean(src, base / "sysadmin_fd.pddl") if fd else src


def run_one(suite: str, nn: str, domain: Path, mode: str, logdir: Path,
            model: str, plan_timeout: int, time_limit: int) -> str:
    """Evaluate a single scenario in-process. Returns a short status word."""
    from inspect_ai import eval as inspect_eval
    from neurosymbolic.task import neurosymbolic_bench

    inspect_eval(
        neurosymbolic_bench(
            mode=mode,
            scenarios=[f"{SUITES[suite]}/scenario-{nn}"],
            domain_path=str(domain),
            fd_path="/home/resbears/fast_downward/fast-downward.py",
            plan_timeout=plan_timeout,
            time_limit=time_limit,
        ),
        model=model,
        log_dir=str(logdir),
        max_connections=4,
    )
    return "ok"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--suite", required=True, choices=sorted(SUITES))
    ap.add_argument("--all", action="store_true", help="every scenario on disk")
    ap.add_argument("--scenario", action="append", default=[],
                    help="scenario id, repeatable (e.g. 01, or 01-debian9)")
    ap.add_argument("--mode", default="auto", choices=["auto", "day1", "zero_day"])
    ap.add_argument("--domain", default="global", choices=["global", "per-scenario"])
    ap.add_argument("--no-fd-clean", action="store_true")
    ap.add_argument("--model", default="openai/MiniMax-M2.7")
    ap.add_argument("--plan-timeout", type=int, default=120)
    ap.add_argument("--time-limit", type=int, default=900)
    ap.add_argument("--workers", type=int, default=1,
                    help="scenarios in flight; each holds a scenario container")
    ap.add_argument("--force", action="store_true", help="ignore resume markers")
    ap.add_argument("--logdir", default=os.environ.get("LOGDIR", ""))
    a = ap.parse_args()

    suite = a.suite
    mode = a.mode
    if mode == "auto":
        mode = "zero_day" if suite in ZERO_DAY_ONLY else "day1"

    ids = a.scenario or (scenario_ids(suite) if a.all else [])
    if not ids:
        ap.error("give --all or at least one --scenario")

    logdir = Path(a.logdir or f"./logs_bench_{suite.replace('/', '_')}_{mode}")
    logdir.mkdir(parents=True, exist_ok=True)
    done_dir = logdir / ".done"
    done_dir.mkdir(exist_ok=True)

    fd = not a.no_fd_clean
    if a.domain == "global":
        global RESOLVED_GLOBAL
        if not GLOBAL_DOMAIN.exists():
            print(f"FATAL: global domain missing at {GLOBAL_DOMAIN}", file=sys.stderr)
            return 2
        RESOLVED_GLOBAL = (fd_clean(GLOBAL_DOMAIN, GLOBAL_DOMAIN_FD) if fd
                           else GLOBAL_DOMAIN)
        print(f"[setup] global domain = {RESOLVED_GLOBAL}", flush=True)

    pending = [nn for nn in ids if a.force or not (done_dir / nn).exists()]
    print(f"[{suite}] mode={mode} domain={a.domain} logdir={logdir}", flush=True)
    print(f"[{suite}] {len(ids)} scenarios on disk, {len(pending)} to run, "
          f"{len(ids) - len(pending)} already done", flush=True)

    counts = {"ok": 0, "nodomain": 0, "error": 0}
    lock_started = time.time()

    def one(nn: str) -> tuple[str, str]:
        dom = resolve_domain(suite, nn, a.domain, fd)
        if dom is None:
            return nn, "nodomain"
        if a.workers > 1:
            # Separate process per scenario: an inspect_eval that dies on a
            # container build takes only its own scenario down.
            cmd = [sys.executable, str(HERE / "run_bench.py"), "--suite", suite,
                   "--scenario", nn, "--mode", mode, "--domain", a.domain,
                   "--model", a.model, "--plan-timeout", str(a.plan_timeout),
                   "--time-limit", str(a.time_limit), "--logdir", str(logdir),
                   "--workers", "1", "--force"]
            if a.no_fd_clean:
                cmd.append("--no-fd-clean")
            rc = subprocess.run(cmd).returncode
            return nn, ("ok" if rc == 0 else "error")
        try:
            run_one(suite, nn, dom, mode, logdir, a.model,
                    a.plan_timeout, a.time_limit)
            return nn, "ok"
        except Exception as e:  # noqa: BLE001
            print(f"=== {suite}/{nn}: EVAL ERROR {type(e).__name__}: "
                  f"{str(e)[:160]} ===", flush=True)
            return nn, "error"

    if a.workers > 1:
        with concurrent.futures.ThreadPoolExecutor(a.workers) as ex:
            results = list(ex.map(one, pending))
    else:
        results = []
        for i, nn in enumerate(pending, 1):
            el = int(time.time() - lock_started)
            print(f"\n=== [{i}/{len(pending)}] {suite}/scenario-{nn} "
                  f"(elapsed {el // 60}m) ===", flush=True)
            results.append(one(nn))

    for nn, status in results:
        counts[status] = counts.get(status, 0) + 1
        if status == "ok":
            (done_dir / nn).write_text("")

    print(f"\n=== {suite}: {counts['ok']} evaluated, {counts['nodomain']} no-domain, "
          f"{counts['error']} errored; logs in {logdir} ===", flush=True)
    print(f"Aggregate with: python aggregate_e2e.py {logdir}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
