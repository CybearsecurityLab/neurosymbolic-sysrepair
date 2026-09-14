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
    # The Windows halves of meta3 run only on a Windows Docker engine, which is
    # mutually exclusive with the Linux engine on the same host. They are listed
    # so the Windows machine can name them; they will simply find no scenarios
    # to start on a Linux host.
    "meta3/windows": "meta3/windows",
    "meta3/windows-vm": "meta3/windows-vm",
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

    THE CLEANER CAN MAKE A DOMAIN WORSE, so its output is checked. It used to
    mint parameters named `?_pad_0`; a PDDL name may not begin with an
    underscore, so the cleaned global domain was rejected by the repo's own
    validator (122 times across 105 lines) while the 30 per-scenario vulnhub
    domains were untouched, which is why it went unnoticed. That is fixed at
    source now, but the gates stay: a cleaner that rewrites a domain can always
    rewrite it into something the planner will not take.

    So: clean, then put the result through BOTH gates (the `pddl` grammar and
    Fast Downward's own translator) and refuse the run if either rejects it.
    There is deliberately no fallback to the uncleaned domain: the raw global
    refined domain passes the grammar but fails FD's translator, so falling
    back trades a loud failure for a silent one. See fd_translates().
    """
    sys.path.insert(0, str(HERE))
    from phase3.planner_wrapper import RandomWalkGenerator  # noqa: E402

    try:
        from phase3.planner_wrapper import PlannerConfig
        gen = RandomWalkGenerator(PlannerConfig())
    except Exception:
        gen = RandomWalkGenerator()

    raw = src.read_text()
    cleaned = gen._validate_pddl_for_fd(raw)
    if grammar_ok(cleaned) and fd_translates(cleaned):
        dst.write_text(cleaned)
        return dst
    raise SystemExit(
        f"FATAL: the FD-cleaned form of {src} does not pass both gates "
        f"(pddl grammar: {grammar_ok(cleaned)}, FD translator: "
        f"{fd_translates(cleaned)}). Refusing to run. Falling back to the "
        f"uncleaned domain is NOT an acceptable recovery: see fd_translates().")


def grammar_ok(pddl_text: str) -> bool:
    from neurosymbolic.solver import assert_valid_domain  # noqa: E402
    return assert_valid_domain(pddl_text, source="run_bench.gate").ok


def fd_translates(pddl_text: str) -> bool:
    """Does Fast Downward's translator accept this domain?

    THE TWO GATES DISAGREE, IN BOTH DIRECTIONS, AND BOTH ARE NEEDED.

    * FD's tokenizer accepts any non-space token, so it accepts the illegal
      `?_pad_0` that the `pddl` grammar rejects.
    * The `pddl` grammar is a parse and nothing more: it accepts the raw global
      refined domain, which FD then refuses to translate (exit 31,
      "Undefined predicate"). Measured, on this machine:

          raw sysadmin_refined.pddl          grammar PASS   FD exit 31
          FD-cleaned, pads renamed legal     grammar PASS   FD exit 0

    Checking only the grammar is what made the earlier fallback dangerous. The
    solver does not bind Fast Downward's return code; it only looks for a
    `sas_plan` file, so a translator abort and a genuinely unsolvable problem
    both surface as `PLANNER_FOUND_NO_PLAN`, which the aggregator scores
    Validate 1. An untranslatable domain therefore earns a Validate point on
    every scenario and reads as "the repair is not expressible in the domain"
    when the truth is "the domain never reached the planner". That is a worse
    failure than the NO_DOMAIN_PROVIDED it replaced, because it is invisible.
    """
    import subprocess
    import tempfile

    probe = ("(define (problem fd-translate-probe)\n"
             "  (:domain sysadmin)\n  (:objects)\n  (:init)\n  (:goal (and))\n)\n")
    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "domain.pddl"
        p = Path(td) / "problem.pddl"
        d.write_text(pddl_text)
        p.write_text(probe)
        try:
            rc = subprocess.run(
                [sys.executable, fast_downward(),
                 "--translate", str(d), str(p)],
                capture_output=True, cwd=td, timeout=300).returncode
        except Exception:
            return False
    return rc == 0


def fast_downward() -> str:
    """Path to Fast Downward's driver.

    Overridable with FAST_DOWNWARD because this runner is not confined to one
    machine: the Windows suites run on a host with the Windows docker engine,
    where nothing sits under /home/resbears. The default is this VM's checkout
    so existing invocations are unchanged.

    The planner version is part of the experiment. These results were produced
    with Fast Downward 24.06+ at 824499f8f7b1d3f8c0260b2b8b0740ee815dcdca,
    built `release`. A different revision is a different experiment, so a peer
    reproducing these numbers must build that revision, not whatever `hg tip`
    or `git clone` gives them today.
    """
    fd = os.environ.get("FAST_DOWNWARD", "/home/resbears/fast_downward/fast-downward.py")
    if not Path(fd).exists():
        raise SystemExit(
            f"Fast Downward driver not found at {fd}.\n"
            "Set FAST_DOWNWARD to the fast-downward.py of a build of revision\n"
            "824499f8f7b1d3f8c0260b2b8b0740ee815dcdca (24.06+), which is the\n"
            "revision these results were produced with."
        )
    return fd


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
            fd_path=fast_downward(),
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
