"""E2E NeuroPlan eval for any collection: FD-clean each built domain, then run
the neurosymbolic solver plus the dual-objective oracle.

Generalised from run_e2e_vulnhub.py, which hard-coded vulnhub in three places
(the domain directory, the scenario id, and the log messages). tab:nsplan needs
a ccdc row as well as the vulnhub one, and the ccdc domains are being generated
now, so the runner has to take the collection as an argument.

Usage:
    python run_e2e.py --collection ccdc 01 02 03
    python run_e2e.py --collection ccdc --all 50
    E2E_LOGDIR=./logs_ccdc_e2e python run_e2e.py --collection ccdc --all 50

Defaults match the vulnhub run that produced logs_final30, so the two rows of
tab:nsplan stay comparable: MiniMax-M2.7, plan_timeout 120, time_limit 900,
max_connections 4, mode day1. Do not change these for one collection only.
"""
import argparse, os, sys

sys.path.insert(0, '.')
from phase3.planner_wrapper import RandomWalkGenerator  # noqa: E402
from neurosymbolic.solver import assert_valid_domain  # noqa: E402

try:
    from phase3.planner_wrapper import PlannerConfig
    _gen = RandomWalkGenerator(PlannerConfig())
except Exception:
    _gen = RandomWalkGenerator()

# Domain directory per collection. These are the on-disk names the pipeline
# writes, which do not follow a single pattern, so they are listed explicitly
# rather than derived.
DOMAIN_DIRS = {
    "vulnhub": "pddl_domains_vulnhub_full/vulnhub-{nn}/",
    "ccdc": "pddl_ccdc_validate/ccdc-{nn}/",
    "meta2": "pddl_domains_meta2_full/meta2-{nn}/",
}


def fd_clean(collection: str, nn: str):
    """Rewrite the generated domain into a Fast Downward-parseable form."""
    base = DOMAIN_DIRS[collection].format(nn=nn)
    src = base + "sysadmin.pddl"
    if not os.path.exists(src):
        return None
    out = base + "sysadmin_fd.pddl"
    with open(src) as f:
        cleaned = _gen._validate_pddl_for_fd(f.read())
    # The cleaner's output was never checked. When it emits something the
    # parser rejects, the solver discards the domain and every scenario is
    # scored as a planning failure that says nothing about the planner. Refuse
    # instead: a domain we cannot parse is a configuration error, not a result.
    _v = assert_valid_domain(cleaned, source="run_e2e.fd_clean")
    if not _v.ok:
        raise SystemExit(
            f"FATAL: the FD-cleaned {src} does not parse: "
            f"{(_v.detail or _v.error or '')[:200]}")
    with open(out, "w") as f:
        f.write(cleaned)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--collection", required=True, choices=sorted(DOMAIN_DIRS))
    ap.add_argument("--all", type=int, metavar="N",
                    help="run scenarios 01..N instead of listing them")
    ap.add_argument("nums", nargs="*", help="two-digit scenario numbers")
    ap.add_argument("--model", default="openai/MiniMax-M2.7")
    ap.add_argument("--mode", default="day1", choices=["day1", "zero_day"])
    a = ap.parse_args()

    nums = ([f"{i:02d}" for i in range(1, a.all + 1)] if a.all else a.nums) or ["01"]

    from inspect_ai import eval as inspect_eval
    from neurosymbolic.task import neurosymbolic_bench

    logdir = os.environ.get("E2E_LOGDIR", f"./logs_{a.collection}_e2e")
    built = skipped = failed = 0
    for nn in nums:
        dom = fd_clean(a.collection, nn)
        if not dom:
            # A missing domain is expected while generation is still running;
            # it is reported rather than treated as an error so a partial run
            # is obvious in the output instead of looking like a clean pass.
            print(f"=== {a.collection}-{nn}: NO DOMAIN BUILT, skipping ===", flush=True)
            skipped += 1
            continue
        print(f"=== {a.collection}-{nn}: domain={dom} ===", flush=True)
        try:
            inspect_eval(
                neurosymbolic_bench(
                    mode=a.mode,
                    scenarios=[f"{a.collection}/scenario-{nn}"],
                    domain_path=dom,
                    fd_path="/home/resbears/fast_downward/fast-downward.py",
                    plan_timeout=120, time_limit=900),
                model=a.model, log_dir=logdir, max_connections=4,
            )
            built += 1
        except Exception as e:
            print(f"=== {a.collection}-{nn}: EVAL ERROR {str(e)[:120]} ===", flush=True)
            failed += 1

    print(f"\n=== {a.collection}: {built} evaluated, {skipped} no-domain, "
          f"{failed} errored; logs in {logdir} ===", flush=True)
    print(f"Aggregate with: python aggregate_e2e.py {logdir}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
