"""E2E vulnhub eval: FD-clean each built domain, run neurosymbolic solver+oracle.
Usage: python run_e2e_vulnhub.py NN [NN ...]"""
import os, sys
sys.path.insert(0, '.')
from phase3.planner_wrapper import RandomWalkGenerator
try:
    from phase3.planner_wrapper import PlannerConfig; _gen = RandomWalkGenerator(PlannerConfig())
except Exception: _gen = RandomWalkGenerator()

def fd_clean(nn):
    base = f'pddl_domains_vulnhub_full/vulnhub-{nn}/'
    if not os.path.exists(base+'sysadmin.pddl'):
        return None
    cleaned = _gen._validate_pddl_for_fd(open(base+'sysadmin.pddl').read())
    # Check the cleaner's output. Unchecked, a domain the parser rejects is
    # silently discarded by the solver and the scenario is scored as a planning
    # failure that says nothing about the planner.
    from neurosymbolic.solver import assert_valid_domain
    _v = assert_valid_domain(cleaned, source='run_e2e_vulnhub.fd_clean')
    if not _v.ok:
        raise SystemExit(f"FATAL: cleaned {base}sysadmin.pddl does not parse: "
                         f"{(_v.detail or _v.error or '')[:200]}")
    open(base+'sysadmin_fd.pddl','w').write(cleaned)
    return base+'sysadmin_fd.pddl'

nums = sys.argv[1:] or ['01']
from inspect_ai import eval as inspect_eval
from neurosymbolic.task import neurosymbolic_bench
for nn in nums:
    dom = fd_clean(nn)
    if not dom:
        print(f"=== vulnhub-{nn}: NO DOMAIN BUILT, skipping ===", flush=True); continue
    print(f"=== vulnhub-{nn}: domain={dom} ===", flush=True)
    try:
        inspect_eval(
            neurosymbolic_bench(mode='day1', scenarios=[f'vulnhub/scenario-{nn}'],
                                domain_path=dom, fd_path='/home/resbears/fast_downward/fast-downward.py',
                                plan_timeout=120, time_limit=900),
            model='openai/MiniMax-M2.7', log_dir=os.environ.get('E2E_LOGDIR','./logs_neuroplan_e2e'), max_connections=4,
        )
    except Exception as e:
        print(f"=== vulnhub-{nn}: EVAL ERROR {str(e)[:120]} ===", flush=True)
