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
    open(base+'sysadmin_fd.pddl','w').write(_gen._validate_pddl_for_fd(open(base+'sysadmin.pddl').read()))
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
                                plan_timeout=120, time_limit=300),
            model='openai/MiniMax-M2.7', log_dir='./logs_neuroplan_e2e', max_connections=4,
        )
    except Exception as e:
        print(f"=== vulnhub-{nn}: EVAL ERROR {str(e)[:120]} ===", flush=True)
