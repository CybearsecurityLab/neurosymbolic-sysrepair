"""Aggregate neurosymbolic E2E .eval logs into the vulnhub Val/Plan/Exec table.
Usage: python aggregate_e2e.py logs_neuroplan_e2e"""
import sys, glob
sys.path.insert(0, '/home/resbears/projects/sysrepair-bench/inspect_eval')
import sysrepair_bench.task  # register sandbox provider so logs deserialize
from inspect_ai.log import read_eval_log

# stage decomposition from solver's output.completion (solver.py:725-733)
VALIDATE_OK = {"PLANNER_FOUND_NO_PLAN", "PLAN_DID_NOT_REMEDIATE", "REMEDIATION_COMPLETE"}
PLAN_OK     = {"PLAN_DID_NOT_REMEDIATE", "REMEDIATION_COMPLETE"}
EXEC_OK     = {"REMEDIATION_COMPLETE"}

logdir = sys.argv[1] if len(sys.argv) > 1 else 'logs_neuroplan_e2e'
rows = {}
for f in glob.glob(f"{logdir}/*.eval"):
    try:
        log = read_eval_log(f)
    except Exception as e:
        print("skip", f, str(e)[:60]); continue
    for s in (log.samples or []):
        comp = (s.output.completion if s.output else "") or ""
        sc = (s.scores or {}).get('dispatch_scorer')
        secure = sc.metadata.get('security_pass') if sc and sc.metadata else None
        reg = sc.metadata.get('regression_pass') if sc and sc.metadata else None
        plen = sum(1 for m in (s.messages or []) if isinstance(getattr(m,'content','') or '', str) and '[neurosym:plan] $' in (m.content or ''))
        toks = 0
        try: toks = sum(u.total_tokens for u in (log.stats.model_usage or {}).values())
        except Exception: pass
        rows[str(s.id)] = dict(comp=comp, val=comp in VALIDATE_OK, plan=comp in PLAN_OK,
                               exe=comp in EXEC_OK, secure=secure, reg=reg, plen=plen, toks=toks)

n = len(rows)
if not n: print("no samples found in", logdir); sys.exit()
V = sum(r['val'] for r in rows.values()); P = sum(r['plan'] for r in rows.values()); E = sum(r['exe'] for r in rows.values())
plens = [r['plen'] for r in rows.values() if r['plan']]
tot_toks = sum(r['toks'] for r in rows.values())
print(f"n = {n} scenarios")
print(f"Validate = {V}/{n} = {V/n:.2f}")
print(f"Plan     = {P}/{n} = {P/n:.2f}")
print(f"Execute  = {E}/{n} = {E/n:.2f}")
print(f"mean |pi| (over planned) = {sum(plens)/len(plens):.1f}" if plens else "mean |pi| = n/a")
print(f"tokens/success = {tot_toks/E:.0f}" if E else f"total tokens = {tot_toks} (0 successes)")
print("--- per-scenario ---")
for k in sorted(rows): r=rows[k]; print(f"  {k}: {r['comp']:24s} V={int(r['val'])} P={int(r['plan'])} E={int(r['exe'])} sec={r['secure']} reg={r['reg']} |pi|={r['plen']}")
