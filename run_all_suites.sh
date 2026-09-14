#!/usr/bin/env bash
# NeuroPlan over the whole SysRepair-Bench corpus, one suite at a time.
#
# Order is deliberate: the cheap suites first so a quota or walltime stop leaves
# the most complete picture, and meta4 last because it is the largest and the
# heaviest on Docker.
#
# Each suite gets its own log directory and its own .done markers, so this is
# safe to re-run: finished scenarios are skipped, not repeated.
#
# Windows scenarios are NOT included. meta3/windows (21) and meta3/windows-vm
# (3) run on a separate Windows host and cannot start from this VM; listing
# them here would produce a column of container-build failures that look like
# solver failures.
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ccdc is already complete in logs_ccdc_codaspy (50/50) and is not repeated.
# hivestorm is NOT part of the NeuroPlan evaluation (Ben, 2026-09-14). It is
# continuous-scored with no pass@k axis, it carries no threat briefing, and its
# 16 hosts split across two mutually exclusive Docker engines, so no single
# machine can produce the suite.
SUITES=(meta2 meta3/ubuntu vulnhub meta4)

for S in "${SUITES[@]}"; do
  SLUG="${S//\//_}"
  echo "=============================================================="
  echo "[all-suites] $(date -u +%F' '%H:%M:%S) starting $S"
  echo "=============================================================="
  ./run_suite.sh "$S" --all --workers 2 --logdir "./logs_bench_${SLUG}"
  rc=$?
  echo "[all-suites] $S finished rc=$rc"
  .venv/bin/python triage.py "./logs_bench_${SLUG}" 2>/dev/null \
    | grep -vE 'WARNING|INFO' | head -12
done
echo "[all-suites] ALL SUITES COMPLETE $(date -u +%F' '%H:%M:%S)"
