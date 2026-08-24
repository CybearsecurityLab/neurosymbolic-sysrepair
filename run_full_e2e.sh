#!/bin/bash
cd /home/resbears/projects/neuroplan
set -a; source .env; set +a
export OPENAI_BASE_URL=https://api.minimax.io/v1 OPENAI_API_KEY="$MINIMAX_API_KEY" PYTHONUNBUFFERED=1
echo "[full-e2e] waiting for vulnhub builds to finish..."
while pgrep -f 'run_pipeline.py.*scenarios vulnhub' >/dev/null 2>&1; do sleep 60; done
echo "[full-e2e] builds done. domains present: $(ls -d pddl_domains_vulnhub_full/vulnhub-*/sysadmin.pddl 2>/dev/null | wc -l)/30"
ALL=$(printf '%02d ' $(seq 1 30))
echo "[full-e2e] running 30 evals (direct API, freed)..."
uv run python run_e2e_vulnhub.py $ALL
echo "[full-e2e] aggregating..."
uv run python aggregate_e2e.py logs_neuroplan_e2e 2>&1 | grep -vE 'WARNING|INFO' | tee vulnhub_table.txt
echo "[full-e2e] DONE -> vulnhub_table.txt"
