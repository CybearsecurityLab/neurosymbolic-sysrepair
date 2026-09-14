#!/usr/bin/env bash
# Launch NeuroPlan over one SysRepair-Bench suite with MiniMax-M2.7.
#
#   ./run_suite.sh ccdc            # whole suite
#   ./run_suite.sh ccdc --scenario 01
#
# KEY CHOICE: MINIMAX_API_KEY (key 1) stopped authenticating on 2026-09-13.
# Both the inspect model provider (OPENAI_API_KEY) and the Phase-1.5 operator
# miner (which reads llm.api_key = ${MINIMAX_API_KEY} out of config.yaml) are
# pointed at key 2 here, because a miner still on the dead key fails silently
# mid-scenario as "no operators mined" rather than as an auth error.
set -euo pipefail
cd /home/resbears/projects/neuroplan
set -a; . ./.env; set +a
# MINIMAX_API_KEY_2 lives only in the benchmark repo's env file, not here.
set -a; . /home/resbears/projects/sysrepair-bench/inspect_eval/.env; set +a

: "${MINIMAX_API_KEY_2:?MINIMAX_API_KEY_2 is not set in .env}"
export MINIMAX_API_KEY="$MINIMAX_API_KEY_2"
export OPENAI_API_KEY="$MINIMAX_API_KEY_2"
export OPENAI_BASE_URL=https://api.minimax.io/v1
export PYTHONUNBUFFERED=1

SUITE="$1"; shift
SLUG="${SUITE//\//_}"
LOGDIR="./logs_bench_${SLUG}"
mkdir -p "$LOGDIR"

exec .venv/bin/python run_bench.py --suite "$SUITE" --logdir "$LOGDIR" "$@"
