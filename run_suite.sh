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
# Paths are resolved relative to this script, not to one machine: the Windows
# suites run on a host with the Windows docker engine where nothing lives under
# /home/resbears. Override BENCH_ENV if the benchmark checkout is not a sibling.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
set -a; . ./.env; set +a
# MINIMAX_API_KEY_2 lives only in the benchmark repo's env file, not here.
BENCH_ENV="${BENCH_ENV:-$HERE/../sysrepair-bench/inspect_eval/.env}"
[ -f "$BENCH_ENV" ] || { echo "benchmark .env not found at $BENCH_ENV; set BENCH_ENV" >&2; exit 1; }
set -a; . "$BENCH_ENV"; set +a

: "${MINIMAX_API_KEY_2:?MINIMAX_API_KEY_2 is not set in .env}"
export MINIMAX_API_KEY="$MINIMAX_API_KEY_2"
export OPENAI_API_KEY="$MINIMAX_API_KEY_2"
export OPENAI_BASE_URL=https://api.minimax.io/v1
export PYTHONUNBUFFERED=1

SUITE="$1"; shift
SLUG="${SUITE//\//_}"
LOGDIR="./logs_bench_${SLUG}"
mkdir -p "$LOGDIR"

# run_bench.py imports inspect_ai IN-PROCESS, so this interpreter is the one
# that talks to the docker engine. On a Windows-engine host it must therefore be
# the Windows venv, whose interpreter is .venv/Scripts/python.exe.
PY="$HERE/.venv/bin/python"
[ -x "$PY" ] || PY="$HERE/.venv/Scripts/python.exe"
[ -x "$PY" ] || { echo "no venv interpreter at $HERE/.venv/{bin/python,Scripts/python.exe}" >&2; exit 1; }
exec "$PY" run_bench.py --suite "$SUITE" --logdir "$LOGDIR" "$@"
