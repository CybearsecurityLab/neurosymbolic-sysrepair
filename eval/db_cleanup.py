#!/usr/bin/env python3
"""
db_cleanup.py — Identify and remove bad runs from the eval results DB.

Usage:
  # Show all bad runs (dry run)
  python -m eval.db_cleanup eval/results/eval_results.db

  # Delete bad runs
  python -m eval.db_cleanup eval/results/eval_results.db --delete

  # Delete only crash-affected runs
  python -m eval.db_cleanup eval/results/eval_results.db --delete --only crashes

  # Delete only specific scenarios
  python -m eval.db_cleanup eval/results/eval_results.db --delete --scenario ccdc-09

  # Deduplicate: keep only the best (highest por, then ew_score) run per (scenario, baseline, model)
  python -m eval.db_cleanup eval/results/eval_results.db --delete --dedup
"""

import argparse
import sqlite3
import sys
from pathlib import Path


def get_crash_runs(conn):
    """Runs where commands_json contains CONTAINER_CRASH."""
    rows = conn.execute(
        "SELECT run_id, scenario_id, baseline, model, total_commands, wall_time_seconds, ew_score "
        "FROM eval_runs WHERE commands_json LIKE '%CONTAINER_CRASH%'"
    ).fetchall()
    return [dict(r) for r in rows]


def get_zero_command_runs(conn):
    """Runs with 0 commands executed (likely LLM or container failure)."""
    rows = conn.execute(
        "SELECT run_id, scenario_id, baseline, model, total_commands, wall_time_seconds, ew_score "
        "FROM eval_runs WHERE total_commands = 0"
    ).fetchall()
    return [dict(r) for r in rows]


def get_empty_trace_runs(conn):
    """Runs where trace_json is empty or null."""
    rows = conn.execute(
        "SELECT run_id, scenario_id, baseline, model, total_commands, wall_time_seconds, ew_score "
        "FROM eval_runs WHERE trace_json IS NULL OR trace_json = '[]' OR trace_json = 'null'"
    ).fetchall()
    return [dict(r) for r in rows]


def get_duplicate_runs(conn):
    """For each (scenario, baseline, model) with multiple runs, return the ones to delete
    (keep the best: highest por, then highest ew_score, then most commands)."""
    dupes = conn.execute("""
        SELECT scenario_id, baseline, model, COUNT(*) as cnt
        FROM eval_runs
        GROUP BY scenario_id, baseline, model
        HAVING cnt > 1
    """).fetchall()

    to_delete = []
    for d in dupes:
        rows = conn.execute(
            "SELECT run_id, scenario_id, baseline, model, total_commands, "
            "wall_time_seconds, por, ew_score "
            "FROM eval_runs "
            "WHERE scenario_id=? AND baseline=? AND model=? "
            "ORDER BY por DESC, ew_score DESC, total_commands DESC",
            (d["scenario_id"], d["baseline"], d["model"]),
        ).fetchall()
        # Keep the first (best), delete the rest
        for r in rows[1:]:
            to_delete.append(dict(r))
    return to_delete


def print_runs(label, runs):
    if not runs:
        print(f"\n{label}: (none)")
        return
    print(f"\n{label}: {len(runs)} runs")
    for r in runs:
        print(
            f"  {r['run_id'][:8]} | {r['scenario_id']} | {r['baseline']} | "
            f"{r['model']} | cmds={r['total_commands']} | "
            f"wall={r.get('wall_time_seconds', 0):.0f}s | "
            f"ew={r.get('ew_score', 0):.2f}"
        )


def delete_runs(conn, run_ids, label):
    if not run_ids:
        return
    placeholders = ",".join("?" * len(run_ids))
    conn.execute(f"DELETE FROM eval_runs WHERE run_id IN ({placeholders})", run_ids)
    conn.commit()
    print(f"  Deleted {len(run_ids)} {label} runs")


def main():
    p = argparse.ArgumentParser(description="Identify and remove bad eval runs")
    p.add_argument("db", type=Path, help="Path to eval_results.db")
    p.add_argument("--delete", action="store_true", help="Actually delete (default: dry run)")
    p.add_argument(
        "--only",
        choices=["crashes", "zero_cmds", "empty_traces", "all"],
        default="all",
        help="Which category of bad runs to target",
    )
    p.add_argument("--scenario", nargs="+", default=None, help="Filter to specific scenario IDs")
    p.add_argument("--dedup", action="store_true", help="Remove duplicate runs, keep best")
    args = p.parse_args()

    conn = sqlite3.connect(str(args.db))
    conn.row_factory = sqlite3.Row

    total_before = conn.execute("SELECT COUNT(*) FROM eval_runs").fetchone()[0]
    print(f"Total runs in DB: {total_before}")

    to_delete_ids = set()

    if args.only in ("crashes", "all"):
        crashes = get_crash_runs(conn)
        if args.scenario:
            crashes = [r for r in crashes if r["scenario_id"] in args.scenario]
        print_runs("Container crash runs", crashes)
        to_delete_ids.update(r["run_id"] for r in crashes)

    if args.only in ("zero_cmds", "all"):
        zeros = get_zero_command_runs(conn)
        if args.scenario:
            zeros = [r for r in zeros if r["scenario_id"] in args.scenario]
        print_runs("Zero-command runs", zeros)
        to_delete_ids.update(r["run_id"] for r in zeros)

    if args.only in ("empty_traces", "all"):
        empties = get_empty_trace_runs(conn)
        if args.scenario:
            empties = [r for r in empties if r["scenario_id"] in args.scenario]
        print_runs("Empty-trace runs", empties)
        to_delete_ids.update(r["run_id"] for r in empties)

    if args.dedup:
        dupes = get_duplicate_runs(conn)
        if args.scenario:
            dupes = [r for r in dupes if r["scenario_id"] in args.scenario]
        print_runs("Duplicate runs (keeping best)", dupes)
        to_delete_ids.update(r["run_id"] for r in dupes)

    print(f"\nTotal runs to delete: {len(to_delete_ids)}")

    if args.delete and to_delete_ids:
        delete_runs(conn, list(to_delete_ids), "bad")
        total_after = conn.execute("SELECT COUNT(*) FROM eval_runs").fetchone()[0]
        print(f"Runs remaining: {total_after}")
    elif to_delete_ids:
        print("(dry run — pass --delete to actually remove)")

    conn.close()


if __name__ == "__main__":
    main()
