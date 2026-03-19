import sqlite3
import json
import uuid
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional
from baselines.state import AgentResult, CommandRecord
from .metrics import MetricsResult
from .monitor import SafetyViolation


@dataclass
class EvalRecord:
    run_id: str
    scenario_id: str
    collection: str
    category: str
    baseline: str
    model: str
    timestamp: str
    # Execution
    total_commands: int
    wall_time_seconds: float
    declared_done: int
    forced_halt: int
    # Metrics
    por: int
    svr_any: int
    svr_critical: int
    svr_invariant: int
    violation_count: int
    ew_score: float
    false_assumption_count: int
    hallucination_rate: float
    hallucination_count: int
    hallucination_severity_avg: float
    judge_agreement_avg: float
    command_count: int
    plan_length: Optional[int]
    steps_wasted: Optional[int]
    reflection_cycles: Optional[int]
    tree_nodes_visited: Optional[int]
    lats_rollout_count: Optional[int]
    # Raw JSON blobs
    commands_json: str
    violations_json: str
    verify_output: str
    trace_json: str


CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS eval_runs (
    run_id              TEXT PRIMARY KEY,
    scenario_id         TEXT NOT NULL,
    collection          TEXT NOT NULL,
    category            TEXT NOT NULL,
    baseline            TEXT NOT NULL,
    model               TEXT NOT NULL,
    timestamp           TEXT NOT NULL,
    total_commands      INTEGER,
    wall_time_seconds   REAL,
    declared_done       INTEGER,
    forced_halt         INTEGER,
    por                 INTEGER,
    svr_any             INTEGER,
    svr_critical        INTEGER,
    svr_invariant       INTEGER,
    violation_count     INTEGER,
    ew_score            REAL,
    false_assumption_count INTEGER,
    hallucination_rate  REAL,
    hallucination_count INTEGER,
    hallucination_severity_avg REAL,
    judge_agreement_avg REAL,
    command_count       INTEGER,
    plan_length         INTEGER,
    steps_wasted        INTEGER,
    reflection_cycles   INTEGER,
    tree_nodes_visited  INTEGER,
    lats_rollout_count  INTEGER,
    commands_json       TEXT,
    violations_json     TEXT,
    verify_output       TEXT,
    trace_json          TEXT
);
CREATE INDEX IF NOT EXISTS idx_scenario   ON eval_runs(scenario_id);
CREATE INDEX IF NOT EXISTS idx_baseline   ON eval_runs(baseline);
CREATE INDEX IF NOT EXISTS idx_model      ON eval_runs(model);
CREATE INDEX IF NOT EXISTS idx_por        ON eval_runs(por);
CREATE INDEX IF NOT EXISTS idx_composite  ON eval_runs(scenario_id, baseline, model);
"""


class ResultsDB:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(CREATE_TABLE_SQL)

    def insert(self, record: EvalRecord) -> None:
        d = asdict(record)
        cols = ", ".join(d.keys())
        placeholders = ", ".join("?" * len(d))
        with self._conn() as conn:
            conn.execute(
                f"INSERT OR REPLACE INTO eval_runs ({cols}) VALUES ({placeholders})",
                list(d.values()),
            )

    def is_completed(self, scenario_id: str, baseline: str, model: str) -> bool:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM eval_runs WHERE scenario_id=? AND baseline=? AND model=?",
                (scenario_id, baseline, model),
            ).fetchone()
            return row is not None

    def get_all(self) -> list:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM eval_runs ORDER BY scenario_id, baseline, model").fetchall()
            return [dict(r) for r in rows]

    def get_summary(self) -> list:
        """Aggregate metrics grouped by baseline x model."""
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT baseline, model,
                       COUNT(*) as n_runs,
                       AVG(por) * 100 as por_pct,
                       AVG(svr_any) * 100 as svr_pct,
                       AVG(svr_critical) * 100 as svr_critical_pct,
                       AVG(ew_score) as avg_ew,
                       AVG(command_count) as avg_cmds,
                       AVG(wall_time_seconds) as avg_time,
                       AVG(hallucination_rate) * 100 as avg_halluc_pct,
                       AVG(COALESCE(hallucination_severity_avg, 0)) as avg_severity,
                       AVG(COALESCE(judge_agreement_avg, 1)) as avg_judge_agreement
                FROM eval_runs
                GROUP BY baseline, model
                ORDER BY baseline, model
            """).fetchall()
            return [dict(r) for r in rows]

    def build_eval_record(
        self,
        scenario,
        result: AgentResult,
        metrics: MetricsResult,
        violations: list,
        verify_output: str,
    ) -> EvalRecord:
        """Construct EvalRecord from all collected data."""
        commands_json = json.dumps([
            {"step": c.step, "command": c.command, "exit_code": c.exit_code,
             "stdout": c.stdout[:500], "stderr": c.stderr[:300],
             "is_hallucination": c.is_hallucination, "hallucination_severity": c.hallucination_severity,
             "is_false_assumption": c.is_false_assumption,
             "duration_ms": c.duration_ms}
            for c in result.commands
        ])
        violations_json = json.dumps([
            {"level": v.level, "type": v.type, "evidence": v.evidence, "timestamp": v.timestamp}
            for v in violations
        ])
        return EvalRecord(
            run_id=str(uuid.uuid4()),
            scenario_id=scenario.id,
            collection=scenario.collection,
            category=scenario.category,
            baseline=result.baseline,
            model=result.model,
            timestamp=datetime.utcnow().isoformat(),
            total_commands=len(result.commands),
            wall_time_seconds=result.wall_time_seconds,
            declared_done=int(result.declared_done),
            forced_halt=int(result.forced_halt),
            por=metrics.por,
            svr_any=metrics.svr_any,
            svr_critical=metrics.svr_critical,
            svr_invariant=metrics.svr_invariant,
            violation_count=metrics.violation_count,
            ew_score=metrics.ew_score,
            false_assumption_count=metrics.false_assumption_count,
            hallucination_rate=metrics.hallucination_rate,
            hallucination_count=metrics.hallucination_count,
            hallucination_severity_avg=metrics.hallucination_severity_avg,
            judge_agreement_avg=metrics.judge_agreement_avg,
            command_count=metrics.plan_optimality.command_count,
            plan_length=metrics.plan_optimality.plan_length,
            steps_wasted=metrics.plan_optimality.steps_wasted,
            reflection_cycles=result.reflection_cycles,
            tree_nodes_visited=result.tree_nodes_visited,
            lats_rollout_count=result.lats_rollout_count,
            commands_json=commands_json,
            violations_json=violations_json,
            verify_output=verify_output,
            trace_json=json.dumps(result.trace, default=str),
        )
