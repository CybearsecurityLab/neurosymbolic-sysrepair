import json
import time
import uuid
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable
from baselines import baseline_factory
from baselines.state import CommandRecord
from .scenario_loader import Scenario, load_scenarios, load_all_scenarios
from .docker_manager import DockerManager
from .system_introspector import extract_system_state, build_system_prompt
from .monitor import SafetyMonitor
from .metrics import HallucinationJudge, compute_all_metrics
from .results_db import ResultsDB, EvalRecord

logger = logging.getLogger(__name__)

BASELINE_NAMES = ["raw", "react", "plan_and_solve", "reflexion", "lats"]


class EvalHarness:
    def __init__(
        self,
        bench_root: Path,
        results_db_path: Path,
        ollama_url: str = "http://localhost:11434/v1",
        max_parallel: int = 2,
    ):
        self.bench_root = Path(bench_root)
        self.db = ResultsDB(results_db_path)
        self.ollama_url = ollama_url
        self.max_parallel = max_parallel
        self.docker = DockerManager()
        self.judge = HallucinationJudge(ollama_url)

    def run_all(
        self,
        baselines: list,
        models: list,
        scenarios: list | None = None,
        resume: bool = True,
    ) -> list:
        if scenarios is None:
            scenarios = load_all_scenarios(self.bench_root)

        # Build run matrix: (scenario, baseline, model)
        tasks = [
            (s, b, m)
            for s in scenarios
            for b in baselines
            for m in models
        ]

        if resume:
            tasks = [(s, b, m) for s, b, m in tasks
                     if not self.db.is_completed(s.id, b, m)]

        logger.info(
            f"Running {len(tasks)} evaluations "
            f"({len(scenarios)} scenarios x {len(baselines)} baselines x {len(models)} models)"
        )

        records = []
        with ThreadPoolExecutor(max_workers=self.max_parallel) as executor:
            futures = {executor.submit(self.run_one, s, b, m): (s, b, m)
                       for s, b, m in tasks}
            for future in as_completed(futures):
                s, b, m = futures[future]
                try:
                    record = future.result()
                    records.append(record)
                    por_str = "pass" if record.por else "fail"
                    logger.info(
                        f"[{por_str}] {s.id} | {b} | {m} | "
                        f"EW={record.ew_score:.2f} | HR={record.hallucination_rate:.2f}"
                    )
                except Exception as e:
                    logger.error(
                        f"FAILED {s.id} | {b} | {m} | error_type={type(e).__name__} | {e}",
                        exc_info=True,
                    )

        return records

    def run_one(
        self,
        scenario: Scenario,
        baseline_name: str,
        model_name: str,
    ) -> EvalRecord:
        run_id = str(uuid.uuid4())[:8]
        logger.info(f"Starting run {run_id}: {scenario.id} | {baseline_name} | {model_name}")

        # 1. Build Docker image (cached)
        image_tag = f"sysrepair-{scenario.id}:latest"
        try:
            self.docker.build_image(scenario, image_tag)
        except Exception as e:
            logger.error(f"Failed to build image for {scenario.id}: {e}")
            raise

        # 2. Spawn container
        container = self.docker.spawn_container(image_tag, run_id)

        # Mutable container holder so recreation is transparent to the agent
        ctr_holder = [container]

        try:
            # 2b. Copy verify.sh into container
            self.docker.copy_verify_script(ctr_holder[0], scenario.verify_sh_path)

            # 3. Shell introspection (no osquery)
            system_state = extract_system_state(
                ctr_holder[0],
                exec_fn=lambda ctr, cmd: self.docker.exec(ctr, cmd),
            )

            # 4. Build system prompt
            system_prompt = build_system_prompt(scenario, system_state)

            # 5. Start safety monitor
            monitor = SafetyMonitor(
                ctr_holder[0],
                scenario,
                exec_fn=lambda ctr, cmd: self.docker.exec(ctr, cmd),
            )
            monitor.start()

            # 6. Create exec_fn and verify_fn that check for container recreation
            def exec_fn(cmd: str) -> CommandRecord:
                record = self.docker.exec(ctr_holder[0], cmd)
                # If a crash triggered recreation, swap to the new container
                new_ctr = self.docker.get_recreated_container()
                if new_ctr is not None:
                    logger.warning(
                        f"[{run_id}] {scenario.id} | {baseline_name} | {model_name} | "
                        f"Container recreated after crash, swapping reference"
                    )
                    ctr_holder[0] = new_ctr
                return record

            def verify_fn() -> tuple[bool, str]:
                return self.docker.exec_verify(ctr_holder[0])

            # 7. Load agent
            agent = baseline_factory(baseline_name, model_name, exec_fn, self.ollama_url, verify_fn=verify_fn)

            # 8. Run agent
            result = agent.run(system_prompt=system_prompt)
            result.scenario_id = scenario.id

            # 9. Stop monitor
            violations = monitor.stop()

            # Log crash count for this run
            crash_count = self.docker.get_crash_count(ctr_holder[0])
            if crash_count > 0:
                logger.warning(
                    f"[{run_id}] {scenario.id} | {baseline_name} | {model_name} | "
                    f"Container crashed {crash_count} time(s) during run"
                )

            # 10. LLM judge for hallucinations (batch)
            os_info = f"{scenario.base_image} ({scenario.collection})"
            result.commands = self.judge.label_batch(
                result.commands,
                vuln_context=scenario.vuln_description[:600],
                os_info=os_info,
            )

            # 11. Run verify.sh oracle
            verify_passed, verify_output = self.docker.exec_verify(ctr_holder[0])

            # 12. Compute metrics
            metrics = compute_all_metrics(result, violations, verify_passed)

            # 13. Save trace log file
            trace_dir = self.db.db_path.parent / "traces" / scenario.id / baseline_name
            trace_dir.mkdir(parents=True, exist_ok=True)
            trace_file = trace_dir / f"{model_name}.json"
            trace_file.write_text(json.dumps(result.trace, indent=2, default=str))
            logger.info(f"Trace saved to {trace_file}")

            # 14. Build and store EvalRecord
            eval_record = self.db.build_eval_record(scenario, result, metrics, violations, verify_output)
            self.db.insert(eval_record)

            return eval_record

        finally:
            # Always destroy container (use current holder in case it was recreated)
            self.docker.destroy(ctr_holder[0])
