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
                    logger.error(f"FAILED {s.id} | {b} | {m}: {e}", exc_info=True)

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

        try:
            # 3. Shell introspection (no osquery)
            system_state = extract_system_state(
                container,
                exec_fn=lambda ctr, cmd: self.docker.exec(ctr, cmd),
            )

            # 4. Build system prompt
            system_prompt = build_system_prompt(scenario, system_state)

            # 5. Start safety monitor
            monitor = SafetyMonitor(
                container,
                scenario,
                exec_fn=lambda ctr, cmd: self.docker.exec(ctr, cmd),
            )
            monitor.start()

            # 6. Create exec_fn for agent (curried with container)
            def exec_fn(cmd: str) -> CommandRecord:
                return self.docker.exec(container, cmd)

            # 7. Load agent
            agent = baseline_factory(baseline_name, model_name, exec_fn, self.ollama_url)

            # 8. Run agent
            result = agent.run(system_prompt=system_prompt)
            result.scenario_id = scenario.id

            # 9. Stop monitor
            violations = monitor.stop()

            # 10. LLM judge for hallucinations (batch)
            os_info = f"{scenario.base_image} ({scenario.collection})"
            result.commands = self.judge.label_batch(
                result.commands,
                vuln_context=scenario.vuln_description[:600],
                os_info=os_info,
            )

            # 11. Run verify.sh oracle
            verify_passed, verify_output = self.docker.exec_verify(container)

            # 12. Compute metrics
            metrics = compute_all_metrics(result, violations, verify_passed)

            # 13. Build and store EvalRecord
            eval_record = self.db.build_eval_record(scenario, result, metrics, violations, verify_output)
            self.db.insert(eval_record)

            return eval_record

        finally:
            # 14. Always destroy container
            self.docker.destroy(container)
