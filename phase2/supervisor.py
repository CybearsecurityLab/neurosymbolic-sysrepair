import logging
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from .config import HardwareConfig, UTILITY_GROUPS
from .models import PartialPDDLDomain
from .llm import LLMInterface
from .worker import WorkerAgent
from .tools import DocumentationExtractor

logger = logging.getLogger("Phase2.Supervisor")

class SupervisorAgent:
    """
    Supervisor agent that orchestrates parallel worker execution.
    Implements the Map phase of Map-Reduce.
    """

    def __init__(
            self,
            llm: LLMInterface,
            hardware_config: HardwareConfig,
            osquery_data: Optional[dict] = None,
            output_dir: str = "./pddl_output",
    ):
        self.llm = llm
        self.hardware = hardware_config
        self.osquery_data = osquery_data or {}
        self.doc_extractor = DocumentationExtractor()
        self.partial_domains: list[PartialPDDLDomain] = []
        self.log_dir = Path(output_dir) / "llm_logs"

    def execute_map_phase(self) -> list[PartialPDDLDomain]:
        """
        Execute the Map phase: dispatch workers in parallel.
        """
        logger.info("=" * 60)
        logger.info("MAP PHASE: Dispatching Worker Agents")
        logger.info("=" * 60)
        logger.info(
            f"Hardware: {self.hardware.num_gpus} GPUs, "
            f"{self.hardware.num_cpus} CPUs, "
            f"{self.hardware.total_ram_gb:.0f}GB RAM"
        )
        logger.info(f"Max parallel workers: {self.hardware.max_parallel_workers}")

        start_time = time.time()

        # Create worker tasks
        worker_configs = [
            (group_name, config) for group_name, config in UTILITY_GROUPS.items()
        ]

        # Execute workers in parallel using ThreadPoolExecutor
        # (GPU-bound via LLM, so threads are fine)
        results = []

        with ThreadPoolExecutor(
                max_workers=self.hardware.max_parallel_workers
        ) as executor:
            future_to_worker = {}

            for group_name, config in worker_configs:
                worker = WorkerAgent(
                    group_name=group_name,
                    group_config=config,
                    llm=self.llm,
                    doc_extractor=self.doc_extractor,
                    osquery_data=self.osquery_data,
                    log_dir=str(self.log_dir),
                )
                future = executor.submit(worker.generate_partial_domain)
                future_to_worker[future] = group_name

            for future in as_completed(future_to_worker):
                worker_name = future_to_worker[future]
                try:
                    result = future.result()
                    results.append(result)
                    logger.info(f"  ✓ {worker_name} completed")
                except Exception as e:
                    logger.error(f"  ✗ {worker_name} failed: {e}")
                    results.append(
                        PartialPDDLDomain(
                            worker_name=f"{worker_name}_agent",
                            group_name=worker_name,
                            error=str(e),
                        )
                    )

        elapsed = time.time() - start_time
        logger.info(f"Map phase completed in {elapsed:.2f}s")
        logger.info(
            f"Successful workers: {sum(1 for r in results if not r.error)}/{len(results)}"
        )

        self.partial_domains = results
        return results