"""
phase2/supervisor.py

Supervisor agent that orchestrates parallel worker execution.
Updated to pass Phase 1 actions and predicates to workers.
"""

import logging
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
import sys
import os

# Add parent directory to path for common imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import Phase1State, ActionSchema

from phase2.config import HardwareConfig, get_utility_groups
from phase2.models import PartialPDDLDomain
from phase2.llm import LLMInterface
from phase2.worker import WorkerAgent
from phase2.tools import DocumentationExtractor, SystemIntrospector

logger = logging.getLogger("Phase2.Supervisor")


class SupervisorAgent:
    """
    Supervisor agent that orchestrates parallel worker execution.
    Implements the Map phase of Map-Reduce.

    Updated to:
    - Pass Phase 1 actions to workers for reuse
    - Pass known predicates for vocabulary consistency
    - Filter Phase 1 actions by utility group
    """

    def __init__(
        self,
        llm: LLMInterface,
        hardware_config: HardwareConfig,
        phase1_state: Optional[Phase1State] = None,
        phase1_actions: Optional[list[ActionSchema]] = None,
        known_predicates: Optional[list[str]] = None,
        output_dir: str = "./pddl_output",
        reuse_phase1_actions: bool = True,
    ):
        self.llm = llm
        self.hardware = hardware_config
        self.phase1_state = phase1_state or Phase1State()
        self.phase1_actions = phase1_actions or []
        self.known_predicates = known_predicates or []
        self.doc_extractor = DocumentationExtractor()
        self.partial_domains: list[PartialPDDLDomain] = []
        self.log_dir = Path(output_dir) / "llm_logs"
        self.reuse_phase1_actions = reuse_phase1_actions

        # Build utility -> actions mapping for quick lookup
        self._actions_by_utility = self._build_actions_index()
        self.os_capabilities = SystemIntrospector.get_os_capabilities()
        self.utility_groups = get_utility_groups()

        if self.os_capabilities["is_sudo_rs"]:
            logger.info(
                "⚠️  Security Mode: sudo-rs detected. Enforcing strict flag validation."
            )

    def _build_actions_index(self) -> dict[str, list[ActionSchema]]:
        """Build index of Phase 1 actions by source utility."""
        index = {}
        for action in self.phase1_actions:
            utility = action.source_utility
            if utility not in index:
                index[utility] = []
            index[utility].append(action)
        return index

    def _get_actions_for_group(self, group_config: dict) -> list[ActionSchema]:
        """Get Phase 1 actions relevant to a utility group."""
        actions = []
        for utility in group_config.get("utilities", []):
            actions.extend(self._actions_by_utility.get(utility, []))
        return actions

    def _prewarm_doc_cache(self):
        """Fetch all docs sequentially before parallel execution."""
        all_utilities = []
        for name, config in self.utility_groups.items():
            logger.info(f"  {name}: {config['utilities']}")
            all_utilities.extend(config["utilities"])

        logger.info(
            f"Pre-warming documentation cache for {len(all_utilities)} utilities..."
        )
        for utility in all_utilities:
            self.doc_extractor.fetch_man_page(utility)
            self.doc_extractor.fetch_help_output(utility)

    def execute_map_phase(self) -> list[PartialPDDLDomain]:
        """
        Execute the Map phase: dispatch workers in parallel.
        Workers receive Phase 1 actions for their utility group.
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
        logger.info(f"Reuse Phase 1 actions: {self.reuse_phase1_actions}")
        logger.info(f"Known predicates: {len(self.known_predicates)}")

        self._prewarm_doc_cache()
        start_time = time.time()

        # Create worker tasks
        worker_configs = [
            (group_name, config) for group_name, config in self.utility_groups.items()
        ]

        # Report Phase 1 action distribution
        if self.reuse_phase1_actions:
            logger.info("\nPhase 1 actions per group:")
            for group_name, config in worker_configs:
                group_actions = self._get_actions_for_group(config)
                logger.info(f"  {group_name}: {len(group_actions)} actions")

        results = []

        with ThreadPoolExecutor(
            max_workers=self.hardware.max_parallel_workers
        ) as executor:
            future_to_worker = {}

            for group_name, config in worker_configs:
                # =================================================================
                # Get Phase 1 actions for this utility group
                # =================================================================
                group_actions = []
                if self.reuse_phase1_actions:
                    group_actions = self._get_actions_for_group(config)

                # Get relevant osquery data for this group
                osquery_data = self._get_osquery_data_for_group(config)

                worker = WorkerAgent(
                    group_name=group_name,
                    group_config=config,
                    llm=self.llm,
                    doc_extractor=self.doc_extractor,
                    osquery_data=osquery_data,
                    phase1_actions=group_actions,  # Pass Phase 1 actions
                    known_predicates=self.known_predicates,  # Pass known predicates
                    log_dir=str(self.log_dir),
                    reuse_phase1_actions=self.reuse_phase1_actions,
                    os_capabilities=self.os_capabilities,
                )
                future = executor.submit(worker.generate_partial_domain)
                future_to_worker[future] = group_name

            for future in as_completed(future_to_worker):
                worker_name = future_to_worker[future]
                try:
                    result = future.result()
                    has_content = result.types or result.predicates or result.actions
                    if result.error:
                        logger.error(f"  ✗ {worker_name} failed: {result.error}")
                    elif not has_content:
                        logger.warning(
                            f"  ⚠ {worker_name} completed but generated no content"
                        )
                    else:
                        # Count reused vs new actions
                        reused = sum(
                            1
                            for a in result.actions
                            if getattr(a, "source_worker", "") == "phase1_reuse"
                        )
                        new = len(result.actions) - reused
                        logger.info(
                            f"  ✓ {worker_name}: {len(result.actions)} actions "
                            f"(reused: {reused}, new: {new})"
                        )
                    results.append(result)
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

    def _get_osquery_data_for_group(self, group_config: dict) -> dict:
        """Extract osquery data relevant to a utility group."""
        osquery_data = {}

        for table in group_config.get("osquery_tables", []):
            if table in self.phase1_state.objects:
                osquery_data[table] = self.phase1_state.objects[table]

        return osquery_data
