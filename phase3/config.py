"""
Configuration for Phase 3: Iterative Refinement via Exploration Walks
"""

import os
import logging
import threading
from dataclasses import dataclass, field

logger = logging.getLogger("Phase3.Config")

# Concurrency cap for Phase 3 LLM calls. Bound to the MiniMax per-account
# concurrent limit (~6), not a fixed 8, so a phase-3 refinement pass does not
# 429 and drop repairs. Overridable via NEUROPLAN_MAX_WORKERS.
LLM_CONCURRENCY_GATE = threading.Semaphore(int(os.environ.get("NEUROPLAN_MAX_WORKERS", "6")))


@dataclass
class DockerConfig:
    """Docker container configuration for sandboxed execution."""

    image: str = "pddl-sandbox:latest"
    container_name: str = "pddl-sandbox"

    # Resource limits
    mem_limit: str = "4g"
    cpu_count: int = 2

    # Timeouts
    exec_timeout: int = 30  # seconds per command
    startup_timeout: int = 60  # seconds to wait for container

    # Networking
    network_mode: str = "none"  # Isolated by default

    # Volumes (read-only mounts if needed)
    volumes: dict = field(default_factory=dict)

    # Container lifecycle
    auto_remove: bool = False  # Keep for debugging
    detach: bool = True
    tty: bool = True

    def to_docker_kwargs(self) -> dict:
        """Convert to docker.containers.run() kwargs."""
        return {
            "image": self.image,
            "name": self.container_name,
            "mem_limit": self.mem_limit,
            "cpu_count": self.cpu_count,
            "network_mode": self.network_mode,
            "volumes": self.volumes,
            "auto_remove": self.auto_remove,
            "detach": self.detach,
            "tty": self.tty,
            # Capabilities needed for iptables/ufw/modprobe
            "cap_add": ["NET_ADMIN", "SYS_MODULE"],
            # tmpfs for systemctl shim runtime state
            "tmpfs": {"/run": ""},
        }


@dataclass
class PlannerConfig:
    """Fast Downward planner configuration."""

    # Path to Fast Downward
    fast_downward_path: str = "/home/resbears/fast_downward/fast-downward.py"

    # Search configuration for random walks
    search_config: str = "eager_greedy([ff()])"

    # Random walk parameters
    default_walk_depth: int = 5  # Max actions per walk
    default_num_walks: int = 10  # Number of exploration walks

    # Timeout for planning
    plan_timeout: int = 300  # seconds (large domains need more time)

    # Temporary directory for PDDL files
    temp_dir: str = "/tmp/pddl_planning"


@dataclass
class LLMRefinementConfig:
    """LLM configuration for domain refinement."""

    model_name: str = "gemma-4-31b"
    base_url: str = "http://localhost:8001/v1"
    api_key: str = "vllm"
    max_tokens: int = 4096
    temperature: float = 0.3

    # Prompting
    max_feedback_items: int = 10  # Max discrepancies to include in prompt
    max_retries: int = 3  # Retries per refinement attempt

    # Concretizer LLM (action→bash translation via OpenAI-compatible API)
    concretizer_model: str = "gemma-4-31b"
    concretizer_max_tokens: int = 4096
    concretizer_temperature: float = 0.6


@dataclass
class Phase3Config:
    """Main configuration for Phase 3."""

    # Sub-configurations
    docker: DockerConfig = field(default_factory=DockerConfig)
    planner: PlannerConfig = field(default_factory=PlannerConfig)
    llm: LLMRefinementConfig = field(default_factory=LLMRefinementConfig)

    # Exploration Walk parameters
    ew_target_score: float = 0.9  # Target EW score to achieve
    max_refinement_iterations: int = 10  # Max iterations before giving up
    walks_per_iteration: int = 10  # N in EW formula (default; overridden by auto-scale)
    walk_depth: int = 5  # T_max in EW formula (default; overridden by auto-scale)
    ew_params_explicitly_set: bool = False  # True if user provided --walks/--depth

    # I/O
    input_domain_path: str = "./pddl_output/sysadmin.pddl"
    input_problem_path: str = "./pddl_output/problem.pddl"
    output_dir: str = "./pddl_output/phase3"

    # Logging
    log_level: str = "INFO"
    save_intermediate_domains: bool = True

    # Concretizer
    phase1_metadata_path: str = "./pddl_output/phase1/phase1_statep2.json"
    concretizer_cache_path: str = ""  # defaults to output_dir/concretizer_cache.json

    def auto_scale_ew_params(self, num_actions: int) -> None:
        """
        Auto-scale EW parameters based on domain size, ONLY if the user
        did not explicitly set them via CLI args.

        Formulas:
        - walks_per_iteration = clamp(num_actions // 10, 30, 100)
        - walk_depth = clamp(num_actions // 100, 8, 20)

        For 1,132 actions: walks=100, depth=11 -> 1,100 total steps
        For 50 actions: walks=30, depth=8 -> 240 total steps
        For 500 actions: walks=50, depth=8 -> 400 total steps
        """
        if self.ew_params_explicitly_set:
            logger.info(
                f"EW params explicitly set by user: "
                f"walks={self.walks_per_iteration}, depth={self.walk_depth}"
            )
            return

        self.walks_per_iteration = max(30, min(100, num_actions // 10))
        self.walk_depth = max(8, min(20, num_actions // 100))

        logger.info(
            f"Auto-scaled EW params for {num_actions} actions: "
            f"walks={self.walks_per_iteration}, depth={self.walk_depth} "
            f"(~{self.walks_per_iteration * self.walk_depth} total steps/iteration)"
        )

    @classmethod
    def from_env(cls) -> "Phase3Config":
        """Create config from environment variables."""
        config = cls()

        # Override from environment
        if os.environ.get("PDDL_DOMAIN_PATH"):
            config.input_domain_path = os.environ["PDDL_DOMAIN_PATH"]
        if os.environ.get("PDDL_PROBLEM_PATH"):
            config.input_problem_path = os.environ["PDDL_PROBLEM_PATH"]
        if os.environ.get("PHASE3_OUTPUT_DIR"):
            config.output_dir = os.environ["PHASE3_OUTPUT_DIR"]
        if os.environ.get("EW_TARGET_SCORE"):
            config.ew_target_score = float(os.environ["EW_TARGET_SCORE"])
        if os.environ.get("LLM_BASE_URL"):
            config.llm.base_url = os.environ["LLM_BASE_URL"]
        if os.environ.get("LLM_MODEL"):
            config.llm.model_name = os.environ["LLM_MODEL"]
        if os.environ.get("DOCKER_IMAGE"):
            config.docker.image = os.environ["DOCKER_IMAGE"]

        return config



# Predicate state checks: how to verify PDDL predicates in the real environment
PREDICATE_CHECKS = {
    # Package predicates
    "package_installed": "dpkg -s {package} 2>/dev/null | grep -q 'Status: install ok installed'",
    "package_outdated": "apt list --upgradable 2>/dev/null | grep -q '^{package}/'",
    "package": "dpkg -s {package} 2>/dev/null | grep -q 'Status: install ok installed'",
    # Service predicates
    "service_running": "systemctl is-active --quiet {service}",
    "service_enabled": "systemctl is-enabled --quiet {service}",
    "service_failed": "systemctl is-failed --quiet {service}",
    "service": "systemctl is-active --quiet {service} 2>/dev/null || systemctl list-unit-files {service}.service --no-pager -q | grep -q .",
    # User predicates
    "user_exists": "id {user} >/dev/null 2>&1",
    "user_locked": "passwd -S {user} 2>/dev/null | grep -q ' L '",
    "user": "id {user} >/dev/null 2>&1",
    # Group predicates
    "group_exists": "getent group {group} >/dev/null 2>&1",
    "member_of": "id -nG {user} 2>/dev/null | grep -qw {group}",
    "group": "getent group {group} >/dev/null 2>&1",
    # File predicates
    "file_exists": "test -e {file}",
    "file_readable": "test -r {file}",
    "file_writable": "test -w {file}",
    "file_executable": "test -x {file}",
    "directory_exists": "test -d {directory}",
    # Network predicates
    "port_open": "ss -tuln | grep -q ':{port} '",
    "interface_up": "ip link show {interface} | grep -q 'state UP'",
}
