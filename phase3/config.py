"""
Configuration for Phase 3: Iterative Refinement via Exploration Walks
"""

import os
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("Phase3.Config")


@dataclass
class DockerConfig:
    """Docker container configuration for sandboxed execution."""

    image: str = "ubuntu:25.10"
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
        }


@dataclass
class PlannerConfig:
    """Fast Downward planner configuration."""

    # Path to Fast Downward
    fast_downward_path: str = "/usr/local/bin/fast-downward.py"

    # Search configuration for random walks
    search_config: str = "eager_greedy([ff()])"

    # Random walk parameters
    default_walk_depth: int = 5  # Max actions per walk
    default_num_walks: int = 10  # Number of exploration walks

    # Timeout for planning
    plan_timeout: int = 60  # seconds

    # Temporary directory for PDDL files
    temp_dir: str = "/tmp/pddl_planning"


@dataclass
class LLMRefinementConfig:
    """LLM configuration for domain refinement."""

    model_name: str = "mistralai/Mistral-7B-Instruct-v0.3"
    base_url: str = "http://localhost:8000/v1"
    max_tokens: int = 4096
    temperature: float = 0.2  # Slightly higher for creative fixes

    # Prompting
    max_feedback_items: int = 10  # Max discrepancies to include in prompt
    max_retries: int = 3  # Retries per refinement attempt


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
    walks_per_iteration: int = 10  # N in EW formula
    walk_depth: int = 5  # T_max in EW formula

    # I/O
    input_domain_path: str = "./pddl_output/sysadmin.pddl"
    input_problem_path: str = "./pddl_output/problem.pddl"
    output_dir: str = "./pddl_output/phase3"

    # Logging
    log_level: str = "INFO"
    save_intermediate_domains: bool = True

    # Mock mode for testing
    use_mock_docker: bool = False
    use_mock_planner: bool = False
    use_mock_llm: bool = False

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


# Action concretization mapping: PDDL action patterns -> bash templates
ACTION_TEMPLATES = {
    # Package management
    "install_package": "apt-get install -y {package}",
    "remove_package": "apt-get remove -y {package}",
    "purge_package": "apt-get purge -y {package}",
    "update_package_list": "apt-get update",
    "upgrade_packages": "apt-get upgrade -y",
    "upgrade_package": "apt-get install --only-upgrade -y {package}",

    # Service management
    "start_service": "systemctl start {service}",
    "stop_service": "systemctl stop {service}",
    "restart_service": "systemctl restart {service}",
    "enable_service": "systemctl enable {service}",
    "disable_service": "systemctl disable {service}",
    "reload_service": "systemctl reload {service}",

    # User management
    "create_user": "useradd {user}",
    "delete_user": "userdel {user}",
    "lock_user": "usermod -L {user}",
    "unlock_user": "usermod -U {user}",
    "add_user_to_group": "usermod -aG {group} {user}",

    # Group management
    "create_group": "groupadd {group}",
    "delete_group": "groupdel {group}",

    # File operations
    "create_file": "touch {file}",
    "delete_file": "rm -f {file}",
    "create_directory": "mkdir -p {directory}",
    "delete_directory": "rm -rf {directory}",
    "set_file_permissions": "chmod {mode} {file}",
    "set_file_owner": "chown {user}:{group} {file}",
    "copy_file": "cp {source} {destination}",
    "move_file": "mv {source} {destination}",

    # Network/firewall (basic)
    "allow_port": "ufw allow {port}",
    "deny_port": "ufw deny {port}",
    "enable_firewall": "ufw --force enable",
    "disable_firewall": "ufw disable",
}

# Predicate state checks: how to verify PDDL predicates in the real environment
PREDICATE_CHECKS = {
    # Package predicates
    "package_installed": "dpkg -s {package} 2>/dev/null | grep -q 'Status: install ok installed'",
    "package_outdated": "apt list --upgradable 2>/dev/null | grep -q '^{package}/'",

    # Service predicates
    "service_running": "systemctl is-active --quiet {service}",
    "service_enabled": "systemctl is-enabled --quiet {service}",
    "service_failed": "systemctl is-failed --quiet {service}",

    # User predicates
    "user_exists": "id {user} >/dev/null 2>&1",
    "user_locked": "passwd -S {user} 2>/dev/null | grep -q ' L '",

    # Group predicates
    "group_exists": "getent group {group} >/dev/null 2>&1",
    "member_of": "id -nG {user} 2>/dev/null | grep -qw {group}",

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
