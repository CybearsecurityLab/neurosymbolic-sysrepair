"""
phase2/config.py

Configuration for Phase 2: Parallel Synthesis.
Defines utility groups, hardware detection, and LLM settings.
"""

import os
from dataclasses import dataclass
import shutil
import psutil
import subprocess
from typing import Optional
from common.models import Phase1State

# =============================================================================
# Utility Groups for Worker Distribution
# =============================================================================

UTILITY_GROUP_CANDIDATES = {
    "package_management": {
        "description": "Package installation, removal, and updates",
        "utilities": ["apt", "apt-get", "dpkg", "snap", "flatpak"],
        "pddl_focus": ["package", "repository"],
        "osquery_tables": ["deb_packages", "apt_sources"],
    },
    "service_management": {
        "description": "Service lifecycle and configuration",
        "utilities": ["systemctl", "service", "journalctl"],
        "pddl_focus": ["service", "configuration_file"],
        "osquery_tables": ["systemd_units"],
    },
    "user_management": {
        "description": "User and group administration",
        "utilities": ["useradd", "usermod", "userdel", "groupadd", "passwd", "chage"],
        "pddl_focus": ["user", "group"],
        "osquery_tables": ["users", "groups", "user_groups"],
    },
    "file_management": {
        "description": "File and directory operations",
        "utilities": ["cp", "mv", "rm", "mkdir", "chmod", "chown", "ln"],
        "pddl_focus": ["file", "directory"],
        "osquery_tables": ["file"],
    },
    "network_management": {
        "description": "Network configuration and firewall",
        "utilities": ["ip", "netplan", "ufw", "iptables", "ss", "nft"],
        "pddl_focus": ["interface", "port", "firewall_rule"],
        "osquery_tables": ["interface_addresses", "listening_ports", "iptables"],
    },
    "process_management": {
        "description": "Process control and monitoring",
        "utilities": ["kill", "pkill", "nice", "renice", "nohup"],
        "pddl_focus": ["process"],
        "osquery_tables": ["processes"],
    },
    "privilege_escalation": {
        "description": "Privilege management (sudo-rs for Ubuntu 25.10)",
        "utilities": ["sudo", "su", "visudo"],
        "pddl_focus": ["user"],
        "osquery_tables": ["sudoers"],
    },
}

# =============================================================================
# Dynamic Discovery Functions
# =============================================================================


def discover_available_utilities(candidates: list[str]) -> list[str]:
    """
    Check which utilities from a candidate list are actually installed.
    Uses shutil.which() to find executables in PATH.
    """
    available = []
    for utility in candidates:
        path = shutil.which(utility)
        if path:
            available.append(utility)
    return available


def discover_all_system_commands() -> set[str]:
    """
    Discover ALL available commands on the system.
    Useful for finding utilities you didn't know about.
    """
    commands = set()

    # Method 1: Scan standard binary directories
    bin_dirs = [
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
    ]

    for dir_path in bin_dirs:
        try:
            import os

            if os.path.isdir(dir_path):
                for entry in os.listdir(dir_path):
                    full_path = os.path.join(dir_path, entry)
                    if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                        commands.add(entry)
        except PermissionError:
            pass

    return commands


def get_installed_packages() -> list[str]:
    """
    Get list of installed package names via dpkg.
    """
    try:
        result = subprocess.run(
            ["dpkg-query", "-f", "${Package}\n", "-W"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return result.stdout.strip().split("\n")
    except Exception:
        pass
    return []


def check_osquery_tables() -> list[str]:
    """
    Discover which osquery tables are actually available.
    """
    try:
        result = subprocess.run(
            [
                "osqueryi",
                "--json",
                "SELECT name FROM osquery_registry WHERE registry='table'",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            import json

            data = json.loads(result.stdout)
            return [row["name"] for row in data]
    except Exception:
        pass
    return []


# =============================================================================
# Build VALIDATED Utility Groups at Runtime
# =============================================================================


def build_utility_groups(phase1_state: Optional["Phase1State"] = None) -> dict:
    """
    Build utility groups with only ACTUALLY INSTALLED utilities.

    Args:
        phase1_state: Optional Phase 1 state object. If provided, 'pddl_focus'
                      will be filtered to only include types that actually exist
                      in the discovered system objects.
    """
    validated_groups = {}
    available_osquery_tables = set(check_osquery_tables())

    for group_name, config in UTILITY_GROUP_CANDIDATES.items():
        # Filter to only installed utilities
        available_utilities = discover_available_utilities(config["utilities"])

        if not available_utilities:
            # Skip groups with no available utilities
            continue

        # Filter to only available osquery tables
        available_tables = [
            t for t in config.get("osquery_tables", []) if t in available_osquery_tables
        ]

        # --- DYNAMIC PDDL FOCUS FIX ---
        # If Phase 1 state is available, filter pddl_focus types to those
        # that actually exist in the system.
        pddl_focus = config["pddl_focus"]
        if phase1_state and hasattr(phase1_state, "objects"):
            pddl_focus = [
                t
                for t in pddl_focus
                if t in phase1_state.objects and phase1_state.objects[t]
            ]
        # ------------------------------

        validated_groups[group_name] = {
            "description": config["description"],
            "utilities": available_utilities,
            "pddl_focus": pddl_focus,
            "osquery_tables": available_tables,
        }

    return validated_groups


# For backwards compatibility, but now it's dynamic
def get_utility_groups(phase1_state: Optional["Phase1State"] = None) -> dict:
    """Get validated utility groups. Call this instead of using UTILITY_GROUPS directly."""
    return build_utility_groups(phase1_state)


# =============================================================================
# Hardware Configuration
# =============================================================================


@dataclass
class HardwareConfig:
    """Hardware configuration for resource allocation."""

    num_gpus: int = 0
    gpu_memory_gb: float = 0.0
    num_cpus: int = 1
    total_ram_gb: float = 8.0
    max_parallel_workers: int = 1

    @classmethod
    def detect(cls) -> "HardwareConfig":
        """Auto-detect hardware capabilities."""
        config = cls()

        # Detect CPUs
        config.num_cpus = os.cpu_count() or 1

        # Detect RAM
        config.total_ram_gb = psutil.virtual_memory().total / (1024**3)

        # Detect GPUs (try nvidia-smi)
        try:
            import subprocess

            result = subprocess.run(
                [
                    "nvidia-smi",
                    "--query-gpu=count,memory.total",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                config.num_gpus = len(lines)
                # Parse memory from first GPU
                if lines:
                    parts = lines[0].split(",")
                    if len(parts) >= 2:
                        config.gpu_memory_gb = float(parts[1].strip()) / 1024
        except Exception:
            pass

        # Calculate max parallel workers
        if config.num_gpus > 0:
            # GPU-based: limited by VRAM for LLM inference
            config.max_parallel_workers = min(
                config.num_gpus * 2,  # 2 workers per GPU with batching
                len(UTILITY_GROUP_CANDIDATES),
            )
        else:
            # CPU-based: limited by RAM and CPU cores
            workers_by_ram = int(config.total_ram_gb / 4)  # ~4GB per worker
            workers_by_cpu = config.num_cpus // 2
            config.max_parallel_workers = max(1, min(workers_by_ram, workers_by_cpu, 4))

        return config


# =============================================================================
# LLM Configuration
# =============================================================================


@dataclass
class LLMConfig:
    """LLM configuration for inference."""

    model_name: str = "mistralai/Mistral-7B-Instruct-v0.3"
    base_url: str = "http://localhost:8000/v1"
    api_key: str = "dummy"  # vLLM doesn't require real key
    max_tokens: int = 4096
    temperature: float = 0.1
    tensor_parallel_size: int = 1
    timeout: int = 300

    def __post_init__(self):
        # Check for environment overrides
        if os.environ.get("LLM_MODEL"):
            self.model_name = os.environ["LLM_MODEL"]
        if os.environ.get("LLM_BASE_URL"):
            self.base_url = os.environ["LLM_BASE_URL"]
        if os.environ.get("OPENAI_API_KEY"):
            self.api_key = os.environ["OPENAI_API_KEY"]
