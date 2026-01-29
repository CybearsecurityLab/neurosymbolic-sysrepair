"""
phase2/config.py

Configuration for Phase 2: Parallel Synthesis.
Defines utility groups, hardware detection, and LLM settings.
Updated to dynamically discover installed utilities and valid osquery tables.
"""

import os
import re
import sys
import json
import shutil
import psutil
import subprocess
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING, Set

if TYPE_CHECKING:
    from common.models import Phase1State

# =============================================================================
# Utility Group Definitions (Templates)
# =============================================================================
# These define the logical groups and the regex patterns to find their tools.
# Actual utilities are populated at runtime by scanning the system.

UTILITY_TEMPLATES = {
    "package_management": {
        "description": "Package installation, removal, and updates",
        "pattern": r"^(apt|apt-get|dpkg|snap|flatpak|pip|npm|dnf|yum|rpm)$",
        "pddl_focus": ["package", "repository"],
        "osquery_candidates": [
            "deb_packages",
            "apt_sources",
            "rpm_packages",
            "npm_packages",
        ],
    },
    "service_management": {
        "description": "Service lifecycle and system configuration",
        "pattern": r"^(systemctl|service|journalctl|timedatectl|hostnamectl|localectl|sysctl)$",
        "pddl_focus": ["service", "configuration_file"],
        "osquery_candidates": ["systemd_units", "services", "startup_items"],
    },
    "user_management": {
        "description": "User and group administration",
        "pattern": r"^(useradd|usermod|userdel|groupadd|groupmod|groupdel|passwd|chage|id|whoami)$",
        "pddl_focus": ["user", "group"],
        "osquery_candidates": ["users", "groups", "user_groups", "shadow"],
    },
    "file_management": {
        "description": "File and directory operations (including ACLs)",
        "pattern": r"^(cp|mv|rm|mkdir|chmod|chown|ln|touch|ls|setfacl|getfacl|stat)$",
        "pddl_focus": ["file", "directory", "filesystem_object"],
        "osquery_candidates": ["file"],
    },
    "network_management": {
        "description": "Network configuration, firewall, and routing",
        "pattern": r"^(ip|netplan|ufw|iptables|ip6tables|ss|nft|firewall-cmd|nmcli|route)$",
        "pddl_focus": ["interface", "port", "firewall_rule"],
        "osquery_candidates": [
            "interface_addresses",
            "listening_ports",
            "iptables",
            "routes",
        ],
    },
    "process_management": {
        "description": "Process control and monitoring",
        "pattern": r"^(kill|pkill|nice|renice|nohup|pgrep|top|ps)$",
        "pddl_focus": ["process"],
        "osquery_candidates": ["processes"],
    },
    "privilege_escalation": {
        "description": "Privilege management (sudo/doas)",
        "pattern": r"^(sudo|su|visudo|doas)$",
        "pddl_focus": ["user"],
        "osquery_candidates": ["sudoers"],
    },
}

# =============================================================================
# Dynamic Discovery Functions
# =============================================================================


def _get_search_paths() -> list[Path]:
    """Get list of standard binary directories to scan."""
    # Use standard paths + PATH environment variable
    standard_paths = [
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
    ]
    env_paths = os.environ.get("PATH", "").split(os.pathsep)

    unique_paths = set()
    for p in standard_paths + env_paths:
        if p and os.path.isdir(p):
            unique_paths.add(Path(p).resolve())

    return list(unique_paths)


def _scan_system_binaries() -> Set[str]:
    """
    Scan all directories in PATH to find all available executable names.
    Returns a set of unique command names (e.g., {'ls', 'grep', 'apt'}).
    """
    found_binaries = set()
    search_paths = _get_search_paths()

    for path in search_paths:
        try:
            for entry in path.iterdir():
                if entry.is_file() and os.access(entry, os.X_OK):
                    found_binaries.add(entry.name)
        except (PermissionError, OSError):
            continue

    return found_binaries


def check_osquery_tables() -> Set[str]:
    """
    Query local osqueryi to find which tables actually exist.
    """
    try:
        # Check if osqueryi is installed first
        if not shutil.which("osqueryi"):
            return set()

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
            data = json.loads(result.stdout)
            return {row["name"] for row in data}
    except Exception:
        pass
    return set()


# =============================================================================
# Build VALIDATED Utility Groups at Runtime
# =============================================================================


def build_utility_groups(phase1_state: Optional["Phase1State"] = None) -> dict:
    """
    Build utility groups by matching installed binaries against regex patterns.

    Args:
        phase1_state: Optional Phase 1 state object. If provided, 'pddl_focus'
                      will be filtered to only include types that actually exist
                      in the discovered system objects.
    """
    validated_groups = {}

    # 1. Get resources (Executables and Tables)
    available_binaries = _scan_system_binaries()
    available_osquery_tables = check_osquery_tables()

    for group_name, template in UTILITY_TEMPLATES.items():
        # Match installed binaries against the group's pattern
        pattern = re.compile(template["pattern"])
        matched_utilities = sorted(
            [bin_name for bin_name in available_binaries if pattern.match(bin_name)]
        )

        if not matched_utilities:
            # Skip groups where no relevant tools are installed
            continue

        # Filter osquery tables to those that actually exist
        valid_tables = [
            t for t in template["osquery_candidates"] if t in available_osquery_tables
        ]

        # Dynamic PDDL Focus: Filter based on Phase 1 extraction results
        pddl_focus = template["pddl_focus"]
        if phase1_state and hasattr(phase1_state, "objects"):
            pddl_focus = [
                t
                for t in pddl_focus
                if t in phase1_state.objects and phase1_state.objects[t]
            ]

        validated_groups[group_name] = {
            "description": template["description"],
            "utilities": matched_utilities,
            "pddl_focus": pddl_focus,
            "osquery_tables": valid_tables,
        }

    return validated_groups


def get_utility_groups(phase1_state: Optional["Phase1State"] = None) -> dict:
    """Get validated utility groups. Call this instead of using constants directly."""
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
                if lines:
                    parts = lines[0].split(",")
                    if len(parts) >= 2:
                        config.gpu_memory_gb = float(parts[1].strip()) / 1024
        except Exception:
            pass

        # Calculate max parallel workers
        # Use length of defined templates as the upper bound
        num_groups = len(UTILITY_TEMPLATES)

        if config.num_gpus > 0:
            # GPU-based: limited by VRAM for LLM inference
            config.max_parallel_workers = min(
                config.num_gpus * 2,
                num_groups,
            )
        else:
            # CPU-based: limited by RAM and CPU cores
            workers_by_ram = int(config.total_ram_gb / 4)
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
    api_key: str = "dummy"
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
