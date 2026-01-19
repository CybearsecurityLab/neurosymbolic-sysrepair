import os
import subprocess
from dataclasses import dataclass


@dataclass
class HardwareConfig:
    """Detected hardware configuration."""

    num_gpus: int = 2
    gpu_memory_gb: float = 48.0  # L40S
    total_ram_gb: float = 400.0
    num_cpus: int = 100

    # Derived settings
    llm_workers_per_gpu: int = 2  # vLLM can handle multiple concurrent requests
    max_parallel_workers: int = 8  # Map workers
    batch_size: int = 16  # LLM batch size

    @classmethod
    def detect(cls) -> "HardwareConfig":
        """Auto-detect hardware capabilities."""
        config = cls()

        # Detect GPUs via nvidia-smi
        try:
            result = subprocess.run(
                [
                    "nvidia-smi",
                    "--query-gpu=count,memory.total",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                config.num_gpus = len(lines)
                if lines:
                    parts = lines[0].split(",")
                    config.gpu_memory_gb = float(parts[1].strip()) / 1024
        except Exception:
            pass

        # Detect RAM
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        config.total_ram_gb = kb / (1024 * 1024)
                        break
        except Exception:
            pass

        # Detect CPUs
        config.num_cpus = os.cpu_count() or 100

        # Calculate optimal parallelism
        config.max_parallel_workers = min(
            config.num_gpus * config.llm_workers_per_gpu, 8
        )

        return config


@dataclass
class LLMConfig:
    """LLM inference configuration."""

    model_name: str = (
        "mistralai/Mistral-7B-Instruct-v0.3"
    )

    base_url: str = "http://localhost:8000/v1"
    max_tokens: int = 4096
    temperature: float = 0.1
    tensor_parallel_size: int = 2

    # Batching config
    max_concurrent_requests: int = 16
    request_timeout: int = 120

# Utility group definitions (Section 5.1)
UTILITY_GROUPS = {
    "package": {
        "utilities": ["apt-get", "apt", "dpkg", "dpkg-query", "apt-cache", "snap"],
        "description": "Package management operations",
        "pddl_focus": ["package", "repository"],
        "osquery_tables": ["deb_packages", "apt_sources"],
    },
    "service": {
        "utilities": ["systemctl", "journalctl", "systemd-analyze"],
        "description": "Service lifecycle management (systemd v257)",
        "pddl_focus": ["service", "process"],
        "osquery_tables": ["systemd_units", "processes"],
    },
    "network": {
        "utilities": ["iptables", "ip", "ss", "netstat", "ufw", "nft"],
        "description": "Firewall and network interface management",
        "pddl_focus": ["port", "interface", "firewall_rule"],
        "osquery_tables": ["listening_ports", "iptables", "interface_addresses"],
    },
    "filesystem": {
        "utilities": [
            "cp",
            "mv",
            "rm",
            "chmod",
            "chown",
            "setfacl",
            "mkdir",
            "touch",
            "ln",
        ],
        "description": "File manipulation (uutils coreutils)",
        "pddl_focus": ["file", "directory", "configuration_file"],
        "osquery_tables": ["file", "file_events"],
    },
    "user": {
        "utilities": [
            "useradd",
            "usermod",
            "userdel",
            "groupadd",
            "groupmod",
            "passwd",
        ],
        "description": "User and group management",
        "pddl_focus": ["user", "group"],
        "osquery_tables": ["users", "groups", "user_groups"],
    },
    "privilege": {
        "utilities": ["sudo", "su", "pkexec"],
        "description": "Privilege escalation (sudo-rs aware)",
        "pddl_focus": ["user", "process"],
        "osquery_tables": ["sudoers"],
    },
}