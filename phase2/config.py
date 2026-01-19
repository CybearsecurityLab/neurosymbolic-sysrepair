import os
import subprocess
import logging
from dataclasses import dataclass

# Setup a logger for config to see detection errors
logger = logging.getLogger("Phase2.Config")


@dataclass
class HardwareConfig:
    """Detected hardware configuration."""

    # --- FIX 1: Set safe defaults (0 GPUs, minimal RAM) ---
    # If detection fails, we shouldn't assume we have 2x L40S GPUs.
    num_gpus: int = 0
    gpu_memory_gb: float = 0.0
    total_ram_gb: float = 16.0
    num_cpus: int = 4

    # Derived settings
    llm_workers_per_gpu: int = 1
    max_parallel_workers: int = 2
    batch_size: int = 4

    @classmethod
    def detect(cls) -> "HardwareConfig":
        """Auto-detect hardware capabilities."""
        config = cls()

        # 1. Detect CPUs
        try:
            config.num_cpus = os.cpu_count() or 4
        except Exception as e:
            logger.warning(f"CPU detection failed: {e}")

        # 2. Detect RAM
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        config.total_ram_gb = kb / (1024 * 1024)
                        break
        except FileNotFoundError:
            # Fallback for non-Linux (e.g., Mac/Windows)
            logger.warning("/proc/meminfo not found (non-Linux system?)")
        except Exception as e:
            logger.warning(f"RAM detection failed: {e}")

        # 3. Detect GPUs via nvidia-smi
        try:
            result = subprocess.run(
                [
                    "nvidia-smi",
                    "--query-gpu=memory.total",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                timeout=5,
                stdin=subprocess.DEVNULL,
            )

            if result.returncode == 0:
                lines = [line for line in result.stdout.strip().split("\n") if line.strip()]
                config.num_gpus = len(lines)
                if lines:
                    # Parse memory from first GPU
                    config.gpu_memory_gb = float(lines[0].strip()) / 1024
                    logger.info(f"Detected {config.num_gpus} GPUs with {config.gpu_memory_gb:.1f}GB VRAM each")
            else:
                logger.info("No NVIDIA GPUs detected (nvidia-smi returned non-zero)")

        except FileNotFoundError:
            logger.info("nvidia-smi not found. Assuming CPU-only mode.")
        except Exception as e:
            logger.warning(f"GPU detection error: {e}")

        # 4. Calculate optimal parallelism
        if config.num_gpus > 0:
            # If we have GPUs, be aggressive
            config.llm_workers_per_gpu = 2
            config.max_parallel_workers = min(config.num_cpus, config.num_gpus * 4)
        else:
            # CPU-only mode: be conservative to avoid freezing the OS
            config.llm_workers_per_gpu = 0
            config.max_parallel_workers = max(1, config.num_cpus // 2)

        return config


@dataclass
class LLMConfig:
    """LLM inference configuration."""
    model_name: str = "mistralai/Mistral-7B-Instruct-v0.3"
    base_url: str = "http://localhost:8000/v1"
    max_tokens: int = 4096
    temperature: float = 0.1
    tensor_parallel_size: int = 1  # Default to 1 (safe for single GPU)

    # Batching config
    max_concurrent_requests: int = 16
    request_timeout: int = 120


# Utility group definitions remain the same...
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
            "cp", "mv", "rm", "chmod", "chown", "setfacl", "mkdir", "touch", "ln",
        ],
        "description": "File manipulation (uutils coreutils)",
        "pddl_focus": ["file", "directory", "configuration_file"],
        "osquery_tables": ["file", "file_events"],
    },
    "user": {
        "utilities": [
            "useradd", "usermod", "userdel", "groupadd", "groupmod", "passwd",
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