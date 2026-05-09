"""
Docker Executor for Phase 3: Sandboxed command execution in Ubuntu 25.10

This module manages a Docker container for safely executing bash commands
and observing their effects on the environment.
"""

import logging
import time
from typing import Optional
from dataclasses import dataclass

from .config import DockerConfig, PREDICATE_CHECKS
from .models import ExecutionResult, GroundedAction, ActionOutcome, EnvironmentState

logger = logging.getLogger("Phase3.DockerExecutor")


@dataclass
class ContainerState:
    """State of the Docker container."""
    container_id: str
    running: bool
    created_at: float
    commands_executed: int = 0


class DockerExecutor:
    """
    Manages a sandboxed Ubuntu 25.10 Docker container for action execution.

    The container is used to:
    1. Execute concretized PDDL actions (bash commands)
    2. Verify predicate state before/after actions
    3. Observe discrepancies between predicted and actual effects
    """

    def __init__(self, config: Optional[DockerConfig] = None):
        self.config = config or DockerConfig()

        self.client = None
        self.container = None
        self.state: Optional[ContainerState] = None

        try:
            import docker
            self.client = docker.from_env()
        except ImportError:
            logger.error("docker package not installed. Install with: pip install docker")
            raise
        except Exception as e:
            logger.error(f"Failed to connect to Docker: {e}")
            raise

    def start_container(self) -> bool:
        """Start the sandbox container."""
        try:
            # Remove existing container if present
            self._cleanup_existing()

            logger.info(f"Starting container with image: {self.config.image}")

            # Pull image if needed
            try:
                self.client.images.get(self.config.image)
            except Exception:
                logger.info(f"Pulling image: {self.config.image}")
                self.client.images.pull(self.config.image)

            # Start container
            self.container = self.client.containers.run(
                **self.config.to_docker_kwargs()
            )

            # Wait for container to be ready
            deadline = time.time() + self.config.startup_timeout
            while time.time() < deadline:
                self.container.reload()
                if self.container.status == "running":
                    break
                time.sleep(0.5)

            if self.container.status != "running":
                raise RuntimeError(f"Container failed to start: {self.container.status}")

            self.state = ContainerState(
                container_id=self.container.id,
                running=True,
                created_at=time.time()
            )

            # Initialize container environment
            self._initialize_container()

            logger.info(f"Container started: {self.container.short_id}")
            return True

        except Exception as e:
            logger.exception(f"Failed to start container: {e}")
            return False

    def _cleanup_existing(self):
        """Remove any existing container with the same name."""
        try:
            existing = self.client.containers.get(self.config.container_name)
            logger.info(f"Removing existing container: {self.config.container_name}")
            existing.remove(force=True)
        except Exception:
            pass  # Container doesn't exist

    def _initialize_container(self):
        """Initialize container environment for PDDL action execution."""
        # Wait for container to be ready for commands
        self._wait_for_container_ready()

        init_commands = [
            # Ensure test user exists (pre-created in Dockerfile, re-ensure after reset)
            "useradd -m testuser 2>/dev/null || true",
            # Create essential directories that some actions expect
            "mkdir -p /var/mail /var/spool/cron/crontabs 2>/dev/null || true",
        ]

        for cmd in init_commands:
            try:
                self.container.exec_run(cmd, user="root")
            except Exception as e:
                logger.warning(f"Init command failed: {cmd} - {e}")

    def _wait_for_container_ready(self, timeout: int = 15):
        """Wait for the container to be running and accepting commands."""
        deadline = time.time() + timeout

        # Wait for the container to be in "running" state
        while time.time() < deadline:
            try:
                self.container.reload()
                if self.container.status == "running":
                    # Verify we can exec into it
                    result = self.container.exec_run(
                        ["echo", "ready"], user="root"
                    )
                    if result.exit_code == 0:
                        logger.info("Container is ready")
                        return
            except Exception:
                pass
            time.sleep(0.5)

        logger.warning(f"Container did not become ready within {timeout}s, proceeding anyway")

    # Commands that can destroy critical system files (/etc/passwd, /etc/shadow)
    _DANGEROUS_PATTERNS = [
        "userdel",       # Can corrupt /etc/passwd
        "vipw",          # Direct passwd editing
        "pwck",          # Passwd consistency check (can delete entries)
        "> /etc/passwd", # Overwrite passwd
        "> /etc/shadow", # Overwrite shadow
        "rm /etc/passwd",
        "rm /etc/shadow",
        "rm -f /etc/passwd",
        "rm -f /etc/shadow",
    ]

    def _is_dangerous_command(self, command: str) -> bool:
        """Check if a command could corrupt critical system files."""
        cmd_lower = command.lower().strip()
        for pattern in self._DANGEROUS_PATTERNS:
            if pattern in cmd_lower:
                return True
        return False

    def execute_command(
        self,
        command: str,
        timeout: Optional[int] = None,
        user: str = "root"
    ) -> tuple[int, str, str]:
        """
        Execute a command in the container.

        Returns: (exit_code, stdout, stderr)
        """
        timeout = timeout or self.config.exec_timeout

        if not self.container:
            raise RuntimeError("Container not started")

        # Block commands that could corrupt the container filesystem
        if self._is_dangerous_command(command):
            logger.warning(f"Blocked dangerous command: {command[:80]}")
            return 1, "", "Command blocked: could corrupt container filesystem"

        try:
            start_time = time.time()
            result = self.container.exec_run(
                ["bash", "-c", f"timeout {timeout} bash -c {repr(command)}"],
                user=user,
                demux=True,  # Separate stdout/stderr
            )
            elapsed = time.time() - start_time

            stdout = result.output[0].decode() if result.output[0] else ""
            stderr = result.output[1].decode() if result.output[1] else ""

            if self.state:
                self.state.commands_executed += 1

            # Detect corruption indicators in stderr
            if "unable to find user" in stderr or "no matching entries in passwd" in stderr:
                logger.error(f"Container corruption detected after command: {command[:80]}")

            logger.debug(f"Executed ({elapsed:.2f}s): {command[:50]}... -> {result.exit_code}")

            return result.exit_code, stdout, stderr

        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return -1, "", str(e)

    def execute_action(
        self,
        action: GroundedAction,
        command: str
    ) -> ExecutionResult:
        """
        Execute a grounded PDDL action and record the result.
        """
        start_time = time.time()

        exit_code, stdout, stderr = self.execute_command(command)
        elapsed = time.time() - start_time

        # Determine outcome
        if exit_code == 0:
            outcome = ActionOutcome.SUCCESS
        elif exit_code in (-1, 124):
            outcome = ActionOutcome.TIMEOUT
        else:
            outcome = ActionOutcome.EXECUTION_FAILED

        return ExecutionResult(
            action=action,
            command=command,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            execution_time=elapsed,
            outcome=outcome,
        )

    def verify_predicate(
        self,
        predicate_name: str,
        bindings: dict[str, str]
    ) -> bool:
        """
        Verify a PDDL predicate holds in the environment.
        """
        check_template = PREDICATE_CHECKS.get(predicate_name)
        if not check_template:
            logger.warning(f"No check defined for predicate: {predicate_name}")
            return True  # Assume true if we can't check

        # Format the check command with bindings
        try:
            command = check_template.format(**bindings)
        except KeyError as e:
            logger.warning(f"Missing binding for predicate check: {e}")
            return True

        exit_code, _, _ = self.execute_command(command)
        return exit_code == 0

    def get_environment_state(self) -> EnvironmentState:
        """
        Extract current environment state for PDDL grounding.
        """
        state = EnvironmentState(
            packages=[],
            services=[],
            users=[],
            groups=[],
            files=[],
        )

        # Get installed packages
        exit_code, stdout, _ = self.execute_command(
            "dpkg-query -W -f='${Package}|${Version}|${Status}\n' 2>/dev/null | head -100"
        )
        if exit_code == 0:
            for line in stdout.strip().split("\n"):
                if "|" in line:
                    parts = line.split("|")
                    if len(parts) >= 3:
                        state.packages.append({
                            "name": parts[0],
                            "version": parts[1],
                            "installed": "installed" in parts[2]
                        })

        # Get services
        exit_code, stdout, _ = self.execute_command(
            "systemctl list-units --type=service --all --no-pager --plain 2>/dev/null | head -50"
        )
        if exit_code == 0:
            for line in stdout.strip().split("\n")[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 4 and parts[0].endswith(".service"):
                    state.services.append({
                        "name": parts[0].replace(".service", ""),
                        "active": parts[2] == "active",
                        "enabled": True  # Would need separate check
                    })

        # Get users
        exit_code, stdout, _ = self.execute_command("cat /etc/passwd")
        if exit_code == 0:
            for line in stdout.strip().split("\n"):
                parts = line.split(":")
                if len(parts) >= 3:
                    state.users.append({
                        "name": parts[0],
                        "uid": parts[2],
                        "groups": []
                    })

        # Get groups
        exit_code, stdout, _ = self.execute_command("cat /etc/group")
        if exit_code == 0:
            for line in stdout.strip().split("\n"):
                parts = line.split(":")
                if len(parts) >= 3:
                    state.groups.append({
                        "name": parts[0],
                        "gid": parts[2],
                        "members": parts[3].split(",") if len(parts) > 3 else []
                    })

        return state

    def _is_container_corrupted(self) -> bool:
        """Check if the container filesystem is corrupted (e.g. /etc/passwd destroyed)."""
        if not self.container:
            return True
        try:
            result = self.container.exec_run(
                ["bash", "-c", "id root"],
                user="root",
            )
            if result.exit_code != 0:
                stderr = result.output.decode() if result.output else ""
                logger.warning(f"Container corruption detected: 'id root' failed: {stderr.strip()}")
                return True
            return False
        except Exception as e:
            logger.warning(f"Container corruption check failed: {e}")
            return True

    def _recreate_container(self) -> bool:
        """Stop, remove, and recreate the container from a fresh image."""
        logger.info("Recreating container from fresh image...")
        try:
            if self.container:
                try:
                    self.container.stop(timeout=5)
                except Exception:
                    pass
                try:
                    self.container.remove(force=True)
                except Exception:
                    pass
                self.container = None

            # Start a fresh container
            self.container = self.client.containers.run(
                **self.config.to_docker_kwargs()
            )

            # Wait for container to be ready
            deadline = time.time() + self.config.startup_timeout
            while time.time() < deadline:
                self.container.reload()
                if self.container.status == "running":
                    break
                time.sleep(0.5)

            if self.container.status != "running":
                raise RuntimeError(f"Recreated container failed to start: {self.container.status}")

            self.state = ContainerState(
                container_id=self.container.id,
                running=True,
                created_at=time.time()
            )

            self._initialize_container()
            logger.info(f"Container recreated successfully: {self.container.short_id}")
            return True

        except Exception as e:
            logger.exception(f"Failed to recreate container: {e}")
            return False

    def reset_container(self):
        """Reset container to clean state.

        Always recreates the container from scratch because systemd (PID 1)
        accumulates state (started/stopped services, created users, modified
        files) that persists across restarts. A full recreate ensures a
        pristine environment for each exploration walk batch.
        """
        if self.container:
            logger.info("Recreating systemd container for clean state")
            self._recreate_container()

    def stop_container(self):
        """Stop and remove the container."""
        if self.container:
            try:
                self.container.stop(timeout=5)
                self.container.remove()
                logger.info("Container stopped and removed")
            except Exception as e:
                logger.warning(f"Error stopping container: {e}")
            finally:
                self.container = None
                self.state = None

    def __enter__(self):
        self.start_container()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_container()
        return False
