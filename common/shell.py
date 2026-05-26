"""
Shell-runner abstraction so phases can either probe the host or a container.

A ShellRunner runs a shell command and returns (exit_code, stdout, stderr).
Phase 1 / Phase 2 components accept an optional runner; when None, they
default to running on the host (legacy behavior).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Protocol


@dataclass
class ShellResult:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


class ShellRunner(Protocol):
    def run(self, cmd: str, timeout: int = 30) -> ShellResult: ...


class HostShellRunner:
    """Runs commands on the host via subprocess. Default/legacy path."""

    def run(self, cmd: str, timeout: int = 30) -> ShellResult:
        try:
            r = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return ShellResult(r.returncode, r.stdout or "", r.stderr or "")
        except subprocess.TimeoutExpired:
            return ShellResult(124, "", "timeout")
        except Exception as e:
            return ShellResult(1, "", str(e))


class ContainerShellRunner:
    """Runs commands inside a running Docker container via exec_run."""

    def __init__(self, container, user: str = "root") -> None:
        self.container = container
        self.user = user

    def run(self, cmd: str, timeout: int = 30) -> ShellResult:
        from common.container import ScenarioContainerManager
        res = ScenarioContainerManager.exec(self.container, cmd, timeout=timeout, user=self.user)
        return ShellResult(res.exit_code, res.stdout, res.stderr)
