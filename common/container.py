"""
Lightweight per-scenario container manager for the auto-sysrepair pipeline.

Builds a scenario's Docker image (with an optional injected dependency layer)
and spawns short-lived containers that Phase 1/2/3 can each exec commands into.
Intentionally independent of the eval harness's baselines code.
"""

from __future__ import annotations

import io
import logging
import shlex
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

import docker

from common.scenarios import Scenario

logger = logging.getLogger(__name__)


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @property
    def output(self) -> str:
        return self.stdout + (("\n" + self.stderr) if self.stderr else "")


class ScenarioContainerManager:
    """Builds scenario images and spawns/destroys containers for phase runs."""

    # Packages we'd like every scenario container to have. osqueryi is the
    # important one for Phase 1; if installation fails we degrade gracefully.
    DEFAULT_EXTRA_PKGS = "man-db manpages procps coreutils"

    def __init__(self, install_osquery: bool = False) -> None:
        self.client = docker.from_env()
        self.install_osquery = install_osquery
        self._built: dict[str, str] = {}  # scenario.id -> image tag

    # ----- image build --------------------------------------------------
    def build_image(self, scenario: Scenario) -> str:
        """Build the scenario image and append a layer with helper packages.

        Returns the final tag.
        """
        if scenario.id in self._built:
            return self._built[scenario.id]

        base_tag = f"sysrepair-{scenario.id}-base:latest"
        logger.info(f"Building base image for {scenario.id} from {scenario.dockerfile_path}")
        self.client.images.build(
            path=str(scenario.dockerfile_path.parent),
            tag=base_tag,
            rm=True,
            forcerm=True,
        )

        pkgs = self.DEFAULT_EXTRA_PKGS
        osquery_layer = ""
        if self.install_osquery:
            osquery_layer = (
                "RUN (apt-get update -qq && apt-get install -y -qq wget gnupg ca-certificates >/dev/null 2>&1 && "
                "wget -qO- https://pkg.osquery.io/deb/pubkey.gpg | apt-key add - >/dev/null 2>&1 && "
                "echo 'deb [arch=amd64] https://pkg.osquery.io/deb deb main' > /etc/apt/sources.list.d/osquery.list && "
                "apt-get update -qq && apt-get install -y -qq osquery >/dev/null 2>&1) || true\n"
            )

        # The Docker ubuntu base is minimized in two layers:
        #   1. /etc/dpkg/dpkg.cfg.d/excludes -> path-exclude=/usr/share/man/*
        #   2. /usr/bin/man is dpkg-diverted to a stub that prints a
        #      "run unminimize" banner instead of rendering pages
        # and there is no `unminimize` script on the Docker base. Replicate
        # what unminimize does: drop the exclude, undo the man diversion, then
        # reinstall every installed package so their man pages get written.
        # (coreutils ships no man pages on Ubuntu at all, so chmod/ls/cp etc.
        # remain --help-only there — that's normal Ubuntu behavior.)
        restore_manpages_layer = (
            "RUN rm -f /etc/dpkg/dpkg.cfg.d/excludes && "
            "( dpkg-divert --list 2>/dev/null | grep -q '/usr/bin/man' && "
            "dpkg-divert --quiet --remove --rename /usr/bin/man || true ) && "
            "apt-get update -qq && "
            f"apt-get install -y -qq {pkgs} >/dev/null 2>&1 || true && "
            "apt-get install -y -qq --reinstall man-db manpages >/dev/null 2>&1 || true && "
            "apt-get install -y -qq --reinstall "
            "$(dpkg-query -W -f='${Package}\\n' 2>/dev/null | tr '\\n' ' ') "
            ">/dev/null 2>&1 || true\n"
        )

        final_tag = f"sysrepair-{scenario.id}:latest"
        addon = (
            f"FROM {base_tag}\n"
            f"{restore_manpages_layer}"
            f"{osquery_layer}"
            f"RUN rm -rf /var/lib/apt/lists/*\n"
        )
        self.client.images.build(
            fileobj=io.BytesIO(addon.encode()),
            tag=final_tag,
            rm=True,
            forcerm=True,
        )
        self._built[scenario.id] = final_tag
        return final_tag

    # ----- container lifecycle ------------------------------------------
    def _spawn(self, image_tag: str, name: str, mem_limit: str = "2g") -> "docker.models.containers.Container":
        # Keep-alive wrapper that reaps zombies (same idea as eval/docker_manager).
        keepalive = 'trap "wait" SIGCHLD; while true; do wait -n 2>/dev/null || sleep 1; done'

        # Preserve the image's original CMD so services start, but in the background.
        try:
            image = self.client.images.get(image_tag)
            original_cmd = image.attrs.get("Config", {}).get("Cmd") or []
        except Exception:
            original_cmd = []

        if original_cmd:
            cmd_str = " ".join(shlex.quote(c) for c in original_cmd)
            wrapper = f"{cmd_str} & {keepalive}"
        else:
            wrapper = keepalive

        container = self.client.containers.run(
            image_tag,
            name=name,
            entrypoint=["/bin/bash", "-c"],
            command=[wrapper],
            detach=True,
            mem_limit=mem_limit,
            security_opt=["no-new-privileges"],
            cap_add=["NET_ADMIN", "SYS_ADMIN"],
            tty=False,
        )
        time.sleep(0.5)  # let services come up
        return container

    @contextmanager
    def container_for(
        self,
        scenario: Scenario,
        phase: str,
        mem_limit: str = "2g",
    ) -> Iterator["docker.models.containers.Container"]:
        """Yield a fresh container for one phase of one scenario. Always tears down."""
        image_tag = self.build_image(scenario)
        name = f"sysrepair-{scenario.id}-{phase}-{uuid.uuid4().hex[:6]}"
        container = self._spawn(image_tag, name, mem_limit=mem_limit)
        logger.info(f"[{scenario.id}/{phase}] container started: {container.short_id}")
        try:
            yield container
        finally:
            try:
                container.stop(timeout=5)
            except Exception:
                pass
            try:
                container.remove(v=True, force=True)
            except Exception:
                pass
            logger.info(f"[{scenario.id}/{phase}] container destroyed")

    # ----- exec helper used by other modules ----------------------------
    @staticmethod
    def exec(container, cmd: list[str] | str, timeout: int = 30, user: str = "root") -> ExecResult:
        """Run a command in the container. Returns (exit_code, stdout, stderr)."""
        if isinstance(cmd, list):
            # Use ["bash", "-c", ...] so we can apply timeout uniformly
            quoted = " ".join(shlex.quote(c) for c in cmd)
        else:
            quoted = cmd
        wrapped = f"timeout {timeout} bash -c {shlex.quote(quoted)}"
        try:
            exit_code, output = container.exec_run(
                cmd=["bash", "-c", wrapped],
                stdout=True,
                stderr=True,
                demux=True,
                user=user,
            )
            stdout_b, stderr_b = output if output else (b"", b"")
            return ExecResult(
                exit_code=exit_code if exit_code is not None else 1,
                stdout=(stdout_b or b"").decode("utf-8", errors="replace"),
                stderr=(stderr_b or b"").decode("utf-8", errors="replace"),
            )
        except Exception as e:
            return ExecResult(exit_code=1, stdout="", stderr=str(e))
