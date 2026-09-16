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

# `docker` is imported lazily in __init__, not here. osquery_install_sh() and
# osquery_install_ps1() render a shell string and need no Docker client; a
# module-level import makes them unusable from anything that is not already a
# Docker host, which is exactly where they are most useful. The type hints
# below are strings under `from __future__ import annotations`, so they do
# not need the module at import time either.

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
        import docker  # lazy: see the note at the top of this module
        self.client = docker.from_env()
        self.install_osquery = install_osquery
        self._built: dict[str, str] = {}  # scenario.id -> image tag

    # osquery release assets. The .deb alone covers only Debian and Ubuntu,
    # which is 13 of the corpus's 44 pullable Linux bases; the rest need a
    # different route. Every asset is from the same 5.23.1 release, so the
    # osqueryi that Phase 1 talks to is identical whichever path is taken.
    _OSQUERY_VERSION = "5.23.1"
    _OSQUERY_BASE = (
        "https://github.com/osquery/osquery/releases/download/5.23.1"
    )
    _OSQUERY_DEB = f"{_OSQUERY_BASE}/osquery_5.23.1-1.linux_amd64.deb"
    _OSQUERY_RPM = f"{_OSQUERY_BASE}/osquery-5.23.1-1.linux.x86_64.rpm"
    # The tarball unpacks to usr/bin/osqueryi + opt/osquery and needs nothing
    # but tar and glibc, so it is the fallback for every image whose package
    # manager is absent, broken, or pointed at a dead mirror (centos:7's
    # mirrorlist, Debian 9/10 after archival).
    _OSQUERY_TGZ = f"{_OSQUERY_BASE}/osquery-5.23.1_1.linux_x86_64.tar.gz"
    _OSQUERY_MSI = f"{_OSQUERY_BASE}/osquery-5.23.1.msi"

    def _osquery_layer(self) -> str:
        """A RUN layer that installs osqueryi on any glibc Linux base.

        Tries, in order: the native package for whichever package manager the
        image has, then the relocatable tarball. Ends by asserting
        /usr/bin/osqueryi exists, but the whole layer is still `|| true`: a
        base that genuinely cannot host osquery (musl, Windows) must not fail
        the build, it must fall through to Phase 1's shell-only introspection.
        """
        sh = (
            "set -e; "
            # curl is not universal; wget is the other half of the corpus.
            'fetch() { curl -fsSL "$1" -o "$2" 2>/dev/null '
            '|| wget -q -O "$2" "$1" 2>/dev/null; }; '
            "if command -v apt-get >/dev/null 2>&1; then "
            #   Debian 9/10 are archived: deb.debian.org 404s and the Release
            #   files are expired, so both have to be worked around or every
            #   apt call fails before osquery is even fetched.
            "  apt-get update -qq >/dev/null 2>&1 || { "
            "    sed -i -e 's|deb.debian.org|archive.debian.org|g' "
            "-e 's|security.debian.org|archive.debian.org|g' "
            "-e '/-updates/d' /etc/apt/sources.list 2>/dev/null || true; "
            "    apt-get -o Acquire::Check-Valid-Until=false update -qq >/dev/null 2>&1 || true; }; "
            "  apt-get install -y -qq curl ca-certificates >/dev/null 2>&1 || true; "
            f"  fetch $DEB /tmp/osq.deb && "
            "  (dpkg -i /tmp/osq.deb >/dev/null 2>&1 || apt-get -y -f install >/dev/null 2>&1) || true; "
            "elif command -v dnf >/dev/null 2>&1 || command -v microdnf >/dev/null 2>&1; then "
            "  M=$(command -v dnf || command -v microdnf); "
            f"  $M install -y curl ca-certificates >/dev/null 2>&1 || true; "
            f"  fetch $RPM /tmp/osq.rpm && rpm -i --nodeps /tmp/osq.rpm >/dev/null 2>&1 || true; "
            "elif command -v yum >/dev/null 2>&1; then "
            #   centos:7 is EOL and its mirrorlist is gone; vault.centos.org
            #   still serves it. Without this yum cannot install curl.
            "  sed -i -e 's|^mirrorlist=|#mirrorlist=|g' "
            "-e 's|^#\\?baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' "
            "/etc/yum.repos.d/CentOS-*.repo 2>/dev/null || true; "
            "  yum install -y curl ca-certificates >/dev/null 2>&1 || true; "
            f"  fetch $RPM /tmp/osq.rpm && rpm -i --nodeps /tmp/osq.rpm >/dev/null 2>&1 || true; "
            "elif command -v zypper >/dev/null 2>&1; then "
            "  zypper --non-interactive install curl >/dev/null 2>&1 || true; "
            f"  fetch $RPM /tmp/osq.rpm && rpm -i --nodeps /tmp/osq.rpm >/dev/null 2>&1 || true; "
            "elif command -v apk >/dev/null 2>&1; then "
            #   Alpine is musl. osquery ships no musl build, so the only hope
            #   is gcompat shimming the glibc tarball; where that fails the
            #   base is genuinely unsupported and says so in the log.
            "  apk add --no-cache curl tar gcompat libstdc++ >/dev/null 2>&1 || true; "
            "fi; "
            "if [ ! -x /usr/bin/osqueryi ]; then "
            f"  fetch $TGZ /tmp/osq.tgz && tar -xzf /tmp/osq.tgz -C / usr opt >/dev/null 2>&1 || true; "
            "fi; "
            "rm -f /tmp/osq.deb /tmp/osq.rpm /tmp/osq.tgz; "
            # Existing on disk is not the claim; answering a query is. An
            # osqueryi that cannot open its tables yields empty introspection,
            # which is the failure Phase 1 used to swallow silently.
            '/usr/bin/osqueryi --json "SELECT name FROM os_version LIMIT 1" >/dev/null 2>&1'
        )
        sh = (f'DEB="{self._OSQUERY_DEB}"; RPM="{self._OSQUERY_RPM}"; '
              f'TGZ="{self._OSQUERY_TGZ}"; ' + sh)
        return f"RUN ({sh}) || true\n"

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
            osquery_layer = self._osquery_layer()

        # The Docker ubuntu base is minimized in two layers:
        #   1. /etc/dpkg/dpkg.cfg.d/excludes -> path-exclude=/usr/share/man/*
        #   2. /usr/bin/man is dpkg-diverted to a stub that prints a
        #      "run unminimize" banner instead of rendering pages
        # and there is no `unminimize` script on the Docker base. Replicate
        # what unminimize does: drop the exclude, undo the man diversion, then
        # reinstall every installed package so their man pages get written.
        # (coreutils ships no man pages on Ubuntu at all, so chmod/ls/cp etc.
        # remain --help-only there — that's normal Ubuntu behavior.)
        # The reinstall-everything step below HANGS FOREVER on any image whose
        # package set contains a service with a blocking postinst. Observed on
        # ccdc-11: the list includes mysql-server, dpkg runs
        # mysql-server.postinst, that starts a real mysqld against a temp socket
        # and waits for readiness, and in a container with no init it never
        # becomes ready. The pipeline parks in unix_stream_data_wait at 0% CPU
        # on a docker exec that will never return, with no output and no error.
        #
        # Two guards, because either alone is insufficient:
        #   policy-rc.d  stops invoke-rc.d starting daemons during configure
        #   timeout      bounds the step regardless, since mysql-server.postinst
        #                launches mysqld DIRECTLY rather than through invoke-rc.d
        # A partial man-page restore is fine: mining reads whatever pages exist.
        # An unbounded wait is not, because it looks identical to slow work.
        restore_manpages_layer = (
            "RUN printf '#!/bin/sh\\nexit 101\\n' > /usr/sbin/policy-rc.d && "
            "chmod +x /usr/sbin/policy-rc.d && "
            "rm -f /etc/dpkg/dpkg.cfg.d/excludes && "
            "( dpkg-divert --list 2>/dev/null | grep -q '/usr/bin/man' && "
            "dpkg-divert --quiet --remove --rename /usr/bin/man || true ) && "
            "apt-get update -qq && "
            f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {pkgs} >/dev/null 2>&1 || true && "
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --reinstall "
            "man-db manpages >/dev/null 2>&1 || true && "
            "timeout 600 env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --reinstall "
            "$(dpkg-query -W -f='${Package}\\n' 2>/dev/null | "
            # Exclude packages whose postinst starts a daemon. Reinstalling
            # them can never succeed in a container with no init: the postinst
            # waits for a service that will never come up, so the transaction
            # is killed by the timeout and dpkg is left interrupted, breaking
            # EVERY later apt call including the osquery layer. Their man pages
            # are not worth a broken package database.
            "grep -vE '^(mysql|mariadb|postgresql|mongodb|redis|apache2|nginx|bind9|slapd|samba|dovecot|postfix|exim4)' | tr '\\n' ' ') "
            ">/dev/null 2>&1; "
            # The timeout above kills apt-get MID-TRANSACTION, which leaves
            # dpkg interrupted: /var/lib/dpkg/updates full of journal files,
            # packages unpacked but unconfigured, and EVERY later apt call
            # failing. The osquery layer runs after this one and needs apt,
            # so without this heal it fails silently behind its `|| true`
            # and Phase 1 reports no osqueryi and produces empty state.
            "dpkg --configure -a >/dev/null 2>&1 || true; "
            "apt-get -y -f install >/dev/null 2>&1 || true; "
            "rm -f /usr/sbin/policy-rc.d; true\n"
        )

        # Many upstream bases drop privileges in their own Dockerfile
        # (jenkins, jupyter, airflow, elasticsearch, ...). Every helper layer
        # below writes to /usr, so it has to run as root; the image is then
        # handed back to the scenario's own user so runtime behaviour is
        # unchanged. Measured: this alone is the difference between osquery
        # installing and not on 7 of the corpus's bases.
        try:
            orig_user = self.client.images.get(base_tag).attrs["Config"].get("User") or ""
        except Exception:  # pragma: no cover - image config is always present
            orig_user = ""

        final_tag = f"sysrepair-{scenario.id}:latest"
        addon = (
            f"FROM {base_tag}\n"
            "USER root\n"
            f"{restore_manpages_layer}"
            f"{osquery_layer}"
            f"RUN rm -rf /var/lib/apt/lists/*\n"
            + (f"USER {orig_user}\n" if orig_user else "")
        )
        self.client.images.build(
            fileobj=io.BytesIO(addon.encode()),
            tag=final_tag,
            rm=True,
            forcerm=True,
        )
        self._built[scenario.id] = final_tag
        return final_tag

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


def osquery_install_sh() -> str:
    """The osquery install script as a bare shell command, no Dockerfile wrapper.

    Derived from `_osquery_layer` rather than copied, so the two cannot drift.
    The Dockerfile layer bakes this into an image; the benchmark solver runs the
    identical text inside an Inspect sandbox, which is a different code path to
    the same substrate. A solver introspecting a different osquery from the one
    the base-image audit measured would make that audit inapplicable to the run.

    `__new__` skips `__init__`, which would otherwise open a Docker client this
    caller does not need.
    """
    mgr = ScenarioContainerManager.__new__(ScenarioContainerManager)
    layer = ScenarioContainerManager._osquery_layer(mgr)
    return layer[len("RUN ("):layer.rindex(") || true")]
