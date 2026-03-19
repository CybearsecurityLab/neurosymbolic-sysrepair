import docker
import io
import logging
import tarfile
import time
from pathlib import Path
from baselines.state import CommandRecord

logger = logging.getLogger(__name__)

# Maximum consecutive crashes before aborting a run
MAX_CRASH_RETRIES = 5


class DockerManager:
    def __init__(self, docker_url: str = "unix://var/run/docker.sock"):
        self.client = docker.from_env()
        self._built_images: set = set()  # cache
        self._container_crashes: dict[str, int] = {}  # container_id -> crash count
        # Track image tag + verify script per container for recreation
        self._container_meta: dict[str, dict] = {}  # container_id -> {image_tag, run_id, verify_sh_path}

    # Packages needed by verify.sh scripts (sshpass for SSH tests, iproute2 for ss, etc.)
    _VERIFY_DEPS = "sshpass openssh-client iproute2 procps"

    def build_image(self, scenario, tag: str | None = None) -> str:
        """Build Docker image from scenario Dockerfile.

        Appends a layer that installs verify-script dependencies so they
        are baked into the image (avoids needing network access at runtime).
        """
        tag = tag or f"sysrepair-{scenario.id}:latest"
        if tag not in self._built_images:
            # Build the base image from the scenario Dockerfile
            base_tag = f"{tag}-base"
            self.client.images.build(
                path=str(scenario.dockerfile_path.parent),
                tag=base_tag,
                rm=True,
                forcerm=True,
            )
            # Add a layer with verify-script dependencies
            dep_dockerfile = (
                f"FROM {base_tag}\n"
                f"RUN apt-get update -qq && "
                f"apt-get install -y -qq {self._VERIFY_DEPS} >/dev/null 2>&1 || true && "
                f"rm -rf /var/lib/apt/lists/*\n"
            )
            self.client.images.build(
                fileobj=io.BytesIO(dep_dockerfile.encode()),
                tag=tag,
                rm=True,
                forcerm=True,
            )
            self._built_images.add(tag)
        return tag

    def _get_image_cmd(self, image_tag: str) -> list[str]:
        """Extract the CMD from an image's config."""
        try:
            image = self.client.images.get(image_tag)
            cmd = image.attrs.get("Config", {}).get("Cmd")
            if cmd:
                return cmd
        except Exception:
            pass
        return []

    def spawn_container(
        self,
        image_tag: str,
        run_id: str,
        mem_limit: str = "2g",
        cpu_quota: int = 100000,
    ):
        """Start detached container with keep-alive wrapper.

        Wraps the image's original CMD to run in the background so that
        if the agent kills/restarts a service (PID 1), the container
        stays alive.
        """
        original_cmd = self._get_image_cmd(image_tag)
        if original_cmd:
            cmd_str = " ".join(original_cmd)
            wrapper = f"{cmd_str} & exec tail -f /dev/null"
        else:
            wrapper = "exec tail -f /dev/null"

        container = self.client.containers.run(
            image_tag,
            name=f"sysrepair-run-{run_id}",
            entrypoint=["/bin/bash", "-c"],
            command=[wrapper],
            detach=True,
            mem_limit=mem_limit,
            cpu_quota=cpu_quota,
            security_opt=["no-new-privileges"],
            cap_add=["NET_ADMIN", "SYS_ADMIN"],  # SYS_ADMIN for service management
            tty=False,
        )
        # Wait briefly for container to start
        time.sleep(1)
        # Track metadata for potential recreation
        self._container_meta[container.id] = {
            "image_tag": image_tag,
            "run_id": run_id,
            "mem_limit": mem_limit,
            "cpu_quota": cpu_quota,
            "verify_sh_path": None,
        }
        return container

    def copy_verify_script(self, container, verify_sh_path: Path) -> None:
        """Copy verify.sh into container at /opt/verify.sh."""
        self._copy_file_to_container(container, verify_sh_path, "/opt/verify.sh")
        # Remember path so we can re-copy after recreation
        if container.id in self._container_meta:
            self._container_meta[container.id]["verify_sh_path"] = verify_sh_path

    def _copy_file_to_container(
        self, container, local_path: Path, container_path: str
    ) -> None:
        """Copy a local file into a running container using a tar stream."""
        local_path = Path(local_path)
        data = local_path.read_bytes()
        # Build an in-memory tar archive
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name=container_path.split("/")[-1])
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))
        buf.seek(0)
        dest_dir = "/".join(container_path.split("/")[:-1]) or "/"
        container.put_archive(dest_dir, buf)

    def exec(
        self,
        container,
        cmd: str,
        timeout: int = 30,
        workdir: str = "/",
    ) -> CommandRecord:
        """Execute command in container, return CommandRecord."""
        t0 = time.time()
        try:
            # Wrap with timeout since exec_run doesn't support timeout kwarg
            wrapped_cmd = f"timeout {timeout} bash -c {self._shell_quote(cmd)}"
            exit_code, output = container.exec_run(
                cmd=["bash", "-c", wrapped_cmd],
                stdout=True,
                stderr=True,
                demux=True,
                workdir=workdir,
            )
            stdout_bytes, stderr_bytes = output if output else (b"", b"")
            stdout = (stdout_bytes or b"").decode("utf-8", errors="replace")
            stderr = (stderr_bytes or b"").decode("utf-8", errors="replace")
        except docker.errors.APIError as e:
            if "is not running" in str(e):
                crash_count = self._container_crashes.get(container.id, 0) + 1
                self._container_crashes[container.id] = crash_count
                logger.error(
                    f"Container crashed during exec (crash #{crash_count}): {e}"
                )
                if crash_count <= MAX_CRASH_RETRIES:
                    new_ctr = self._recreate_container(container)
                    if new_ctr is not None:
                        # Propagate crash count to new container
                        self._container_crashes[new_ctr.id] = crash_count
                        logger.info(
                            f"Container recreated successfully (crash #{crash_count})"
                        )
                else:
                    logger.error(
                        f"Container exceeded max crash retries ({MAX_CRASH_RETRIES}), giving up"
                    )
            exit_code = 1
            stdout = ""
            stderr = f"CONTAINER_CRASH: {e}"
        except Exception as e:
            exit_code = 1
            stdout = ""
            stderr = str(e)

        return CommandRecord(
            step=0,          # set by BaseAgent.bash()
            command=cmd,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code if exit_code is not None else 1,
            timestamp=t0,    # set by BaseAgent.bash()
            duration_ms=(time.time() - t0) * 1000,
        )

    def get_crash_count(self, container) -> int:
        """Return the number of times this container crashed and was restarted."""
        return self._container_crashes.get(container.id, 0)

    @staticmethod
    def _shell_quote(s: str) -> str:
        """Single-quote a string for shell, escaping embedded single quotes."""
        return "'" + s.replace("'", "'\\''") + "'"

    def exec_verify(
        self,
        container,
    ) -> tuple:
        """Run /opt/verify.sh oracle. Returns (passed, output)."""
        try:
            container.exec_run(["chmod", "+x", "/opt/verify.sh"])
            exit_code, output = container.exec_run(
                cmd=["bash", "-c", "timeout 60 bash /opt/verify.sh"],
                stdout=True, stderr=True, demux=True,
            )
            stdout_b, stderr_b = output if output else (b"", b"")
            combined = (stdout_b or b"").decode("utf-8", errors="replace") + \
                       (stderr_b or b"").decode("utf-8", errors="replace")
            passed = (exit_code == 0)
            return passed, combined
        except Exception as e:
            logger.warning(f"exec_verify failed: {e}")
            return False, f"Verification error: {e}"

    def _recreate_container(self, old_container):
        """Destroy a dead container and spawn a fresh one from the same image.

        Returns the new container, or None on failure.  Also re-copies
        verify.sh if the path was recorded.
        """
        meta = self._container_meta.get(old_container.id)
        if not meta:
            logger.error("Cannot recreate container: no metadata recorded")
            return None

        # Generate a new run_id suffix to avoid name collision
        import uuid
        new_run_id = meta["run_id"] + "-r" + str(uuid.uuid4())[:4]

        # Destroy the old container
        self.destroy(old_container)

        try:
            new_ctr = self.spawn_container(
                meta["image_tag"],
                new_run_id,
                mem_limit=meta.get("mem_limit", "2g"),
                cpu_quota=meta.get("cpu_quota", 100000),
            )
            # Re-copy verify script
            if meta.get("verify_sh_path"):
                self.copy_verify_script(new_ctr, meta["verify_sh_path"])
            # Store a callback so the harness can swap its reference
            self._last_recreated = new_ctr
            return new_ctr
        except Exception as e:
            logger.error(f"Failed to recreate container: {e}")
            return None

    def get_recreated_container(self):
        """Return and clear the most recently recreated container, if any."""
        ctr = getattr(self, "_last_recreated", None)
        self._last_recreated = None
        return ctr

    def destroy(self, container) -> None:
        """Stop + remove container and its volumes."""
        self._container_meta.pop(container.id, None)
        try:
            container.stop(timeout=10)
        except Exception:
            pass
        try:
            container.remove(v=True, force=True)
        except Exception:
            pass

    def snapshot(self, container) -> str:
        """docker commit — returns snapshot image ID."""
        img = container.commit()
        return img.id

    def restore(self, snapshot_image_id: str, run_id: str):
        """Spawn fresh container from snapshot."""
        return self.spawn_container(snapshot_image_id, run_id)
