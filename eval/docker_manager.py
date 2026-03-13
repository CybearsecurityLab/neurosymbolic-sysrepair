import docker
import time
from pathlib import Path
from baselines.state import CommandRecord


class DockerManager:
    def __init__(self, docker_url: str = "unix://var/run/docker.sock"):
        self.client = docker.from_env()
        self._built_images: set = set()  # cache

    def build_image(self, scenario, tag: str | None = None) -> str:
        """Build Docker image from scenario Dockerfile. Returns image tag."""
        tag = tag or f"sysrepair-{scenario.id}:latest"
        if tag not in self._built_images:
            self.client.images.build(
                path=str(scenario.dockerfile_path.parent),
                tag=tag,
                rm=True,
                forcerm=True,
            )
            self._built_images.add(tag)
        return tag

    def spawn_container(
        self,
        image_tag: str,
        run_id: str,
        mem_limit: str = "2g",
        cpu_quota: int = 100000,
    ):
        """Start detached container with security constraints."""
        container = self.client.containers.run(
            image_tag,
            name=f"sysrepair-run-{run_id}",
            detach=True,
            network_mode="none",
            mem_limit=mem_limit,
            cpu_quota=cpu_quota,
            security_opt=["no-new-privileges"],
            cap_drop=["ALL"],
            cap_add=["NET_ADMIN", "SYS_ADMIN"],  # SYS_ADMIN for service management
            tty=False,
        )
        # Wait briefly for container to start
        time.sleep(1)
        return container

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
            exit_code, output = container.exec_run(
                cmd=["bash", "-c", cmd],
                stdout=True,
                stderr=True,
                demux=True,
                workdir=workdir,
                timeout=timeout,
            )
            stdout_bytes, stderr_bytes = output if output else (b"", b"")
            stdout = (stdout_bytes or b"").decode("utf-8", errors="replace")
            stderr = (stderr_bytes or b"").decode("utf-8", errors="replace")
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

    def exec_verify(
        self,
        container,
    ) -> tuple:
        """Run /opt/verify.sh oracle. Returns (passed, output)."""
        # Make verify.sh executable
        container.exec_run(["chmod", "+x", "/opt/verify.sh"])
        exit_code, output = container.exec_run(
            cmd=["bash", "/opt/verify.sh"],
            stdout=True, stderr=True, demux=True, timeout=60,
        )
        stdout_b, stderr_b = output if output else (b"", b"")
        combined = (stdout_b or b"").decode("utf-8", errors="replace") + \
                   (stderr_b or b"").decode("utf-8", errors="replace")
        passed = (exit_code == 0)
        return passed, combined

    def destroy(self, container) -> None:
        """Stop + remove container and its volumes."""
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
