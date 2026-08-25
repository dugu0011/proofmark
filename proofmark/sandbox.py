"""A throwaway Docker container the agent works inside.

Every command the agent runs and every request it makes happens in here, not on
the host. The container:

  * drops all Linux capabilities and sets no-new-privileges
  * has capped memory and process count, so a runaway payload cannot exhaust the
    host
  * mounts a tmpfs workspace and nothing from the host filesystem
  * is removed when the run ends, whatever happened

It keeps network access, because reaching the target is the point — the scope
guard in authorization.py is what keeps that from becoming "reach anything".
"""
from __future__ import annotations

import io
import tarfile
import time
from pathlib import Path

try:
    import docker
    from docker.errors import DockerException, ImageNotFound, NotFound
except ImportError:  # surfaced with a clear message by cli.doctor()
    docker = None
    DockerException = ImageNotFound = NotFound = Exception


DEFAULT_IMAGE = "python:3.12-slim"
_RUNNER = Path(__file__).parent / "resources" / "http_runner.py"


class SandboxError(RuntimeError):
    """The sandbox could not be started or a command could not be run."""


class Sandbox:
    def __init__(
        self,
        image: str = DEFAULT_IMAGE,
        *,
        mem_limit: str = "512m",
        pids_limit: int = 256,
        name_prefix: str = "proofmark",
    ) -> None:
        if docker is None:
            raise SandboxError("the 'docker' package is not installed (pip install docker)")
        self.image = image
        self.mem_limit = mem_limit
        self.pids_limit = pids_limit
        self.name = f"{name_prefix}-{int(time.time())}"
        # The runner lives outside /work: /work is a tmpfs mount, and Docker's
        # put_archive writes to the image layer *under* a mount, where the file
        # would be invisible. /opt is not mounted, so it lands and stays.
        self.runner_path = "/opt/proofmark/http_runner.py"
        # Where a code target is copied inside the jail. Not a mount, so the
        # agent can read, build and run it without ever touching the host.
        self.source_root = "/src"
        self._client = None
        self._container = None

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        try:
            self._client = docker.from_env()
            self._client.ping()
        except DockerException as exc:
            raise SandboxError(f"cannot reach Docker: {exc}. Is the daemon running?") from exc

        self._ensure_image()
        try:
            self._container = self._client.containers.run(
                self.image,
                command=["sleep", "infinity"],
                name=self.name,
                detach=True,
                network_mode="bridge",
                mem_limit=self.mem_limit,
                pids_limit=self.pids_limit,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                tmpfs={"/work": "rw,size=128m,mode=1777"},
                working_dir="/work",
                labels={"app": "proofmark"},
            )
        except DockerException as exc:
            raise SandboxError(f"could not start the sandbox container: {exc}") from exc

        self._install_runner()

    def stop(self) -> None:
        if self._container is not None:
            try:
                self._container.remove(force=True)
            except DockerException:
                pass
            self._container = None

    def __enter__(self) -> "Sandbox":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # -- running things ----------------------------------------------------
    def exec(self, command: list[str] | str, timeout: int = 30) -> tuple[int, str]:
        """Run a command in the sandbox. Returns (exit_code, combined_output).

        Wrapped in coreutils `timeout` so a hanging command cannot stall the
        whole run — Debian slim ships it.
        """
        if self._container is None:
            raise SandboxError("sandbox is not started")
        if isinstance(command, str):
            argv = ["timeout", "--signal=KILL", str(timeout), "sh", "-lc", command]
        else:
            argv = ["timeout", "--signal=KILL", str(timeout), *command]
        try:
            result = self._container.exec_run(argv, demux=False)
        except DockerException as exc:
            return 1, f"[sandbox error] {exc}"
        out = result.output.decode("utf-8", "replace") if result.output else ""
        return result.exit_code, out

    # -- setup helpers -----------------------------------------------------
    def _ensure_image(self) -> None:
        try:
            self._client.images.get(self.image)
        except ImageNotFound:
            # First run pulls the base image; can take a moment.
            self._client.images.pull(self.image)

    def _install_runner(self) -> None:
        """Copy the HTTP runner into the container, outside the tmpfs mount."""
        self._container.exec_run(["mkdir", "-p", "/opt/proofmark"])
        data = _RUNNER.read_bytes()
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as tar:
            info = tarfile.TarInfo("http_runner.py")
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))
        stream.seek(0)
        if not self._container.put_archive("/opt/proofmark", stream.getvalue()):
            raise SandboxError("could not install the HTTP runner into the sandbox")

    def copy_in(self, local_dir, dest: str | None = None) -> str:
        """Copy a local directory tree into the sandbox. Returns the dest path.

        Places a code target inside the jail. Skips the usual noise (.git,
        node_modules, venvs) and very large blobs so a big repo does not blow up
        the transfer.
        """
        from pathlib import Path as _P

        dest = dest or self.source_root
        self._container.exec_run(["mkdir", "-p", dest])
        skip = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
        root = _P(local_dir)
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as tar:
            for path in root.rglob("*"):
                rel = path.relative_to(root)
                if any(part in skip for part in rel.parts):
                    continue
                if path.is_file() and path.stat().st_size < 2_000_000:
                    tar.add(path, arcname=str(rel))
        stream.seek(0)
        if not self._container.put_archive(dest, stream.getvalue()):
            raise SandboxError("could not copy the source into the sandbox")
        return dest
