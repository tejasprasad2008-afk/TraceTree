"""Hardened runner for import-only adaptive npm probes.

This module intentionally does not call the legacy ``run_sandbox`` helper.
That helper has a different threat model (including a network-capable mode and
host bind mounts).  Adaptive attempts are fresh, non-root, no-network Docker
containers populated through a one-shot tar archive.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import tarfile
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Mapping, Optional

from .environment import redact_directory
from .harness_renderer import render_harness
from .models import (
    DependencyClosure,
    HarnessPlan,
    HarnessRun,
    NpmArtifact,
    PackageMap,
    PreparedEnvironment,
)


class AdaptiveSandboxError(RuntimeError):
    """Base class for adaptive sandbox execution failures."""


class AdaptiveSandboxPolicyError(AdaptiveSandboxError):
    """Raised when a caller requests a mode that violates the contract."""


_MAX_INPUT_BYTES = 100 * 1024 * 1024
_MAX_OUTPUT_BYTES = 100 * 1024 * 1024
_MAX_OUTPUT_FILES = 10_000


class AdaptiveSandboxRunner:
    """Run an import-only probe in a newly-created hardened Docker container."""

    def __init__(
        self,
        docker_client: Any = None,
        image: str = "tracetree-adaptive-node:latest",
    ) -> None:
        self._docker_client = docker_client
        self.image = image

    def run_import_probe(
        self,
        artifact: NpmArtifact,
        package_map: PackageMap,
        environment: PreparedEnvironment,
        output_root: Path,
        timeout_seconds: float = 20,
        dependency_closure: Optional[DependencyClosure] = None,
    ) -> HarnessRun:
        """Import static entrypoints once, with V8 coverage and ``strace``.

        The caller supplies an already materialised fake profile.  No host
        directories, real credentials, or outbound network are exposed to the
        package.  A result is returned for package-level failures; exceptions
        are reserved for a broken runner or policy violation.
        """

        self._validate_request(artifact, package_map, environment, timeout_seconds, dependency_closure)
        return self._run(
            artifact=artifact,
            package_map=package_map,
            environment=environment,
            output_root=output_root,
            timeout_seconds=timeout_seconds,
            kind="import",
            script_path="/opt/tracetree/adaptive_import_probe.mjs",
            dependency_closure=dependency_closure,
        )

    def run_harness(
        self,
        artifact: NpmArtifact,
        package_map: PackageMap,
        plan: HarnessPlan,
        environment: PreparedEnvironment,
        output_root: Path,
        timeout_seconds: float = 20,
        dependency_closure: Optional[DependencyClosure] = None,
    ) -> HarnessRun:
        """Run one validated harness attempt in a fresh adaptive container."""

        self._validate_request(artifact, package_map, environment, timeout_seconds, dependency_closure)
        if plan.profile_id != environment.profile_id:
            raise AdaptiveSandboxPolicyError("harness plan and synthetic profile do not match")
        return self._run(
            artifact=artifact,
            package_map=package_map,
            environment=environment,
            output_root=output_root,
            timeout_seconds=timeout_seconds,
            kind="harness",
            script_path="/input/harness.mjs",
            extra_files={"harness.mjs": render_harness(plan).encode("utf-8")},
            dependency_closure=dependency_closure,
        )

    def _run(
        self,
        *,
        artifact: NpmArtifact,
        package_map: PackageMap,
        environment: PreparedEnvironment,
        output_root: Path,
        timeout_seconds: float,
        kind: str,
        script_path: str,
        extra_files: Optional[Mapping[str, bytes]] = None,
        dependency_closure: Optional[DependencyClosure] = None,
    ) -> HarnessRun:
        client = self._client()
        attempt_id = uuid.uuid4().hex
        run_dir = Path(output_root).resolve() / f"adaptive-{kind}-{artifact.sha256[:16]}-{attempt_id}"
        run_dir.mkdir(parents=True, mode=0o700)
        run_dir.chmod(0o700)
        stdout_path = run_dir / "stdout.log"
        stderr_path = run_dir / "stderr.log"
        container = None
        input_volume = None
        output_volume = None
        timed_out = False

        try:
            payload = _build_input_archive(
                artifact, package_map, environment, extra_files, dependency_closure
            )
            input_volume = self._materialize_input_volume(client, payload, attempt_id)
            output_volume = self._prepare_output_volume(client, attempt_id)
            container = client.containers.create(
                **self._container_options(
                    environment, script_path, kind, input_volume.name, output_volume.name
                )
            )
            container.start()
            timed_out = _wait_for_container(container, timeout_seconds)
            if timed_out:
                container.kill()

            stdout_path.write_bytes(_container_logs(container, stdout=True, stderr=False))
            stderr_path.write_bytes(_container_logs(container, stdout=False, stderr=True))
            _copy_container_output(container, run_dir)
            redact_directory(run_dir, environment)

            trace_path = run_dir / "strace.log"
            coverage_dir = run_dir / "v8"
            return HarnessRun(
                attempt_id=attempt_id,
                profile_id=environment.profile_id,
                outcome="timed_out" if timed_out else _container_outcome(container),
                output_dir=run_dir,
                trace_path=trace_path if trace_path.is_file() else None,
                coverage_dir=coverage_dir if coverage_dir.is_dir() else None,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                timed_out=timed_out,
            )
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    # A failed cleanup must not hide the evidence already
                    # written to the owner-only run directory.
                    pass
            if input_volume is not None:
                try:
                    input_volume.remove(force=True)
                except Exception:
                    pass
            if output_volume is not None:
                try:
                    output_volume.remove(force=True)
                except Exception:
                    pass

    def _client(self) -> Any:
        if self._docker_client is not None:
            return self._docker_client
        try:
            import docker
        except ImportError as exc:  # pragma: no cover - project dependency
            raise AdaptiveSandboxError("Docker SDK is not installed") from exc
        return docker.from_env()

    def _validate_request(
        self,
        artifact: NpmArtifact,
        package_map: PackageMap,
        environment: PreparedEnvironment,
        timeout_seconds: float,
        dependency_closure: Optional[DependencyClosure],
    ) -> None:
        if os.environ.get("TRACETREE_SANDBOX_MODE", "").strip().lower() == "direct":
            raise AdaptiveSandboxPolicyError("adaptive npm execution is unavailable in direct mode")
        if package_map.artifact_sha256 != artifact.sha256:
            raise AdaptiveSandboxPolicyError("package map does not belong to this artifact")
        if dependency_closure and dependency_closure.root_artifact_sha256 != artifact.sha256:
            raise AdaptiveSandboxPolicyError("dependency closure does not belong to this artifact")
        if environment.profile_id not in {
            "node-library-v1",
            "developer-workstation-v1",
            "ci-runner-v1",
            "cloud-service-v1",
            "commerce-client-v1",
        }:
            raise AdaptiveSandboxPolicyError(f"unrecognised environment profile: {environment.profile_id}")
        if not environment.root.is_dir():
            raise AdaptiveSandboxPolicyError("synthetic environment has not been materialised")
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise AdaptiveSandboxPolicyError("adaptive probe timeout must be between 0 and 60 seconds")

    def _materialize_input_volume(self, client: Any, payload: bytes, attempt_id: str) -> Any:
        """Fill one Docker-managed volume without exposing it to package code.

        Docker rejects ``put_archive`` against all read-only containers,
        including containers that have a writable tmpfs.  A short-lived loader
        therefore receives the archive first.  The actual execution container
        mounts the same new volume read-only, so it keeps a read-only root,
        no capabilities, and no host bind mounts.
        """

        volume = client.volumes.create(
            name=f"tracetree-adaptive-{attempt_id}",
            labels={"tracetree.component": "adaptive-npm-input", "tracetree.ephemeral": "true"},
        )
        loader = None
        try:
            loader = client.containers.create(
                image=self.image,
                command=["/bin/sh", "-c", "sleep 20"],
                detach=True,
                user="0:0",
                network_mode="none",
                read_only=False,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                pids_limit=8,
                mem_limit="64m",
                volumes={volume.name: {"bind": "/input", "mode": "rw"}},
                labels={"tracetree.component": "adaptive-npm-input-loader"},
            )
            loader.start()
            if not loader.put_archive("/input", payload):
                raise AdaptiveSandboxError("Docker rejected adaptive sandbox input archive")
            loader.remove(force=True)
            return volume
        except Exception:
            if loader is not None:
                try:
                    loader.remove(force=True)
                except Exception:
                    pass
            try:
                volume.remove(force=True)
            except Exception:
                pass
            raise

    def _prepare_output_volume(self, client: Any, attempt_id: str) -> Any:
        """Create an evidence volume writable only by the target uid.

        A tmpfs disappears as soon as the execution container exits, before
        Docker can retrieve it.  The evidence volume is instead fresh for this
        one attempt, mounted only at ``/out``, and removed after extraction.
        """

        volume = client.volumes.create(
            name=f"tracetree-adaptive-out-{attempt_id}",
            labels={"tracetree.component": "adaptive-npm-output", "tracetree.ephemeral": "true"},
        )
        initializer = None
        try:
            initializer = client.containers.create(
                image=self.image,
                command=["/bin/sh", "-c", "chmod 0700 /out && chown 10001:10001 /out"],
                detach=True,
                user="0:0",
                network_mode="none",
                read_only=True,
                cap_drop=["ALL"],
                cap_add=["CHOWN", "FOWNER"],
                security_opt=["no-new-privileges:true"],
                pids_limit=8,
                mem_limit="64m",
                volumes={volume.name: {"bind": "/out", "mode": "rw"}},
                labels={"tracetree.component": "adaptive-npm-output-initializer"},
            )
            initializer.start()
            if _wait_for_container(initializer, 5):
                raise AdaptiveSandboxError("adaptive output volume initializer timed out")
            if _container_outcome(initializer) != "completed":
                detail = _container_logs(initializer, stdout=False, stderr=True).decode(
                    "utf-8", errors="replace"
                )[:1_000]
                raise AdaptiveSandboxError(
                    f"adaptive output volume initializer failed: {detail.strip() or 'no stderr'}"
                )
            initializer.remove(force=True)
            return volume
        except Exception:
            if initializer is not None:
                try:
                    initializer.remove(force=True)
                except Exception:
                    pass
            try:
                volume.remove(force=True)
            except Exception:
                pass
            raise

    def _container_options(
        self,
        environment: PreparedEnvironment,
        script_path: str,
        kind: str,
        input_volume_name: str,
        output_volume_name: str,
    ) -> Dict[str, Any]:
        runtime_environment = {
            "NODE_V8_COVERAGE": "/out/v8",
            "TT_PACKAGE_DIR": "/input/package",
            "TT_PROBE_RESULTS": "/out/import-results.ndjson",
            "TT_ENTRYPOINTS_PATH": "/input/entrypoints.json",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            **environment.container_environment,
        }
        return {
            "image": self.image,
            "command": [
                "strace",
                "-f",
                "-t",
                "-e",
                "trace=all",
                "-yy",
                "-s",
                "1000",
                "-o",
                "/out/strace.log",
                "node",
                "--no-addons",
                "--disable-proto=throw",
                script_path,
                *(["/input/entrypoints.json"] if kind == "import" else []),
            ],
            "detach": True,
            "user": "10001:10001",
            "network_mode": "none",
            "read_only": True,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "pids_limit": 64,
            "mem_limit": "512m",
            "cpu_period": 100000,
            "cpu_quota": 25000,
            "tmpfs": {
                "/tmp": "rw,noexec,nosuid,nodev,size=64m",
            },
            "environment": runtime_environment,
            "volumes": {
                input_volume_name: {"bind": "/input", "mode": "ro"},
                output_volume_name: {"bind": "/out", "mode": "rw"},
            },
            "labels": {
                "tracetree.component": f"adaptive-npm-{kind}",
                "tracetree.profile": environment.profile_id,
            },
        }


def _build_input_archive(
    artifact: NpmArtifact,
    package_map: PackageMap,
    environment: PreparedEnvironment,
    extra_files: Optional[Mapping[str, bytes]] = None,
    dependency_closure: Optional[DependencyClosure] = None,
) -> bytes:
    """Return a read-only tar payload containing only artifact/profile data."""

    config = {
        "artifact_sha256": artifact.sha256,
        "entrypoints": [
            {
                "specifier": entrypoint.specifier,
                "import_path": entrypoint.import_path,
                "require_path": entrypoint.require_path,
            }
            for entrypoint in package_map.entrypoints
        ],
        "dependencies": dependency_closure.as_dict() if dependency_closure else None,
    }
    output = io.BytesIO()
    byte_count = 0
    with tarfile.open(fileobj=output, mode="w") as archive:
        byte_count = _add_tree(archive, artifact.package_dir, "package", byte_count)
        if dependency_closure:
            for install in dependency_closure.installs:
                archive_root = _dependency_archive_root(artifact, install.install_path)
                byte_count = _add_tree(archive, install.artifact.package_dir, archive_root, byte_count)
        byte_count = _add_tree(archive, environment.root, "profile", byte_count)
        encoded = json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")
        byte_count += len(encoded)
        _ensure_input_size(byte_count)
        member = tarfile.TarInfo("entrypoints.json")
        member.size = len(encoded)
        member.mode = 0o444
        member.uid = member.gid = 10001
        member.mtime = 0
        archive.addfile(member, io.BytesIO(encoded))
        for name, payload in sorted((extra_files or {}).items()):
            byte_count = _add_extra_file(archive, name, payload, byte_count)
    return output.getvalue()


def _dependency_archive_root(root_artifact: NpmArtifact, install_path: str) -> str:
    relative = PurePosixPath(install_path)
    if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise AdaptiveSandboxPolicyError(f"unsafe dependency install path: {install_path}")
    destination = root_artifact.package_dir.joinpath(*relative.parts)
    if destination.exists():
        raise AdaptiveSandboxPolicyError(
            f"dependency install path conflicts with immutable root artifact: {install_path}"
        )
    return f"package/{relative.as_posix()}"


def _add_extra_file(archive: tarfile.TarFile, name: str, payload: bytes, byte_count: int) -> int:
    path = PurePosixPath(name)
    if path.is_absolute() or len(path.parts) != 1 or path.name != name:
        raise AdaptiveSandboxPolicyError(f"unsafe adaptive runner file name: {name}")
    if not isinstance(payload, bytes):
        raise AdaptiveSandboxPolicyError(f"adaptive runner file must be bytes: {name}")
    _ensure_input_size(byte_count + len(payload))
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    member.mode = 0o444
    member.uid = member.gid = 10001
    member.mtime = 0
    archive.addfile(member, io.BytesIO(payload))
    return byte_count + len(payload)


def _add_tree(archive: tarfile.TarFile, source_root: Path, archive_root: str, byte_count: int) -> int:
    """Add a tree with invariant ownership and read-only file modes."""

    source_root = Path(source_root).resolve()
    _add_directory_member(archive, archive_root)
    for path in sorted(source_root.rglob("*")):
        relative = path.relative_to(source_root).as_posix()
        arcname = f"{archive_root}/{relative}"
        stat = path.lstat()
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise AdaptiveSandboxPolicyError(f"adaptive input contains unsupported file type: {path}")
        if path.is_dir():
            _add_directory_member(archive, arcname)
            continue
        byte_count += stat.st_size
        _ensure_input_size(byte_count)
        info = tarfile.TarInfo(arcname)
        info.size = stat.st_size
        info.mode = 0o444
        info.uid = info.gid = 10001
        info.mtime = 0
        with path.open("rb") as input_file:
            archive.addfile(info, input_file)
    return byte_count


def _add_directory_member(archive: tarfile.TarFile, arcname: str) -> None:
    info = tarfile.TarInfo(arcname)
    info.type = tarfile.DIRTYPE
    info.mode = 0o555
    info.uid = info.gid = 10001
    info.mtime = 0
    archive.addfile(info)


def _ensure_input_size(byte_count: int) -> None:
    if byte_count > _MAX_INPUT_BYTES:
        raise AdaptiveSandboxPolicyError("adaptive input exceeds 100 MiB limit")


def _wait_for_container(container: Any, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        container.reload()
        status = getattr(container, "status", None)
        if status == "exited":
            return False
        if time.monotonic() >= deadline:
            return True
        time.sleep(0.1)


def _container_logs(container: Any, *, stdout: bool, stderr: bool) -> bytes:
    try:
        payload = container.logs(stdout=stdout, stderr=stderr)
    except Exception:
        return b""
    return payload if isinstance(payload, bytes) else bytes(payload)


def _copy_container_output(container: Any, destination: Path) -> None:
    """Safely extract the runner's ``/out`` archive into ``destination``."""

    try:
        stream, _metadata = container.get_archive("/out")
    except Exception as exc:
        _record_output_extraction_error(destination, f"could not retrieve /out archive: {exc}")
        return
    archive_bytes = b"".join(stream)
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as archive:
            _extract_output_archive(archive, destination)
    except (tarfile.TarError, OSError, ValueError) as exc:
        # Keep stdout/stderr even when a hostile or corrupt output archive is
        # rejected.  The run must not write files outside its evidence root.
        _record_output_extraction_error(destination, f"could not extract /out archive: {exc}")
        return


def _record_output_extraction_error(destination: Path, message: str) -> None:
    path = Path(destination) / "output-extraction-error.txt"
    path.write_text(message[:2_000], encoding="utf-8")
    path.chmod(0o600)


def _extract_output_archive(archive: tarfile.TarFile, destination: Path) -> None:
    root = Path(destination).resolve()
    files = 0
    total_bytes = 0
    for member in archive.getmembers():
        parts = PurePosixPath(member.name).parts
        if not parts or parts[0] != "out":
            raise ValueError(f"unexpected container output path: {member.name}")
        relative_parts = parts[1:]
        if not relative_parts:
            continue
        if any(part in {"", ".", ".."} for part in relative_parts):
            raise ValueError(f"unsafe container output path: {member.name}")
        target = root.joinpath(*relative_parts).resolve()
        if target != root and root not in target.parents:
            raise ValueError(f"unsafe container output path: {member.name}")
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.chmod(0o700)
            continue
        if not member.isfile():
            raise ValueError(f"unsupported container output member: {member.name}")
        files += 1
        total_bytes += member.size
        if files > _MAX_OUTPUT_FILES or total_bytes > _MAX_OUTPUT_BYTES:
            raise ValueError("container output exceeds extraction limits")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        source = archive.extractfile(member)
        if source is None:
            raise ValueError(f"missing container output data: {member.name}")
        with source, target.open("wb") as output:
            shutil.copyfileobj(source, output)
        target.chmod(0o600)


def _container_outcome(container: Any) -> str:
    state = getattr(container, "attrs", {}).get("State", {})
    exit_code = state.get("ExitCode")
    return "completed" if exit_code in (0, None) else f"container_exit_{exit_code}"
