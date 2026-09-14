from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from npm_adaptive.artifact_store import ArtifactStore
from npm_adaptive.environment import prepare_environment
from npm_adaptive.models import DependencyClosure, DependencyInstall
from npm_adaptive.plan_schema import PLAN_SCHEMA_VERSION, validate_harness_plan
from npm_adaptive.sandbox_runner import (
    AdaptiveSandboxPolicyError,
    AdaptiveSandboxRunner,
)
from npm_adaptive.static_mapper import build_package_map


def _tarball(path: Path) -> Path:
    with tarfile.open(path, "w:gz") as archive:
        for name, content in {
            "package/package.json": '{"name":"probe-demo","version":"1.0.0","main":"index.js"}',
            "package/index.js": "exports.hello = () => 'ok';",
        }.items():
            payload = content.encode("utf-8")
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    return path


class _FakeContainer:
    def __init__(self) -> None:
        self.status = "created"
        self.attrs = {"State": {"ExitCode": 0}}
        self.removed = False
        self.input_archives: list[tuple[str, bytes]] = []
        self.token = ""

    def put_archive(self, path: str, payload: bytes) -> bool:
        self.input_archives.append((path, payload))
        return True

    def start(self) -> None:
        self.status = "exited"

    def reload(self) -> None:
        return None

    def kill(self) -> None:
        self.status = "exited"

    def logs(self, *, stdout: bool, stderr: bool) -> bytes:
        if stdout:
            return f"target printed {self.token}".encode("utf-8")
        return b""

    def get_archive(self, path: str):
        assert path == "/out"
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w") as archive:
            for name, content in {
                "out/strace.log": "123 openat(AT_FDCWD, \"/input/package/index.js\", O_RDONLY) = 3\n",
                "out/v8/coverage-1.json": '{"result": []}',
            }.items():
                encoded = content.encode("utf-8")
                member = tarfile.TarInfo(name)
                member.size = len(encoded)
                archive.addfile(member, io.BytesIO(encoded))
        return [payload.getvalue()], {"name": "out"}

    def remove(self, *, force: bool) -> None:
        assert force is True
        self.removed = True


class _FakeContainers:
    def __init__(self) -> None:
        self.created: list[dict] = []
        self.container = _FakeContainer()
        self.loader = _FakeContainer()
        self.output_initializer = _FakeContainer()

    def create(self, **options):
        self.created.append(options)
        if options["labels"]["tracetree.component"] == "adaptive-npm-input-loader":
            return self.loader
        if options["labels"]["tracetree.component"] == "adaptive-npm-output-initializer":
            return self.output_initializer
        self.container.token = options["environment"].get("NPM_TOKEN", "synthetic-empty-token")
        return self.container


class _FakeVolume:
    def __init__(self, name: str) -> None:
        self.name = name
        self.removed = False

    def remove(self, *, force: bool) -> None:
        assert force is True
        self.removed = True


class _FakeVolumes:
    def __init__(self) -> None:
        self.created: list[dict] = []
        self.volumes: list[_FakeVolume] = []

    def create(self, **options):
        self.created.append(options)
        volume = _FakeVolume(options["name"])
        self.volumes.append(volume)
        return volume


class _FakeDockerClient:
    def __init__(self) -> None:
        self.containers = _FakeContainers()
        self.volumes = _FakeVolumes()


def _fixture(tmp_path: Path):
    artifact = ArtifactStore(tmp_path / "artifacts").ingest_tarball(
        _tarball(tmp_path / "package.tgz"), "probe-demo@1.0.0"
    )
    return artifact, build_package_map(artifact)


def _dependency_artifact(tmp_path: Path):
    tarball = tmp_path / "dependency.tgz"
    with tarfile.open(tarball, "w:gz") as archive:
        for name, content in {
            "package/package.json": '{"name":"tiny-dependency","version":"1.0.0","main":"index.js"}',
            "package/index.js": "module.exports = 42;",
        }.items():
            payload = content.encode("utf-8")
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    return ArtifactStore(tmp_path / "dependency-artifacts").ingest_tarball(
        tarball, "tiny-dependency@1.0.0"
    )


def test_import_probe_uses_fresh_bootstrap_then_non_root_no_network_container(tmp_path: Path):
    artifact, package_map = _fixture(tmp_path)
    environment = prepare_environment("developer-workstation-v1", tmp_path / "profile")
    client = _FakeDockerClient()

    run = AdaptiveSandboxRunner(client).run_import_probe(
        artifact, package_map, environment, tmp_path / "runs"
    )

    options = client.containers.created[2]
    assert options["network_mode"] == "none"
    assert options["user"] == "10001:10001"
    assert options["read_only"] is True
    assert options["cap_drop"] == ["ALL"]
    assert options["security_opt"] == ["no-new-privileges:true"]
    assert options["volumes"] == {
        client.volumes.volumes[0].name: {"bind": "/input", "mode": "ro"},
        client.volumes.volumes[1].name: {"bind": "/out", "mode": "rw"},
    }
    assert client.containers.loader.input_archives[0][0] == "/input"
    assert client.containers.created[1]["cap_add"] == ["CHOWN", "FOWNER"]
    assert client.containers.container.status == "exited"
    assert client.containers.container.removed is True
    assert client.containers.loader.removed is True
    assert client.containers.output_initializer.removed is True
    assert all(volume.removed for volume in client.volumes.volumes)
    assert run.trace_path and run.trace_path.is_file()
    assert run.coverage_dir and run.coverage_dir.is_dir()
    assert environment.secret_values["npm_token"] not in run.stdout_path.read_text()
    assert "[REDACTED:npm_token]" in run.stdout_path.read_text()


def test_import_probe_refuses_direct_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    artifact, package_map = _fixture(tmp_path)
    environment = prepare_environment("node-library-v1", tmp_path / "profile")
    monkeypatch.setenv("TRACETREE_SANDBOX_MODE", "direct")

    with pytest.raises(AdaptiveSandboxPolicyError, match="direct mode"):
        AdaptiveSandboxRunner(_FakeDockerClient()).run_import_probe(
            artifact, package_map, environment, tmp_path / "runs"
        )


def test_import_probe_materialises_verified_dependency_tree(tmp_path: Path):
    artifact, package_map = _fixture(tmp_path)
    dependency = _dependency_artifact(tmp_path)
    closure = DependencyClosure(
        root_artifact_sha256=artifact.sha256,
        installs=[
            DependencyInstall(
                artifact=dependency,
                install_path="node_modules/tiny-dependency",
                requested_by="probe-demo",
                requested_range="^1.0.0",
            )
        ],
    )
    environment = prepare_environment("node-library-v1", tmp_path / "profile")
    client = _FakeDockerClient()

    AdaptiveSandboxRunner(client).run_import_probe(
        artifact, package_map, environment, tmp_path / "runs", dependency_closure=closure
    )

    payload = client.containers.loader.input_archives[0][1]
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        assert archive.getmember("package/node_modules/tiny-dependency/package.json")


def test_harness_uses_validated_generated_source_in_another_fresh_container(tmp_path: Path):
    artifact, package_map = _fixture(tmp_path)
    environment = prepare_environment("node-library-v1", tmp_path / "profile")
    plan = validate_harness_plan(
        {
            "schema_version": PLAN_SCHEMA_VERSION,
            "profile_id": "node-library-v1",
            "attempt_budget": 1,
            "actions": [
                {
                    "entrypoint": "probe-demo",
                    "loader": "require",
                    "export_name": "hello",
                    "operation": "call",
                    "fixtures": [],
                    "timeout_ms": 1000,
                }
            ],
        },
        package_map,
    )
    client = _FakeDockerClient()

    run = AdaptiveSandboxRunner(client).run_harness(
        artifact, package_map, plan, environment, tmp_path / "runs"
    )

    options = client.containers.created[2]
    assert options["command"][-1] == "/input/harness.mjs"
    payload = client.containers.loader.input_archives[0][1]
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        harness = archive.extractfile("harness.mjs")
        assert harness is not None
        source = harness.read().decode("utf-8")
    assert "child_process" not in source
    assert "TRACE_TREE_UNRESOLVED_ENTRYPOINT" in source
    assert run.outcome == "completed"
