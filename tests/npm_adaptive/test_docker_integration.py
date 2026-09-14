"""Real-Docker smoke coverage for the hardened adaptive runner.

Run explicitly with ``pytest -m integration tests/npm_adaptive/test_docker_integration.py``.
The fixture is generated locally and does not download or execute a third-party
package.
"""

from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path

import pytest

from npm_adaptive.artifact_store import ArtifactStore
from npm_adaptive.coverage import summarize_v8_coverage
from npm_adaptive.environment import prepare_environment
from npm_adaptive.models import DependencyClosure, DependencyInstall
from npm_adaptive.plan_schema import PLAN_SCHEMA_VERSION, validate_harness_plan
from npm_adaptive.probe_results import load_import_probe_results
from npm_adaptive.sandbox_runner import AdaptiveSandboxRunner
from npm_adaptive.static_mapper import build_package_map


def _docker_client_or_skip():
    if os.environ.get("TRACETREE_RUN_DOCKER_INTEGRATION") != "1":
        pytest.skip("set TRACETREE_RUN_DOCKER_INTEGRATION=1 to run Docker integration tests")
    try:
        import docker

        client = docker.from_env()
        client.ping()
        client.images.get("tracetree-adaptive-node:latest")
        return client
    except Exception as exc:
        pytest.skip(f"adaptive Docker image is unavailable: {exc}")


def _safe_fixture_artifact(tmp_path: Path):
    store = ArtifactStore(tmp_path / "artifacts")
    tarball = tmp_path / "safe-demo.tgz"
    source = """
const fs = require('node:fs');
const suffix = require('tiny-dependency');
const token = process.env.NPM_TOKEN || 'no-token';
fs.readFileSync(`${process.env.HOME}/.npmrc`, 'utf8');
console.log(`synthetic-token=${token}`);
exports.greet = (name) => `hello ${name}${suffix}`;
""".strip()
    with tarfile.open(tarball, "w:gz") as archive:
        for name, content in {
            "package/package.json": '{"name":"safe-adaptive-demo","version":"1.0.0","main":"index.js"}',
            "package/index.js": source,
        }.items():
            encoded = content.encode("utf-8")
            member = tarfile.TarInfo(name)
            member.size = len(encoded)
            archive.addfile(member, io.BytesIO(encoded))
    artifact = store.ingest_tarball(
        tarball, "safe-adaptive-demo@1.0.0"
    )
    dependency_tarball = tmp_path / "tiny-dependency.tgz"
    with tarfile.open(dependency_tarball, "w:gz") as archive:
        for name, content in {
            "package/package.json": '{"name":"tiny-dependency","version":"1.0.0","main":"index.js"}',
            "package/index.js": "module.exports = '-from-dependency';",
        }.items():
            encoded = content.encode("utf-8")
            member = tarfile.TarInfo(name)
            member.size = len(encoded)
            archive.addfile(member, io.BytesIO(encoded))
    dependency = store.ingest_tarball(dependency_tarball, "tiny-dependency@1.0.0")
    closure = DependencyClosure(
        root_artifact_sha256=artifact.sha256,
        installs=[
            DependencyInstall(
                artifact=dependency,
                install_path="node_modules/tiny-dependency",
                requested_by="safe-adaptive-demo",
                requested_range="1.0.0",
            )
        ],
    )
    return artifact, build_package_map(artifact), closure


@pytest.mark.integration
def test_real_docker_import_and_harness_preserve_canary_redaction_and_coverage(tmp_path: Path):
    client = _docker_client_or_skip()
    artifact, package_map, closure = _safe_fixture_artifact(tmp_path)
    runner = AdaptiveSandboxRunner(client)
    import_environment = prepare_environment("developer-workstation-v1", tmp_path / "import-profile")

    import_run = runner.run_import_probe(
        artifact, package_map, import_environment, tmp_path / "runs", dependency_closure=closure
    )

    assert import_run.outcome == "completed"
    assert import_run.trace_path and import_run.trace_path.is_file()
    assert import_run.coverage_dir and import_run.coverage_dir.is_dir()
    assert load_import_probe_results(import_run.output_dir) == [
        {
            "specifier": "safe-adaptive-demo",
            "loader": "import",
            "path": "index.js",
            "outcome": "ok",
        },
        {
            "specifier": "safe-adaptive-demo",
            "loader": "require",
            "path": "index.js",
            "outcome": "ok",
        },
    ]
    import_stdout = import_run.stdout_path.read_text(encoding="utf-8")
    assert import_environment.secret_values["npm_token"] not in import_stdout
    assert "[REDACTED:npm_token]" in import_stdout
    import_coverage = summarize_v8_coverage(import_run.coverage_dir, package_map, Path("/input/package"))
    assert "index.js" in import_coverage.executed_files

    plan = validate_harness_plan(
        {
            "schema_version": PLAN_SCHEMA_VERSION,
            "profile_id": "developer-workstation-v1",
            "attempt_budget": 1,
            "actions": [
                {
                    "entrypoint": "safe-adaptive-demo",
                    "loader": "require",
                    "export_name": "greet",
                    "operation": "call",
                    "fixtures": ["string-basic"],
                    "timeout_ms": 1000,
                }
            ],
        },
        package_map,
    )
    harness_environment = prepare_environment("developer-workstation-v1", tmp_path / "harness-profile")
    harness_run = runner.run_harness(
        artifact, package_map, plan, harness_environment, tmp_path / "runs", dependency_closure=closure
    )

    assert harness_run.outcome == "completed"
    assert harness_run.coverage_dir and harness_run.coverage_dir.is_dir()
    assert "action_complete" in harness_run.stdout_path.read_text(encoding="utf-8")
    harness_coverage = summarize_v8_coverage(harness_run.coverage_dir, package_map, Path("/input/package"))
    assert "safe-adaptive-demo:greet" in harness_coverage.exercised_exports
