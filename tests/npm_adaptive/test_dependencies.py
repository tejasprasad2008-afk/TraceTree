from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from npm_adaptive.artifact_store import ArtifactStore
from npm_adaptive.dependencies import DependencyResolver
from npm_adaptive.registry import ResolvedNpmRelease, parse_registry_specifier


def _artifact(store: ArtifactStore, tmp_path: Path, name: str, version: str, **manifest_fields):
    manifest = {"name": name, "version": version, "main": "index.js", **manifest_fields}
    tarball = tmp_path / f"{name.replace('/', '_').replace('@', '')}-{version}.tgz"
    with tarfile.open(tarball, "w:gz") as archive:
        for path, content in {
            "package/package.json": json.dumps(manifest),
            "package/index.js": "module.exports = true;",
        }.items():
            encoded = content.encode("utf-8")
            member = tarfile.TarInfo(path)
            member.size = len(encoded)
            archive.addfile(member, io.BytesIO(encoded))
    return store.ingest_tarball(tarball, f"{name}@{version}")


class _Broker:
    def __init__(self, artifacts):
        self.artifacts = artifacts
        self.requests = []

    def fetch_to_store(self, specifier, store):
        name, selector = parse_registry_specifier(specifier)
        self.requests.append((name, selector))
        artifact = self.artifacts[name]
        return artifact, ResolvedNpmRelease(
            requested_specifier=specifier,
            package_name=name,
            version=artifact.version,
            tarball_url="https://registry.example/fixture.tgz",
            integrity="sha512-fixture",
        )


def test_runtime_dependency_closure_builds_nested_node_modules_tree(tmp_path: Path):
    store = ArtifactStore(tmp_path / "store")
    root = _artifact(store, tmp_path, "root", "1.0.0", dependencies={"alpha": "^1.0.0"})
    alpha = _artifact(store, tmp_path, "alpha", "1.4.0", dependencies={"@scope/beta": "~2.0.0"})
    beta = _artifact(store, tmp_path, "@scope/beta", "2.0.3")
    broker = _Broker({"alpha": alpha, "@scope/beta": beta})

    closure = DependencyResolver(broker, store).resolve(root)

    assert [install.install_path for install in closure.installs] == [
        "node_modules/alpha",
        "node_modules/alpha/node_modules/@scope/beta",
    ]
    assert [install.artifact.sha256 for install in closure.installs] == [alpha.sha256, beta.sha256]
    assert closure.unresolved == []
    assert broker.requests == [("alpha", "^1.0.0"), ("@scope/beta", "~2.0.0")]


def test_dependency_closure_preserves_unsupported_runtime_requirements(tmp_path: Path):
    store = ArtifactStore(tmp_path / "store")
    root = _artifact(
        store,
        tmp_path,
        "root",
        "1.0.0",
        dependencies={"local-only": "file:../local"},
        peerDependencies={"react": "^18"},
    )

    closure = DependencyResolver(_Broker({}), store).resolve(root)

    assert closure.installs == []
    assert any("unsupported dependencies source" in item for item in closure.unresolved)
    assert any("peer dependency requires host policy" in item for item in closure.unresolved)
