from __future__ import annotations

import io
import tarfile
from pathlib import Path

from npm_adaptive.artifact_store import ArtifactStore
from npm_adaptive.static_mapper import build_package_map


def _artifact(tmp_path: Path):
    tarball = tmp_path / "package.tgz"
    entries = {
        "package/package.json": """{
          \"name\": \"mapped-pkg\",
          \"version\": \"1.0.0\",
          \"type\": \"module\",
          \"types\": \"./dist/index.d.ts\",
          \"exports\": {
            \".\": {\"import\": \"./dist/index.mjs\", \"require\": \"./dist/index.cjs\"},
            \"./feature\": \"./dist/feature.js\"
          }
        }""",
        "package/dist/index.mjs": "export async function greet(name) { return name; }\nexport default function () {}\n",
        "package/dist/index.cjs": "exports.legacy = () => true;\n",
        "package/dist/index.d.ts": "export function greet(name: string): Promise<string>;\n",
        "package/dist/feature.js": "export const enabled = true;\n",
    }
    with tarfile.open(tarball, "w:gz") as archive:
        for name, content in entries.items():
            data = content.encode("utf-8")
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return ArtifactStore(tmp_path / "artifacts").ingest_tarball(tarball, "mapped-pkg@1.0.0")


def test_static_mapper_discovers_conditional_and_subpath_exports(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("npm_adaptive.static_mapper._scan_static_tree", lambda _: [])
    package_map = build_package_map(_artifact(tmp_path))

    assert {entry.specifier for entry in package_map.entrypoints} == {
        "mapped-pkg",
        "mapped-pkg/feature",
    }
    assert {export.name for export in package_map.exports} >= {"greet", "default", "legacy", "enabled"}
    greet = next(export for export in package_map.exports if export.name == "greet")
    assert greet.kind == "function"
    assert greet.parameters == ["name"]
    assert not package_map.unsupported_paths


def test_static_mapper_marks_native_addons_as_uncovered(tmp_path: Path, monkeypatch):
    artifact = _artifact(tmp_path)
    (artifact.package_dir / "native.node").write_bytes(b"not a real addon")
    monkeypatch.setattr("npm_adaptive.static_mapper._scan_static_tree", lambda _: [])

    package_map = build_package_map(artifact)

    assert "native addon present; JavaScript coverage is incomplete" in package_map.unsupported_paths


def test_static_mapper_surfaces_static_findings(tmp_path: Path, monkeypatch):
    artifact = _artifact(tmp_path)
    expected = [{"rule_name": "demo-rule", "severity": "high"}]
    monkeypatch.setattr("npm_adaptive.static_mapper._scan_static_tree", lambda _: expected)

    package_map = build_package_map(artifact)

    assert package_map.static_findings == expected
