from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from npm_adaptive.artifact_store import ArtifactStore, UnsafeArtifactError


def _write_tgz(path: Path, entries: dict[str, str]) -> Path:
    with tarfile.open(path, "w:gz") as archive:
        for name, content in entries.items():
            encoded = content.encode("utf-8")
            member = tarfile.TarInfo(name)
            member.size = len(encoded)
            archive.addfile(member, io.BytesIO(encoded))
    return path


def test_ingest_tarball_is_content_addressed_and_preserves_manifest(tmp_path: Path):
    tarball = _write_tgz(
        tmp_path / "demo.tgz",
        {
            "package/package.json": '{"name":"demo-pkg","version":"1.2.3"}',
            "package/index.js": "module.exports = () => 'ok';",
        },
    )
    store = ArtifactStore(tmp_path / "artifacts")

    first = store.ingest_tarball(tarball, "demo-pkg@1.2.3")
    second = store.ingest_tarball(tarball, "a-different-specifier")

    assert first.sha256 == second.sha256
    assert first.package_dir == second.package_dir
    assert first.manifest["name"] == "demo-pkg"
    assert (first.package_dir / "index.js").read_text() == "module.exports = () => 'ok';"
    assert first.tarball_path.parent.name == first.sha256


def test_ingest_tarball_rejects_path_traversal(tmp_path: Path):
    tarball = _write_tgz(
        tmp_path / "traversal.tgz",
        {
            "package/package.json": "{}",
            "package/../outside.txt": "nope",
        },
    )

    with pytest.raises(UnsafeArtifactError, match="unsafe archive path"):
        ArtifactStore(tmp_path / "artifacts").ingest_tarball(tarball, "bad")


def test_ingest_tarball_rejects_symlinks(tmp_path: Path):
    tarball = tmp_path / "symlink.tgz"
    with tarfile.open(tarball, "w:gz") as archive:
        manifest = b'{}'
        package_json = tarfile.TarInfo("package/package.json")
        package_json.size = len(manifest)
        archive.addfile(package_json, io.BytesIO(manifest))

        link = tarfile.TarInfo("package/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        archive.addfile(link)

    with pytest.raises(UnsafeArtifactError, match="unsupported archive member"):
        ArtifactStore(tmp_path / "artifacts").ingest_tarball(tarball, "bad-link")
