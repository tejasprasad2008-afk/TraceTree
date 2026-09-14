"""Immutable, safe npm tarball storage.

The adaptive pipeline must correlate its static evidence and every dynamic
attempt to the same bytes.  This module accepts a tarball from the separate
registry broker; it does not execute npm or package code itself.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Set

from .models import NpmArtifact


class UnsafeArtifactError(ValueError):
    """Raised when an untrusted package archive violates storage policy."""


class ArtifactStore:
    """Content-addressed npm tarball store with defensive extraction.

    Archives may contain only regular files and directories under npm's normal
    ``package/`` prefix.  Symlinks and special files are rejected in this MVP
    rather than being followed or interpreted on the host.
    """

    METADATA_FILENAME = "artifact.json"
    TARBALL_FILENAME = "package.tgz"
    PACKAGE_DIRNAME = "package"

    def __init__(
        self,
        root: Path,
        max_tarball_bytes: int = 100 * 1024 * 1024,
        max_members: int = 20_000,
        max_unpacked_bytes: int = 250 * 1024 * 1024,
    ) -> None:
        self.root = Path(root).resolve()
        self.max_tarball_bytes = max_tarball_bytes
        self.max_members = max_members
        self.max_unpacked_bytes = max_unpacked_bytes
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)

    def ingest_tarball(self, tarball_path: Path, specifier: str) -> NpmArtifact:
        """Hash, safely extract, and persist an npm tarball exactly once."""

        source = Path(tarball_path).resolve()
        if not source.is_file():
            raise FileNotFoundError(f"npm tarball not found: {source}")
        if source.stat().st_size > self.max_tarball_bytes:
            raise UnsafeArtifactError(
                f"tarball exceeds {self.max_tarball_bytes} byte storage limit"
            )

        sha256 = self._sha256(source)
        artifact_dir = self.root / sha256
        if artifact_dir.is_dir():
            return self._load_existing(artifact_dir, specifier, sha256)

        temporary_dir = Path(
            tempfile.mkdtemp(prefix=f".{sha256[:12]}-", dir=str(self.root))
        )
        try:
            stored_tarball = temporary_dir / self.TARBALL_FILENAME
            shutil.copyfile(source, stored_tarball)
            stored_tarball.chmod(0o600)

            package_dir = temporary_dir / self.PACKAGE_DIRNAME
            self._extract_tarball(stored_tarball, package_dir)
            manifest = self._read_manifest(package_dir)
            metadata = {
                "schema": "tracetree.npm_artifact.v1",
                "specifier": specifier,
                "sha256": sha256,
                "byte_size": stored_tarball.stat().st_size,
                "manifest": manifest,
            }
            self._write_metadata(temporary_dir / self.METADATA_FILENAME, metadata)

            try:
                os.replace(temporary_dir, artifact_dir)
            except FileExistsError:
                # A concurrent analysis stored the same content first.  Its
                # content hash is the identity, so it is safe to reuse it.
                shutil.rmtree(temporary_dir)

            return self._load_existing(artifact_dir, specifier, sha256)
        except Exception:
            if temporary_dir.exists():
                shutil.rmtree(temporary_dir, ignore_errors=True)
            raise

    def _load_existing(
        self, artifact_dir: Path, fallback_specifier: str, expected_sha256: str
    ) -> NpmArtifact:
        metadata_path = artifact_dir / self.METADATA_FILENAME
        tarball_path = artifact_dir / self.TARBALL_FILENAME
        package_dir = artifact_dir / self.PACKAGE_DIRNAME
        if not metadata_path.is_file() or not tarball_path.is_file() or not package_dir.is_dir():
            raise UnsafeArtifactError(f"incomplete artifact store entry: {artifact_dir}")

        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise UnsafeArtifactError(f"invalid artifact metadata: {artifact_dir}") from exc

        if metadata.get("sha256") != expected_sha256:
            raise UnsafeArtifactError("artifact metadata hash does not match store path")
        if self._sha256(tarball_path) != expected_sha256:
            raise UnsafeArtifactError("stored tarball hash does not match artifact identity")

        manifest = metadata.get("manifest")
        if not isinstance(manifest, dict):
            raise UnsafeArtifactError("artifact metadata has no valid manifest")

        return NpmArtifact(
            specifier=str(metadata.get("specifier") or fallback_specifier),
            sha256=expected_sha256,
            tarball_path=tarball_path,
            package_dir=package_dir,
            manifest=manifest,
            byte_size=tarball_path.stat().st_size,
        )

    def _extract_tarball(self, tarball_path: Path, package_dir: Path) -> None:
        package_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        total_size = 0
        extracted_paths: Set[Path] = set()

        try:
            archive = tarfile.open(tarball_path, mode="r:*")
        except (tarfile.TarError, OSError) as exc:
            raise UnsafeArtifactError("tarball cannot be opened") from exc

        with archive:
            members = archive.getmembers()
            if len(members) > self.max_members:
                raise UnsafeArtifactError(
                    f"archive has more than {self.max_members} members"
                )

            for member in members:
                destination = self._member_destination(member.name, package_dir)
                if member.issym() or member.islnk() or member.ischr() or member.isblk() or member.isfifo():
                    raise UnsafeArtifactError(f"unsupported archive member: {member.name}")

                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                if not member.isfile():
                    raise UnsafeArtifactError(f"unsupported archive member: {member.name}")
                if destination in extracted_paths or destination.exists():
                    raise UnsafeArtifactError(f"duplicate archive member: {member.name}")

                total_size += member.size
                if total_size > self.max_unpacked_bytes:
                    raise UnsafeArtifactError(
                        f"archive exceeds {self.max_unpacked_bytes} byte unpacked limit"
                    )

                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                member_stream = archive.extractfile(member)
                if member_stream is None:
                    raise UnsafeArtifactError(f"cannot read archive member: {member.name}")
                with member_stream, open(destination, "xb") as output:
                    shutil.copyfileobj(member_stream, output)
                destination.chmod(0o600)
                extracted_paths.add(destination)

    @staticmethod
    def _member_destination(member_name: str, package_dir: Path) -> Path:
        member_path = PurePosixPath(member_name)
        if member_path.is_absolute() or not member_path.parts:
            raise UnsafeArtifactError(f"unsafe archive path: {member_name}")
        if any(part in ("", ".", "..") for part in member_path.parts):
            raise UnsafeArtifactError(f"unsafe archive path: {member_name}")
        if member_path.parts[0] != "package":
            raise UnsafeArtifactError(
                f"npm tarball member is outside package/ prefix: {member_name}"
            )

        relative_parts = member_path.parts[1:]
        if not relative_parts:
            return package_dir
        destination = package_dir.joinpath(*relative_parts).resolve()
        try:
            destination.relative_to(package_dir.resolve())
        except ValueError as exc:
            raise UnsafeArtifactError(f"unsafe archive path: {member_name}") from exc
        return destination

    @staticmethod
    def _read_manifest(package_dir: Path) -> Dict[str, Any]:
        manifest_path = package_dir / "package.json"
        if not manifest_path.is_file():
            raise UnsafeArtifactError("npm tarball does not contain package/package.json")
        if manifest_path.stat().st_size > 2 * 1024 * 1024:
            raise UnsafeArtifactError("package.json exceeds 2 MiB parsing limit")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UnsafeArtifactError("package.json is not valid UTF-8 JSON") from exc
        if not isinstance(manifest, dict):
            raise UnsafeArtifactError("package.json must contain a JSON object")
        return manifest

    @staticmethod
    def _write_metadata(path: Path, metadata: Dict[str, Any]) -> None:
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, path)

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
