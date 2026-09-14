from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from npm_adaptive.artifact_store import ArtifactStore
from npm_adaptive.registry import (
    NpmRegistryBroker,
    RegistryIntegrityError,
    RegistryResolutionError,
    parse_registry_specifier,
)


def _tarball() -> bytes:
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode="w:gz") as archive:
        for name, text in {
            "package/package.json": '{"name":"demo-pkg","version":"1.2.3"}',
            "package/index.js": "exports.ok = true;",
        }.items():
            encoded = text.encode("utf-8")
            member = tarfile.TarInfo(name)
            member.size = len(encoded)
            archive.addfile(member, io.BytesIO(encoded))
    return content.getvalue()


class _Response:
    def __init__(self, content: bytes) -> None:
        self.content = content
        self.closed = False

    def raise_for_status(self) -> None:
        return None

    def iter_content(self, chunk_size: int):
        for index in range(0, len(self.content), chunk_size):
            yield self.content[index : index + chunk_size]

    def close(self) -> None:
        self.closed = True


class _Session:
    def __init__(self, responses: list[_Response]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict]] = []

    def get(self, url: str, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


def _metadata(tarball: bytes, integrity: str | None = None) -> bytes:
    value = integrity or "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode()
    return json.dumps(
        {
            "dist-tags": {"latest": "1.2.3"},
            "versions": {
                "1.2.3": {
                    "dist": {
                        "tarball": "https://registry.example/demo-pkg/-/demo-pkg-1.2.3.tgz",
                        "integrity": value,
                    }
                }
            },
        }
    ).encode("utf-8")


def _metadata_with_versions(tarball: bytes) -> bytes:
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode()
    return json.dumps(
        {
            "dist-tags": {"latest": "2.1.0"},
            "versions": {
                version: {
                    "dist": {
                        "tarball": f"https://registry.example/demo-pkg/-/demo-pkg-{version}.tgz",
                        "integrity": integrity,
                    }
                }
                for version in ["1.2.0", "1.9.3", "2.0.0", "2.1.0", "3.0.0-beta.1"]
            },
        }
    ).encode("utf-8")


def test_broker_resolves_exact_registry_artifact_and_verifies_integrity(tmp_path: Path):
    tarball = _tarball()
    session = _Session([_Response(_metadata(tarball)), _Response(tarball)])
    broker = NpmRegistryBroker(session=session, registry_base="https://registry.example")

    artifact, release = broker.fetch_to_store("demo-pkg", ArtifactStore(tmp_path / "store"))

    assert release.version == "1.2.3"
    assert artifact.package_name == "demo-pkg"
    assert artifact.version == "1.2.3"
    assert session.calls[0][0] == "https://registry.example/demo-pkg"
    assert all(call[1]["allow_redirects"] is False for call in session.calls)


def test_broker_rejects_tarball_with_bad_registry_integrity(tmp_path: Path):
    tarball = _tarball()
    session = _Session([_Response(_metadata(tarball, "sha512-" + base64.b64encode(b"wrong").decode())), _Response(tarball)])
    broker = NpmRegistryBroker(session=session, registry_base="https://registry.example")

    with pytest.raises(RegistryIntegrityError, match="does not match"):
        broker.fetch_to_store("demo-pkg@1.2.3", ArtifactStore(tmp_path / "store"))


@pytest.mark.parametrize(
    "specifier, expected",
    [
        ("demo-pkg", ("demo-pkg", None)),
        ("demo-pkg@1.2.3", ("demo-pkg", "1.2.3")),
        ("@scope/demo@next", ("@scope/demo", "next")),
    ],
)
def test_parse_registry_specifier(specifier: str, expected: tuple[str, str | None]):
    assert parse_registry_specifier(specifier) == expected


@pytest.mark.parametrize("selector, expected", [("^1.2.0", "1.9.3"), ("~2.0.0", "2.0.0"), ("2.x", "2.1.0"), (">=1.0.0 <2.0.0", "1.9.3")])
def test_broker_resolves_common_semver_ranges(selector: str, expected: str):
    session = _Session([_Response(_metadata_with_versions(_tarball()))])
    release = NpmRegistryBroker(session=session, registry_base="https://registry.example").resolve(
        f"demo-pkg@{selector}"
    )

    assert release.version == expected


@pytest.mark.parametrize("specifier", ["git+https://example.test/repo.git", "../local-package"])
def test_broker_rejects_non_registry_specifiers(specifier: str):
    with pytest.raises(RegistryResolutionError, match="registry npm package names"):
        parse_registry_specifier(specifier)
