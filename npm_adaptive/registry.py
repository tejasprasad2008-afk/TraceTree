"""Registry-only npm artifact broker.

The broker resolves a package name to one exact registry version, verifies the
registry's Subresource Integrity value while streaming the tarball, and hands
the bytes to :class:`ArtifactStore`.  It never invokes npm, Node, or package
scripts on the host.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from functools import cmp_to_key
from pathlib import Path
from typing import Any, Optional, Tuple
from urllib.parse import quote, urlparse

from .artifact_store import ArtifactStore
from .models import NpmArtifact


class RegistryResolutionError(ValueError):
    """Raised when a specifier cannot be resolved to one registry release."""


class RegistryIntegrityError(ValueError):
    """Raised when registry tarball bytes do not match their SRI metadata."""


@dataclass(frozen=True)
class ResolvedNpmRelease:
    """One exact release resolved before any untrusted bytes are unpacked."""

    requested_specifier: str
    package_name: str
    version: str
    tarball_url: str
    integrity: str


_PACKAGE_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")
_SRI = re.compile(r"^(sha512)-([A-Za-z0-9+/]+={0,2})$")
_SEMVER = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$"
)


@dataclass(frozen=True)
class _SemVer:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()


class NpmRegistryBroker:
    """Fetch exact npm registry artifacts with bounded, verified downloads."""

    def __init__(
        self,
        session: Any = None,
        registry_base: str = "https://registry.npmjs.org",
        timeout_seconds: float = 20,
        max_metadata_bytes: int = 5 * 1024 * 1024,
        max_tarball_bytes: int = 100 * 1024 * 1024,
    ) -> None:
        parsed = urlparse(registry_base)
        if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment:
            raise ValueError("registry_base must be an HTTPS origin without a query or fragment")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.session = session
        self.registry_base = registry_base.rstrip("/")
        self.registry_host = parsed.hostname
        self.timeout_seconds = timeout_seconds
        self.max_metadata_bytes = max_metadata_bytes
        self.max_tarball_bytes = max_tarball_bytes

    def resolve(self, specifier: str) -> ResolvedNpmRelease:
        """Resolve a name plus optional exact version/tag to registry metadata."""

        package_name, selector = parse_registry_specifier(specifier)
        metadata_url = f"{self.registry_base}/{quote(package_name, safe='@')}"
        response = self._get(metadata_url, accept="application/vnd.npm.install-v1+json")
        try:
            payload = _read_limited(response, self.max_metadata_bytes)
        finally:
            _close_response(response)
        try:
            metadata = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RegistryResolutionError("npm registry metadata is not valid UTF-8 JSON") from exc
        if not isinstance(metadata, dict):
            raise RegistryResolutionError("npm registry metadata must be an object")

        version, release = _select_release(metadata, selector)
        dist = release.get("dist") if isinstance(release, dict) else None
        if not isinstance(dist, dict):
            raise RegistryResolutionError(f"npm release {version} has no dist metadata")
        tarball_url = dist.get("tarball")
        integrity = dist.get("integrity")
        if not isinstance(tarball_url, str) or not _is_registry_tarball(tarball_url, self.registry_host):
            raise RegistryResolutionError("npm release tarball is not an HTTPS URL on the configured registry")
        if not isinstance(integrity, str) or not _SRI.fullmatch(integrity):
            raise RegistryResolutionError("npm release is missing a valid sha512 integrity value")

        return ResolvedNpmRelease(
            requested_specifier=specifier,
            package_name=package_name,
            version=version,
            tarball_url=tarball_url,
            integrity=integrity,
        )

    def fetch_to_store(self, specifier: str, store: ArtifactStore) -> Tuple[NpmArtifact, ResolvedNpmRelease]:
        """Resolve, integrity-check, and content-address one npm release."""

        release = self.resolve(specifier)
        response = self._get(release.tarball_url, accept="application/octet-stream")
        temporary_path: Optional[Path] = None
        try:
            descriptor, raw_path = tempfile.mkstemp(
                prefix=".registry-", suffix=".tgz", dir=str(store.root)
            )
            temporary_path = Path(raw_path)
            digest, total = _stream_to_file(response, descriptor, self.max_tarball_bytes)
            _verify_integrity(release.integrity, digest)
            if total == 0:
                raise RegistryIntegrityError("npm registry returned an empty tarball")
            artifact = store.ingest_tarball(temporary_path, f"{release.package_name}@{release.version}")
            return artifact, release
        finally:
            _close_response(response)
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass

    def _get(self, url: str, *, accept: str) -> Any:
        session = self.session
        if session is None:
            try:
                import requests
            except ImportError as exc:  # pragma: no cover - project dependency
                raise RegistryResolutionError("requests is not installed") from exc
            session = requests.Session()
        try:
            response = session.get(
                url,
                headers={"Accept": accept, "User-Agent": "TraceTree-Adaptive/1"},
                stream=True,
                timeout=self.timeout_seconds,
                allow_redirects=False,
            )
            try:
                response.raise_for_status()
            except Exception:
                _close_response(response)
                raise
            return response
        except Exception as exc:
            raise RegistryResolutionError(f"npm registry request failed: {exc}") from exc


def parse_registry_specifier(specifier: str) -> Tuple[str, Optional[str]]:
    """Parse a registry package name plus a bounded version/tag/range selector."""

    if not isinstance(specifier, str) or not specifier or len(specifier) > 214:
        raise RegistryResolutionError("npm package specifier must be a non-empty package name")
    if specifier.startswith("@"):
        slash = specifier.find("/")
        separator = specifier.find("@", slash + 1) if slash >= 0 else -1
    else:
        separator = specifier.find("@")
    name = specifier if separator < 0 else specifier[:separator]
    selector = None if separator < 0 else specifier[separator + 1 :]
    if not _PACKAGE_NAME.fullmatch(name):
        raise RegistryResolutionError("only registry npm package names are supported")
    if selector is not None and (
        not selector
        or len(selector) > 128
        or any(ord(char) < 32 for char in selector)
    ):
        raise RegistryResolutionError("npm version selector is invalid")
    return name, selector


def _select_release(metadata: dict[str, Any], selector: Optional[str]) -> Tuple[str, dict[str, Any]]:
    versions = metadata.get("versions")
    tags = metadata.get("dist-tags")
    if not isinstance(versions, dict):
        raise RegistryResolutionError("npm registry metadata has no versions map")
    if selector is None:
        selector = tags.get("latest") if isinstance(tags, dict) else None
    if isinstance(tags, dict) and selector in tags:
        selector = tags[selector]
    if not isinstance(selector, str):
        raise RegistryResolutionError("npm selector did not resolve to a version")
    if selector not in versions:
        selector = _select_highest_satisfying_version(versions, selector)
    release = versions[selector]
    if not isinstance(release, dict):
        raise RegistryResolutionError(f"npm version metadata is invalid: {selector}")
    return selector, release


def _select_highest_satisfying_version(versions: dict[str, Any], selector: str) -> str:
    """Resolve common runtime npm semver ranges without executing npm."""

    candidates = []
    for raw_version in versions:
        version = _parse_semver(raw_version)
        if version is not None and _semver_satisfies(version, selector):
            candidates.append((raw_version, version))
    if not candidates:
        raise RegistryResolutionError(
            f"npm selector does not match a supported published version: {selector}"
        )
    candidates.sort(key=cmp_to_key(lambda left, right: _compare_semver(left[1], right[1])))
    return candidates[-1][0]


def _semver_satisfies(version: _SemVer, selector: str) -> bool:
    selector = selector.strip()
    if not selector or selector in {"*", "latest"}:
        return not version.prerelease
    if version.prerelease and "-" not in selector:
        return False
    return any(_semver_clause_satisfies(version, clause.strip()) for clause in selector.split("||"))


def _semver_clause_satisfies(version: _SemVer, clause: str) -> bool:
    if not clause or clause in {"*", "x", "X"}:
        return True
    hyphen = re.fullmatch(r"\s*(\S+)\s+-\s+(\S+)\s*", clause)
    if hyphen:
        lower = _parse_partial_semver(hyphen.group(1))
        upper = _parse_partial_semver(hyphen.group(2))
        return lower is not None and upper is not None and _compare_semver(version, lower[0]) >= 0 and _compare_semver(version, upper[0]) <= 0
    tokens = clause.replace(",", " ").split()
    return bool(tokens) and all(_semver_token_satisfies(version, token) for token in tokens)


def _semver_token_satisfies(version: _SemVer, token: str) -> bool:
    token = token.strip()
    if token in {"", "*", "x", "X"}:
        return True
    if token.startswith("^"):
        partial = _parse_partial_semver(token[1:])
        if partial is None:
            return False
        base, components = partial
        if base.major > 0:
            upper = _SemVer(base.major + 1, 0, 0)
        elif components <= 1:
            upper = _SemVer(1, 0, 0)
        elif base.minor > 0:
            upper = _SemVer(0, base.minor + 1, 0)
        elif components <= 2:
            upper = _SemVer(0, 1, 0)
        else:
            upper = _SemVer(0, 0, base.patch + 1)
        return _compare_semver(version, base) >= 0 and _compare_semver(version, upper) < 0
    if token.startswith("~"):
        partial = _parse_partial_semver(token[1:])
        if partial is None:
            return False
        base, components = partial
        upper = _SemVer(base.major + 1, 0, 0) if components <= 1 else _SemVer(base.major, base.minor + 1, 0)
        return _compare_semver(version, base) >= 0 and _compare_semver(version, upper) < 0

    comparator = re.fullmatch(r"(<=|>=|<|>|=)?(.+)", token)
    if comparator is None:
        return False
    operator, raw_value = comparator.groups()
    partial = _parse_partial_semver(raw_value)
    if partial is None:
        return False
    base, components = partial
    if operator in {">", ">=", "<", "<="}:
        comparison = _compare_semver(version, base)
        return {
            ">": comparison > 0,
            ">=": comparison >= 0,
            "<": comparison < 0,
            "<=": comparison <= 0,
        }[operator]
    if components == 1:
        return version.major == base.major
    if components == 2:
        return version.major == base.major and version.minor == base.minor
    return _compare_semver(version, base) == 0


def _parse_partial_semver(value: str) -> Optional[Tuple[_SemVer, int]]:
    value = value.strip()
    if not value:
        return None
    raw_parts = value.lstrip("v").split(".")
    if len(raw_parts) > 3:
        return None
    components = 0
    numeric = []
    for part in raw_parts:
        if part.lower() in {"x", "*"}:
            numeric.append(0)
            break
        match = re.fullmatch(r"(\d+)(?:-([0-9A-Za-z.-]+))?", part)
        if match is None:
            return None
        numeric.append(int(match.group(1)))
        components += 1
        if match.group(2):
            while len(numeric) < 3:
                numeric.append(0)
            return _SemVer(*numeric[:3], tuple(match.group(2).split("."))), components
    while len(numeric) < 3:
        numeric.append(0)
    return _SemVer(*numeric[:3]), components


def _parse_semver(value: str) -> Optional[_SemVer]:
    match = _SEMVER.fullmatch(value)
    if match is None:
        return None
    major, minor, patch, prerelease = match.groups()
    return _SemVer(
        int(major),
        int(minor or 0),
        int(patch or 0),
        tuple(prerelease.split(".")) if prerelease else (),
    )


def _compare_semver(left: _SemVer, right: _SemVer) -> int:
    numeric = (left.major, left.minor, left.patch)
    other = (right.major, right.minor, right.patch)
    if numeric != other:
        return -1 if numeric < other else 1
    if not left.prerelease or not right.prerelease:
        if left.prerelease == right.prerelease:
            return 0
        return -1 if left.prerelease else 1
    for left_part, right_part in zip(left.prerelease, right.prerelease):
        if left_part == right_part:
            continue
        left_numeric = left_part.isdigit()
        right_numeric = right_part.isdigit()
        if left_numeric and right_numeric:
            return -1 if int(left_part) < int(right_part) else 1
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return -1 if left_part < right_part else 1
    if len(left.prerelease) == len(right.prerelease):
        return 0
    return -1 if len(left.prerelease) < len(right.prerelease) else 1


def _is_registry_tarball(url: str, registry_host: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" and parsed.hostname == registry_host and not parsed.username and not parsed.password


def _read_limited(response: Any, limit: int) -> bytes:
    chunks = []
    total = 0
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        total += len(chunk)
        if total > limit:
            raise RegistryResolutionError(f"npm registry response exceeds {limit} byte limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _stream_to_file(response: Any, descriptor: int, limit: int) -> Tuple[bytes, int]:
    digest = hashlib.sha512()
    total = 0
    try:
        with os.fdopen(descriptor, "wb") as output:
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                total += len(chunk)
                if total > limit:
                    raise RegistryIntegrityError(f"npm tarball exceeds {limit} byte limit")
                digest.update(chunk)
                output.write(chunk)
    except Exception:
        # ``fdopen`` owns the descriptor after the ``with`` begins.  If it
        # failed before that point, close defensively without masking failure.
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    return digest.digest(), total


def _verify_integrity(integrity: str, sha512_digest: bytes) -> None:
    match = _SRI.fullmatch(integrity)
    if match is None:  # guarded by resolve(), defensive for direct callers
        raise RegistryIntegrityError("unsupported registry integrity value")
    algorithm, encoded_digest = match.groups()
    try:
        expected = base64.b64decode(encoded_digest, validate=True)
    except ValueError as exc:
        raise RegistryIntegrityError("registry integrity digest is invalid base64") from exc
    if expected != sha512_digest:
        raise RegistryIntegrityError("downloaded tarball does not match npm registry integrity")


def _close_response(response: Any) -> None:
    close = getattr(response, "close", None)
    if callable(close):
        close()
