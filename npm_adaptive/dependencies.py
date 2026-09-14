"""Bounded, no-lifecycle npm runtime dependency closure resolution."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Dict, List, Set, Tuple

from .artifact_store import ArtifactStore
from .models import DependencyClosure, DependencyInstall, NpmArtifact
from .registry import NpmRegistryBroker, RegistryResolutionError, parse_registry_specifier


class DependencyResolver:
    """Resolve runtime dependencies into explicit Node ``node_modules`` paths.

    The resolver downloads tarballs through ``NpmRegistryBroker`` and extracts
    them through ``ArtifactStore`` only.  It never invokes npm and therefore
    never runs lifecycle scripts.  The initial policy intentionally excludes
    dev, peer, git, file, workspace, and alias dependencies.
    """

    def __init__(
        self,
        broker: NpmRegistryBroker,
        store: ArtifactStore,
        max_depth: int = 5,
        max_packages: int = 100,
    ) -> None:
        if max_depth < 0 or max_packages < 1:
            raise ValueError("dependency limits must be non-negative depth and positive package count")
        self.broker = broker
        self.store = store
        self.max_depth = max_depth
        self.max_packages = max_packages
        self._cache: Dict[Tuple[str, str], NpmArtifact] = {}

    def resolve(self, root: NpmArtifact) -> DependencyClosure:
        installs: List[DependencyInstall] = []
        unresolved: List[str] = []
        self._resolve_children(
            parent=root,
            parent_install_path="",
            depth=0,
            ancestry={root.package_name},
            installs=installs,
            unresolved=unresolved,
        )
        return DependencyClosure(
            root_artifact_sha256=root.sha256,
            installs=installs,
            unresolved=sorted(set(unresolved)),
        )

    def _resolve_children(
        self,
        *,
        parent: NpmArtifact,
        parent_install_path: str,
        depth: int,
        ancestry: Set[str],
        installs: List[DependencyInstall],
        unresolved: List[str],
    ) -> None:
        dependencies = _runtime_dependencies(parent.manifest, parent.package_name, unresolved)
        if not dependencies:
            return
        if depth >= self.max_depth:
            unresolved.extend(
                f"dependency depth limit ({self.max_depth}) reached below {parent.package_name}: {name}"
                for name in sorted(dependencies)
            )
            return

        for name, requested_range in sorted(dependencies.items()):
            if len(installs) >= self.max_packages:
                unresolved.append(f"dependency package limit ({self.max_packages}) reached at {name}")
                continue
            if name in ancestry:
                # Node will resolve the nearest already-installed ancestor;
                # avoid making a mutable/infinite nested copy.
                continue
            install_path = _install_path(parent_install_path, name)
            if _bundled_dependency_exists(parent, name):
                continue
            try:
                artifact = self._fetch(name, requested_range)
            except (RegistryResolutionError, ValueError, OSError) as exc:
                unresolved.append(
                    f"runtime dependency unresolved: {parent.package_name} -> {name}@{requested_range}: {exc}"
                )
                continue
            if artifact.package_name != name:
                unresolved.append(
                    f"runtime dependency name mismatch: requested {name}, tarball declares {artifact.package_name}"
                )
                continue
            installs.append(
                DependencyInstall(
                    artifact=artifact,
                    install_path=install_path,
                    requested_by=parent.package_name,
                    requested_range=requested_range,
                )
            )
            self._resolve_children(
                parent=artifact,
                parent_install_path=install_path,
                depth=depth + 1,
                ancestry=ancestry | {name},
                installs=installs,
                unresolved=unresolved,
            )

    def _fetch(self, name: str, requested_range: str) -> NpmArtifact:
        cache_key = (name, requested_range)
        if cache_key not in self._cache:
            # Validates the package name and uses the registry broker's bounded
            # semver resolver; no shell or npm command is involved.
            parse_registry_specifier(f"{name}@{requested_range}")
            artifact, _release = self.broker.fetch_to_store(
                f"{name}@{requested_range}", self.store
            )
            self._cache[cache_key] = artifact
        return self._cache[cache_key]


def _runtime_dependencies(
    manifest: object, parent_name: str, unresolved: List[str]
) -> Dict[str, str]:
    if not isinstance(manifest, dict):
        return {}
    merged: Dict[str, str] = {}
    for field in ("dependencies", "optionalDependencies"):
        values = manifest.get(field)
        if values is None:
            continue
        if not isinstance(values, dict):
            unresolved.append(f"{parent_name} has invalid {field} metadata")
            continue
        for name, requested_range in values.items():
            if not isinstance(name, str) or not isinstance(requested_range, str):
                unresolved.append(f"{parent_name} has invalid {field} entry")
                continue
            if requested_range.startswith(("file:", "git+", "git@", "http:", "https:", "workspace:", "npm:")):
                unresolved.append(
                    f"unsupported {field} source: {parent_name} -> {name}@{requested_range}"
                )
                continue
            merged[name] = requested_range
    peer = manifest.get("peerDependencies")
    if isinstance(peer, dict) and peer:
        unresolved.extend(
            f"peer dependency requires host policy: {parent_name} -> {name}@{value}"
            for name, value in sorted(peer.items())
            if isinstance(name, str) and isinstance(value, str)
        )
    return merged


def _install_path(parent_install_path: str, package_name: str) -> str:
    parent = PurePosixPath(parent_install_path) if parent_install_path else PurePosixPath()
    path = parent / "node_modules" / PurePosixPath(package_name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"unsafe dependency install path: {package_name}")
    return path.as_posix()


def _bundled_dependency_exists(parent: NpmArtifact, package_name: str) -> bool:
    candidate = parent.package_dir / "node_modules" / Path(package_name)
    return candidate.is_dir() and not candidate.is_symlink()
