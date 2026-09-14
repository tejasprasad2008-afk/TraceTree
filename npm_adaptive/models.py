"""Typed contracts shared by the adaptive npm analysis stages.

The contracts deliberately describe facts and uncertainty.  A missing or
unsupported path must never be silently treated as benign.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional


@dataclass(frozen=True)
class NpmArtifact:
    """An immutable, safely extracted npm package tarball."""

    specifier: str
    sha256: str
    tarball_path: Path
    package_dir: Path
    manifest: Mapping[str, Any]
    byte_size: int

    @property
    def package_name(self) -> str:
        name = self.manifest.get("name")
        return name if isinstance(name, str) and name else self.specifier

    @property
    def version(self) -> str:
        version = self.manifest.get("version")
        return version if isinstance(version, str) and version else "unknown"


@dataclass(frozen=True)
class PackageEntrypoint:
    """One public package entrypoint and its static resolution results."""

    specifier: str
    source: str
    import_path: Optional[str] = None
    require_path: Optional[str] = None
    types_path: Optional[str] = None
    conditions: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class PackageExport:
    """A best-effort statically discovered export.

    ``confidence`` reflects static certainty only.  Runtime probes in a fresh
    sandbox are the source of truth for dynamic CommonJS exports and getters.
    """

    entrypoint: str
    name: str
    kind: str
    source_path: Optional[str]
    confidence: str
    parameters: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class PackageMap:
    """Static description of an npm artifact before any package code runs."""

    artifact_sha256: str
    package_name: str
    package_version: str
    module_type: str
    entrypoints: List[PackageEntrypoint]
    exports: List[PackageExport]
    static_findings: List[Dict[str, Any]]
    unsupported_paths: List[str]

    def as_dict(self) -> Dict[str, Any]:
        """Return a stable, JSON-serialisable representation for receipts."""

        return {
            "artifact_sha256": self.artifact_sha256,
            "package": {
                "name": self.package_name,
                "version": self.package_version,
                "type": self.module_type,
            },
            "entrypoints": [
                {
                    "specifier": entry.specifier,
                    "source": entry.source,
                    "import_path": entry.import_path,
                    "require_path": entry.require_path,
                    "types_path": entry.types_path,
                    "conditions": list(entry.conditions),
                }
                for entry in self.entrypoints
            ],
            "exports": [
                {
                    "entrypoint": export.entrypoint,
                    "name": export.name,
                    "kind": export.kind,
                    "source_path": export.source_path,
                    "confidence": export.confidence,
                    "parameters": list(export.parameters),
                }
                for export in self.exports
            ],
            "static_findings": list(self.static_findings),
            "unsupported_paths": list(self.unsupported_paths),
        }


@dataclass(frozen=True)
class EnvironmentProfile:
    """A versioned, allowlisted synthetic execution environment."""

    profile_id: str
    version: str
    description: str
    fixture_ids: List[str]
    network_policy: str
    allowed_services: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class HarnessAction:
    """One validated callable-export invocation."""

    entrypoint: str
    loader: str
    export_name: str
    fixture_ids: List[str]
    timeout_ms: int


@dataclass(frozen=True)
class HarnessPlan:
    """Validated declarative plan rendered into trusted harness source."""

    schema_version: str
    profile_id: str
    actions: List[HarnessAction]
    attempt_budget: int


@dataclass(frozen=True)
class CoverageReport:
    """Normalised native V8 coverage compared with a static package map."""

    target_files: List[str]
    executed_files: List[str]
    executed_function_names: List[str]
    exercised_exports: List[str]
    uncovered_exports: List[str]
    parse_errors: List[str] = field(default_factory=list)

    @property
    def file_ratio(self) -> float:
        if not self.target_files:
            return 0.0
        return len(self.executed_files) / len(self.target_files)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "target_files": list(self.target_files),
            "executed_files": list(self.executed_files),
            "executed_function_names": list(self.executed_function_names),
            "exercised_exports": list(self.exercised_exports),
            "uncovered_exports": list(self.uncovered_exports),
            "file_ratio": round(self.file_ratio, 4),
            "parse_errors": list(self.parse_errors),
        }


@dataclass
class PreparedEnvironment:
    """Per-run synthetic profile materialisation.

    ``secret_values`` exist only while the runner is active so it can redact
    output.  They must never be persisted in receipts, plans, or history.
    """

    profile_id: str
    profile_version: str
    root: Path
    container_environment: Dict[str, str]
    fixture_labels: List[str]
    secret_values: Dict[str, str] = field(repr=False)

    def redact(self, text: str) -> str:
        redacted = text
        for label, value in self.secret_values.items():
            redacted = redacted.replace(value, f"[REDACTED:{label}]")
        return redacted


@dataclass(frozen=True)
class HarnessRun:
    """Artifacts produced by a single fresh adaptive sandbox attempt."""

    attempt_id: str
    profile_id: str
    outcome: str
    output_dir: Path
    trace_path: Optional[Path]
    coverage_dir: Optional[Path]
    stdout_path: Path
    stderr_path: Path
    timed_out: bool


@dataclass(frozen=True)
class DependencyInstall:
    """One immutable runtime dependency placed at a Node resolution path."""

    artifact: NpmArtifact
    install_path: str
    requested_by: str
    requested_range: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.artifact.package_name,
            "version": self.artifact.version,
            "artifact_sha256": self.artifact.sha256,
            "install_path": self.install_path,
            "requested_by": self.requested_by,
            "requested_range": self.requested_range,
        }


@dataclass(frozen=True)
class DependencyClosure:
    """Bounded runtime dependency tree for one root npm artifact."""

    root_artifact_sha256: str
    installs: List[DependencyInstall]
    unresolved: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "root_artifact_sha256": self.root_artifact_sha256,
            "installs": [install.as_dict() for install in self.installs],
            "unresolved": list(self.unresolved),
        }
