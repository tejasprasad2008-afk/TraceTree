"""High-level orchestration for the safe adaptive npm vertical slice."""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .artifact_store import ArtifactStore
from .coverage import merge_coverage_reports, summarize_v8_coverage
from .dependencies import DependencyResolver
from .environment import prepare_environment
from .harness_policy import (
    HarnessGateDecision,
    build_deterministic_plan,
    build_planner_context,
    evaluate_harness_gate,
)
from .models import (
    CoverageReport,
    DependencyClosure,
    HarnessPlan,
    HarnessRun,
    NpmArtifact,
    PackageMap,
)
from .planner import HarnessPlannerClient, request_validated_plan
from .probe_results import load_import_probe_results
from .registry import NpmRegistryBroker, ResolvedNpmRelease
from .sandbox_runner import AdaptiveSandboxRunner
from .static_mapper import build_package_map
from .trace_analysis import TraceEvidence, analyze_trace


@dataclass(frozen=True)
class AdaptiveAttempt:
    """Evidence from one fresh import or harness container."""

    kind: str
    run: HarnessRun
    coverage: CoverageReport
    trace_evidence: TraceEvidence
    probe_results: List[Dict[str, Any]]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "attempt_id": self.run.attempt_id,
            "profile_id": self.run.profile_id,
            "outcome": self.run.outcome,
            "timed_out": self.run.timed_out,
            "coverage": self.coverage.as_dict(),
            "probe_results": list(self.probe_results),
            "trace_evidence": self.trace_evidence.as_dict(),
        }


@dataclass(frozen=True)
class AdaptiveNpmResult:
    """Artifact-correlated adaptive result without a blanket safe verdict."""

    artifact: NpmArtifact
    package_map: PackageMap
    import_attempt: AdaptiveAttempt
    registry_release: Optional[ResolvedNpmRelease] = None
    dependency_closure: Optional[DependencyClosure] = None
    harness_gate: Optional[HarnessGateDecision] = None
    deterministic_harness_plan: Optional[HarnessPlan] = None

    @property
    def unresolved_paths(self) -> List[str]:
        coverage = self.import_attempt.coverage
        return sorted(
            set(self.package_map.unsupported_paths)
            | set(f"uncovered export: {value}" for value in coverage.uncovered_exports)
            | set(self.import_attempt.trace_evidence.warnings)
            | set(self.dependency_closure.unresolved if self.dependency_closure else [])
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "artifact": {
                "sha256": self.artifact.sha256,
                "package_name": self.artifact.package_name,
                "version": self.artifact.version,
                "byte_size": self.artifact.byte_size,
            },
            "registry_release": (
                {
                    "requested_specifier": self.registry_release.requested_specifier,
                    "version": self.registry_release.version,
                    "tarball_url": self.registry_release.tarball_url,
                    "integrity": self.registry_release.integrity,
                }
                if self.registry_release
                else None
            ),
            "package_map": self.package_map.as_dict(),
            "dependency_closure": self.dependency_closure.as_dict() if self.dependency_closure else None,
            "import_attempt": self.import_attempt.as_dict(),
            "harness_gate": self.harness_gate.as_dict() if self.harness_gate else None,
            "harness_planner_context": (
                build_planner_context(self.package_map, self.harness_gate)
                if self.harness_gate
                else None
            ),
            "deterministic_harness_plan": _plan_as_dict(self.deterministic_harness_plan),
            "unresolved_paths": self.unresolved_paths,
            "verdict_note": "Observed behavior only; unexecuted and unsupported paths remain unresolved.",
        }


@dataclass(frozen=True)
class AdaptiveExecutionResult:
    """Resolved evidence after one explicitly authorized harness attempt.

    This is intentionally a coverage/evidence update, not a clean verdict.
    The package may still contain uncalled paths or use conditions no supplied
    synthetic environment represents.
    """

    analysis: AdaptiveNpmResult
    harness_plan: HarnessPlan
    harness_attempt: AdaptiveAttempt
    combined_coverage: CoverageReport

    @property
    def unresolved_paths(self) -> List[str]:
        warnings = {
            f"{attempt.kind} warning: {warning}"
            for attempt in (self.analysis.import_attempt, self.harness_attempt)
            for warning in attempt.trace_evidence.warnings
        }
        return sorted(
            set(self.analysis.package_map.unsupported_paths)
            | set(f"uncovered export: {value}" for value in self.combined_coverage.uncovered_exports)
            | warnings
            | set(
                self.analysis.dependency_closure.unresolved
                if self.analysis.dependency_closure
                else []
            )
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "harness_plan": _plan_as_dict(self.harness_plan),
            "harness_attempt": self.harness_attempt.as_dict(),
            "combined_coverage": self.combined_coverage.as_dict(),
            "unresolved_paths": self.unresolved_paths,
            "verdict_note": (
                "Combined observed behavior only; uncovered and unsupported paths remain unresolved."
            ),
        }


class AdaptiveNpmAnalyzer:
    """Coordinates immutable storage, mapping, import probing, and evidence."""

    def __init__(
        self,
        artifact_store: ArtifactStore,
        runner: AdaptiveSandboxRunner,
        workspace: Path,
        broker: Optional[NpmRegistryBroker] = None,
    ) -> None:
        self.artifact_store = artifact_store
        self.runner = runner
        self.broker = broker
        self.workspace = Path(workspace).resolve()
        self.workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.workspace.chmod(0o700)

    def analyze_specifier(
        self, specifier: str, profile_id: str = "node-library-v1"
    ) -> AdaptiveNpmResult:
        """Fetch one verified npm release before any package code can run."""

        if self.broker is None:
            raise ValueError("an npm registry broker is required to analyze a package specifier")
        artifact, release = self.broker.fetch_to_store(specifier, self.artifact_store)
        closure = DependencyResolver(self.broker, self.artifact_store).resolve(artifact)
        return self.analyze_artifact(
            artifact,
            profile_id=profile_id,
            registry_release=release,
            dependency_closure=closure,
        )

    def analyze_artifact(
        self,
        artifact: NpmArtifact,
        profile_id: str = "node-library-v1",
        registry_release: Optional[ResolvedNpmRelease] = None,
        dependency_closure: Optional[DependencyClosure] = None,
    ) -> AdaptiveNpmResult:
        """Statically map and import-probe one already verified artifact."""

        package_map = build_package_map(artifact)
        attempt = self._run_import_attempt(
            artifact, package_map, profile_id, dependency_closure
        )
        harness_gate = evaluate_harness_gate(
            package_map, attempt.coverage, attempt.trace_evidence
        )
        deterministic_harness_plan = build_deterministic_plan(package_map, harness_gate)
        return AdaptiveNpmResult(
            artifact=artifact,
            package_map=package_map,
            import_attempt=attempt,
            registry_release=registry_release,
            dependency_closure=dependency_closure,
            harness_gate=harness_gate,
            deterministic_harness_plan=deterministic_harness_plan,
        )

    def run_selected_harness(self, result: AdaptiveNpmResult) -> AdaptiveAttempt:
        """Run the gate-selected plan only when the caller explicitly opts in.

        Analysis itself never silently progresses from import probing into
        exported-function execution.  The resulting declarative plan remains
        visible for review and this method is the explicit execution boundary.
        """

        if result.deterministic_harness_plan is None:
            raise ValueError("no deterministic harness plan was authorized for this result")
        return self.run_harness_attempt(
            result.artifact,
            result.package_map,
            result.deterministic_harness_plan,
            result.dependency_closure,
        )

    def request_model_harness_plan(
        self, result: AdaptiveNpmResult, client: HarnessPlannerClient
    ) -> HarnessPlan:
        """Ask an injected model adapter for a constrained, validated plan.

        This method only returns a plan.  Callers must separately and
        explicitly pass it to :meth:`run_harness_attempt` to execute it in a
        fresh container.
        """

        if result.harness_gate is None:
            raise ValueError("adaptive result does not include a harness gate")
        return request_validated_plan(client, result.package_map, result.harness_gate)

    def run_harness_attempt(
        self,
        artifact: NpmArtifact,
        package_map: PackageMap,
        plan: HarnessPlan,
        dependency_closure: Optional[DependencyClosure] = None,
    ) -> AdaptiveAttempt:
        """Run a validated function-call plan in another new sandbox."""

        return self._run_attempt(
            "harness",
            artifact,
            package_map,
            plan.profile_id,
            plan=plan,
            dependency_closure=dependency_closure,
        )

    def finalize_harness_attempt(
        self,
        result: AdaptiveNpmResult,
        plan: HarnessPlan,
        harness_attempt: AdaptiveAttempt,
    ) -> AdaptiveExecutionResult:
        """Merge evidence from an explicit second sandbox into a final receipt view."""

        if harness_attempt.kind != "harness":
            raise ValueError("only a harness attempt can finalize adaptive execution")
        if (
            result.harness_gate is None
            or not result.harness_gate.should_execute
            or plan.profile_id not in result.harness_gate.allowed_profiles
        ):
            raise ValueError("harness plan was not authorized by the adaptive gate")
        if harness_attempt.run.profile_id != plan.profile_id:
            raise ValueError("harness attempt profile does not match its validated plan")
        return AdaptiveExecutionResult(
            analysis=result,
            harness_plan=plan,
            harness_attempt=harness_attempt,
            combined_coverage=merge_coverage_reports(
                result.package_map,
                [result.import_attempt.coverage, harness_attempt.coverage],
            ),
        )

    def _run_import_attempt(
        self,
        artifact: NpmArtifact,
        package_map: PackageMap,
        profile_id: str,
        dependency_closure: Optional[DependencyClosure],
    ) -> AdaptiveAttempt:
        return self._run_attempt(
            "import",
            artifact,
            package_map,
            profile_id,
            dependency_closure=dependency_closure,
        )

    def _run_attempt(
        self,
        kind: str,
        artifact: NpmArtifact,
        package_map: PackageMap,
        profile_id: str,
        plan: Optional[HarnessPlan] = None,
        dependency_closure: Optional[DependencyClosure] = None,
    ) -> AdaptiveAttempt:
        session_root = Path(
            tempfile.mkdtemp(prefix=f"adaptive-{kind}-{artifact.sha256[:12]}-", dir=str(self.workspace))
        )
        session_root.chmod(0o700)
        environment = prepare_environment(profile_id, session_root / "profile")
        try:
            if kind == "import":
                run = self.runner.run_import_probe(
                    artifact,
                    package_map,
                    environment,
                    session_root / "runs",
                    dependency_closure=dependency_closure,
                )
            else:
                if plan is None:
                    raise ValueError("a harness attempt requires a validated plan")
                run = self.runner.run_harness(
                    artifact,
                    package_map,
                    plan,
                    environment,
                    session_root / "runs",
                    dependency_closure=dependency_closure,
                )
            coverage = (
                summarize_v8_coverage(run.coverage_dir, package_map, Path("/input/package"))
                if run.coverage_dir
                else summarize_v8_coverage(session_root / "missing-v8", package_map)
            )
            trace_evidence = analyze_trace(run.trace_path, artifact.package_dir)
            probe_results = load_import_probe_results(run.output_dir) if kind == "import" else []
            return AdaptiveAttempt(kind, run, coverage, trace_evidence, probe_results)
        finally:
            # The profile holds generated canaries only, but it is still
            # transient input and should not outlive the individual attempt.
            shutil.rmtree(environment.root, ignore_errors=True)


def _plan_as_dict(plan: Optional[HarnessPlan]) -> Optional[Dict[str, Any]]:
    """Serialize a trusted plan without leaking an executable source payload."""

    if plan is None:
        return None
    return {
        "schema_version": plan.schema_version,
        "profile_id": plan.profile_id,
        "attempt_budget": plan.attempt_budget,
        "actions": [
            {
                "entrypoint": action.entrypoint,
                "loader": action.loader,
                "export_name": action.export_name,
                "fixture_ids": list(action.fixture_ids),
                "timeout_ms": action.timeout_ms,
            }
            for action in plan.actions
        ],
    }
