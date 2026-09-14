from __future__ import annotations

import io
import tarfile
from pathlib import Path

from npm_adaptive.analyzer import AdaptiveNpmAnalyzer
from npm_adaptive.artifact_store import ArtifactStore
from npm_adaptive.models import CoverageReport, HarnessRun


def _artifact(tmp_path: Path):
    tarball = tmp_path / "package.tgz"
    with tarfile.open(tarball, "w:gz") as archive:
        for name, content in {
            "package/package.json": '{"name":"analysis-demo","version":"1.0.0","main":"index.js"}',
            "package/index.js": "exports.unused = () => true;",
        }.items():
            encoded = content.encode()
            member = tarfile.TarInfo(name)
            member.size = len(encoded)
            archive.addfile(member, io.BytesIO(encoded))
    return ArtifactStore(tmp_path / "artifacts").ingest_tarball(tarball, "analysis-demo@1.0.0")


class _Runner:
    def run_import_probe(self, artifact, package_map, environment, output_root, dependency_closure=None):
        output = Path(output_root)
        output.mkdir(parents=True)
        trace = output / "strace.log"
        trace.write_text('12:00:00 openat(AT_FDCWD, "/input/package/index.js", O_RDONLY) = 3\n')
        coverage = output / "v8"
        coverage.mkdir()
        return HarnessRun(
            attempt_id="attempt-1",
            profile_id=environment.profile_id,
            outcome="completed",
            output_dir=output,
            trace_path=trace,
            coverage_dir=coverage,
            stdout_path=output / "stdout.log",
            stderr_path=output / "stderr.log",
            timed_out=False,
        )

    def run_harness(self, artifact, package_map, plan, environment, output_root, dependency_closure=None):
        output = Path(output_root)
        output.mkdir(parents=True)
        trace = output / "strace.log"
        trace.write_text('12:00:00 openat(AT_FDCWD, "/input/package/index.js", O_RDONLY) = 3\\n')
        coverage = output / "v8"
        coverage.mkdir()
        return HarnessRun(
            attempt_id="attempt-2",
            profile_id=environment.profile_id,
            outcome="completed",
            output_dir=output,
            trace_path=trace,
            coverage_dir=coverage,
            stdout_path=output / "stdout.log",
            stderr_path=output / "stderr.log",
            timed_out=False,
        )


def test_analyzer_keeps_uncovered_exports_visible(tmp_path: Path, monkeypatch):
    artifact = _artifact(tmp_path)
    monkeypatch.setattr("npm_adaptive.static_mapper._scan_static_tree", lambda _: [])
    result = AdaptiveNpmAnalyzer(
        ArtifactStore(tmp_path / "artifacts"), _Runner(), tmp_path / "adaptive-work"
    ).analyze_artifact(artifact)

    assert result.artifact.sha256 == result.package_map.artifact_sha256
    assert "uncovered export: analysis-demo:unused" in result.unresolved_paths
    assert result.harness_gate is not None
    assert not result.harness_gate.should_execute
    assert result.deterministic_harness_plan is None
    assert result.as_dict()["harness_planner_context"]["callable_exports"][0]["name"] == "unused"
    assert "Observed behavior only" in result.as_dict()["verdict_note"]
    assert not list((tmp_path / "adaptive-work").glob("**/profile"))


def test_analyzer_emits_reviewable_harness_plan_for_suspicious_export(tmp_path: Path, monkeypatch):
    artifact = _artifact(tmp_path)
    monkeypatch.setattr(
        "npm_adaptive.static_mapper._scan_static_tree",
        lambda _: [{"rule_name": "credential-access", "severity": "high"}],
    )
    analyzer = AdaptiveNpmAnalyzer(
        ArtifactStore(tmp_path / "artifacts"), _Runner(), tmp_path / "adaptive-work"
    )

    result = analyzer.analyze_artifact(artifact)

    assert result.harness_gate is not None
    assert result.harness_gate.should_execute
    assert result.harness_gate.profile_id == "developer-workstation-v1"
    assert result.deterministic_harness_plan is not None
    assert result.deterministic_harness_plan.actions[0].export_name == "unused"
    payload = result.as_dict()
    assert payload["deterministic_harness_plan"]["profile_id"] == "developer-workstation-v1"
    assert payload["harness_planner_context"]["planner_rule"].startswith("Return only")
    harness_attempt = analyzer.run_selected_harness(result)
    assert harness_attempt.kind == "harness"
    assert harness_attempt.run.attempt_id == "attempt-2"

    completed_harness = harness_attempt.__class__(
        kind="harness",
        run=harness_attempt.run,
        coverage=CoverageReport(
            target_files=["index.js"],
            executed_files=["index.js"],
            executed_function_names=["unused"],
            exercised_exports=["analysis-demo:unused"],
            uncovered_exports=[],
        ),
        trace_evidence=harness_attempt.trace_evidence,
        probe_results=[],
    )
    execution = analyzer.finalize_harness_attempt(
        result, result.deterministic_harness_plan, completed_harness
    )

    assert execution.combined_coverage.exercised_exports == ["analysis-demo:unused"]
    assert "uncovered export: analysis-demo:unused" not in execution.unresolved_paths
    assert "Combined observed behavior only" in execution.as_dict()["verdict_note"]
