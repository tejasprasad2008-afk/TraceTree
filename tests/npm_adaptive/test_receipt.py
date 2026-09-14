from __future__ import annotations

from pathlib import Path

from npm_adaptive.analyzer import AdaptiveNpmAnalyzer
from npm_adaptive.artifact_store import ArtifactStore
from npm_adaptive.receipt import ADAPTIVE_RECEIPT_SCHEMA, build_adaptive_receipt
from tests.npm_adaptive.test_analyzer import _Runner, _artifact


def test_receipt_never_upgrades_clean_baseline_to_clean(tmp_path: Path, monkeypatch):
    artifact = _artifact(tmp_path)
    monkeypatch.setattr("npm_adaptive.static_mapper._scan_static_tree", lambda _: [])
    result = AdaptiveNpmAnalyzer(
        ArtifactStore(tmp_path / "artifacts"), _Runner(), tmp_path / "adaptive-work"
    ).analyze_artifact(artifact)

    receipt = build_adaptive_receipt(result, sandbox_image="example@sha256:abc")

    assert receipt["schema"] == ADAPTIVE_RECEIPT_SCHEMA
    assert receipt["target"]["artifact_sha256"] == f"sha256:{artifact.sha256}"
    assert receipt["classification"]["decision"] == "inconclusive"
    assert receipt["classification"]["review_required"] is True
    assert receipt["privacy"]["raw_syscalls_included"] is False
    assert receipt["attempts"][0]["artifacts"]["strace_log_sha256"].startswith("sha256:")
    assert receipt["combined_coverage"]["uncovered_exports"] == ["analysis-demo:unused"]


def test_receipt_records_second_harness_attempt(tmp_path: Path, monkeypatch):
    artifact = _artifact(tmp_path)
    monkeypatch.setattr(
        "npm_adaptive.static_mapper._scan_static_tree",
        lambda _: [{"rule_name": "credential-access", "severity": "high"}],
    )
    analyzer = AdaptiveNpmAnalyzer(
        ArtifactStore(tmp_path / "artifacts"), _Runner(), tmp_path / "adaptive-work"
    )
    result = analyzer.analyze_artifact(artifact)
    harness_attempt = analyzer.run_selected_harness(result)
    execution = analyzer.finalize_harness_attempt(
        result, result.deterministic_harness_plan, harness_attempt
    )

    receipt = build_adaptive_receipt(result, harness_attempt, execution=execution)

    assert receipt["classification"]["decision"] == "suspicious"
    assert receipt["harness"]["status"] == "executed"
    assert [item["kind"] for item in receipt["attempts"]] == ["import", "harness"]
    assert receipt["harness"]["plan"]["profile_id"] == "developer-workstation-v1"
    assert receipt["combined_coverage"]["file_ratio"] == 0.0
