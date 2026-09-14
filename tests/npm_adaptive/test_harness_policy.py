from __future__ import annotations

import pytest

from npm_adaptive.harness_policy import (
    build_deterministic_plan,
    build_planner_context,
    evaluate_harness_gate,
    validate_planner_proposal,
)
from npm_adaptive.models import CoverageReport, PackageEntrypoint, PackageExport, PackageMap
from npm_adaptive.plan_schema import PLAN_SCHEMA_VERSION, HarnessPlanValidationError
from npm_adaptive.trace_analysis import TraceEvidence


def _package_map(static_findings=None) -> PackageMap:
    return PackageMap(
        artifact_sha256="f" * 64,
        package_name="policy-demo",
        package_version="1.0.0",
        module_type="commonjs",
        entrypoints=[
            PackageEntrypoint(
                specifier="policy-demo",
                source="main",
                require_path="index.js",
            )
        ],
        exports=[
            PackageExport(
                entrypoint="policy-demo",
                name="collect",
                kind="function",
                source_path="index.js",
                confidence="high",
                parameters=["input"],
            )
        ],
        static_findings=static_findings or [],
        unsupported_paths=[],
    )


def _coverage() -> CoverageReport:
    return CoverageReport(
        target_files=["index.js"],
        executed_files=["index.js"],
        executed_function_names=[],
        exercised_exports=[],
        uncovered_exports=["policy-demo:collect"],
    )


def _trace(flags=None) -> TraceEvidence:
    return TraceEvidence(
        trace_path=None,
        parsed_data={"flags": flags or []},
        signature_matches=[],
        temporal_patterns=[],
        yara_matches=[],
        ngram_data={},
    )


def test_clean_baseline_does_not_trigger_harness_only_for_coverage_gap():
    decision = evaluate_harness_gate(_package_map(), _coverage(), _trace())

    assert decision.should_execute is False
    assert decision.suspicion_score == 0
    assert build_deterministic_plan(_package_map(), decision) is None
    assert "unresolved" in " ".join(decision.reasons)


def test_credential_static_signal_selects_fake_developer_profile_and_plan():
    package_map = _package_map(
        [{"rule_name": "Credential_Theft", "severity": "high", "description": "reads npm token"}]
    )
    decision = evaluate_harness_gate(package_map, _coverage(), _trace())
    plan = build_deterministic_plan(package_map, decision)
    context = build_planner_context(package_map, decision)

    assert decision.should_execute is True
    assert decision.profile_id == "developer-workstation-v1"
    assert plan and plan.profile_id == "developer-workstation-v1"
    assert plan.actions[0].fixture_ids == ["string-basic"]
    assert context["profiles"][0]["profile_id"] == "developer-workstation-v1"
    assert "source code" in context["planner_rule"]


def test_planner_cannot_expand_gate_authorized_profile():
    package_map = _package_map([{"rule_name": "credential", "severity": "medium"}])
    decision = evaluate_harness_gate(package_map, _coverage(), _trace())
    proposal = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "profile_id": "node-library-v1",
        "attempt_budget": 1,
        "actions": [
            {
                "entrypoint": "policy-demo",
                "loader": "require",
                "export_name": "collect",
                "operation": "call",
                "fixtures": ["string-basic"],
                "timeout_ms": 1000,
            }
        ],
    }

    with pytest.raises(HarnessPlanValidationError, match="not authorized"):
        validate_planner_proposal(proposal, package_map, decision)


def test_gate_selects_narrow_commerce_profile_from_finding_label():
    package_map = _package_map(
        [{"rule_name": "checkout-payment-token", "severity": "high"}]
    )
    decision = evaluate_harness_gate(package_map, _coverage(), _trace())

    assert decision.profile_id == "commerce-client-v1"
    context = build_planner_context(package_map, decision)
    assert context["profiles"] == [
        {
            "profile_id": "commerce-client-v1",
            "fixture_ids": ["string-basic", "json-empty-object", "checkout-payload"],
            "network_policy": "none",
        }
    ]
