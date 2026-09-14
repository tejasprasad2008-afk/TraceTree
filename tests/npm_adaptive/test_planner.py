from __future__ import annotations

import pytest

from npm_adaptive.harness_policy import evaluate_harness_gate
from npm_adaptive.models import CoverageReport, PackageEntrypoint, PackageExport, PackageMap
from npm_adaptive.plan_schema import HarnessPlanValidationError
from npm_adaptive.planner import HarnessPlannerResponseError, request_validated_plan
from npm_adaptive.trace_analysis import TraceEvidence


def _package_map() -> PackageMap:
    return PackageMap(
        artifact_sha256="a" * 64,
        package_name="planner-demo",
        package_version="1.0.0",
        module_type="commonjs",
        entrypoints=[PackageEntrypoint(specifier="planner-demo", source="main", require_path="index.js")],
        exports=[
            PackageExport(
                entrypoint="planner-demo",
                name="probe",
                kind="function",
                source_path="index.js",
                confidence="high",
                parameters=["value"],
            )
        ],
        static_findings=[{"rule_name": "credential-access", "severity": "high"}],
        unsupported_paths=[],
    )


def _coverage() -> CoverageReport:
    return CoverageReport([], [], [], [], ["planner-demo:probe"])


def _decision():
    return evaluate_harness_gate(
        _package_map(), _coverage(), TraceEvidence(None, {}, [], [], [], {})
    )


class _Client:
    def __init__(self, response):
        self.response = response
        self.context = None

    def propose_harness_plan(self, context):
        self.context = context
        return self.response


class _SequenceClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.contexts = []

    def propose_harness_plan(self, context):
        self.contexts.append(context)
        return self.responses.pop(0)


def test_planner_receives_only_context_and_validated_json_plan():
    client = _Client(
        {
            "schema_version": "tracetree.harness_plan.v1",
            "profile_id": "developer-workstation-v1",
            "attempt_budget": 1,
            "actions": [
                {
                    "entrypoint": "planner-demo",
                    "loader": "require",
                    "export_name": "probe",
                    "operation": "call",
                    "fixtures": ["string-basic"],
                    "timeout_ms": 500,
                }
            ],
        }
    )

    plan = request_validated_plan(client, _package_map(), _decision())

    assert plan.profile_id == "developer-workstation-v1"
    assert client.context["callable_exports"][0]["name"] == "probe"
    assert "source" not in client.context
    assert "trace" not in client.context


def test_planner_cannot_escape_profile_gate():
    client = _Client(
        {
            "schema_version": "tracetree.harness_plan.v1",
            "profile_id": "node-library-v1",
            "attempt_budget": 1,
            "actions": [
                {
                    "entrypoint": "planner-demo",
                    "loader": "require",
                    "export_name": "probe",
                    "operation": "call",
                    "fixtures": ["string-basic"],
                    "timeout_ms": 500,
                }
            ],
        }
    )

    with pytest.raises(HarnessPlanValidationError, match="not authorized"):
        request_validated_plan(client, _package_map(), _decision())


def test_planner_rejects_non_json_or_oversized_response():
    with pytest.raises(HarnessPlannerResponseError, match="not valid JSON"):
        request_validated_plan(_Client("write a harness"), _package_map(), _decision())
    with pytest.raises(HarnessPlannerResponseError, match="exceeds"):
        request_validated_plan(_Client("x" * (16 * 1024 + 1)), _package_map(), _decision())


def test_planner_gets_one_safe_repair_pass_after_validation_failure():
    invalid = {
        "schema_version": "tracetree.harness_plan.v1",
        "profile_id": "developer-workstation-v1",
        "attempt_budget": 1,
        "actions": [
            {
                "entrypoint": "planner-demo",
                "loader": "require",
                "export_name": "probe",
                "operation": "call",
                "fixtures": ["string-basic", "json-empty-object"],
                "timeout_ms": 500,
            }
        ],
    }
    corrected = {
        **invalid,
        "actions": [{**invalid["actions"][0], "fixtures": ["string-basic"]}],
    }
    client = _SequenceClient([invalid, corrected])

    plan = request_validated_plan(client, _package_map(), _decision())

    assert plan.actions[0].fixture_ids == ["string-basic"]
    assert len(client.contexts) == 2
    assert "previous_validation_error" in client.contexts[1]
    assert "source" not in client.contexts[1]["previous_validation_error"]
