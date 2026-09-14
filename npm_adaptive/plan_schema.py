"""Validation for bounded, declarative harness plans.

An LLM or deterministic planner may propose this data, but it cannot provide
source code, shell syntax, filesystem paths, credentials, or network policy.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Set

from .models import HarnessAction, HarnessPlan, PackageExport, PackageMap
from .profiles import get_profile

PLAN_SCHEMA_VERSION = "tracetree.harness_plan.v1"
_MAX_ACTIONS = 10
_MAX_ATTEMPTS = 3
_MAX_TIMEOUT_MS = 5_000
_MIN_TIMEOUT_MS = 100
_ALLOWED_LOADERS = {"import", "require"}
_ALLOWED_OPERATIONS = {"call"}


class HarnessPlanValidationError(ValueError):
    """Raised when a planner proposes a capability outside the policy."""


def validate_harness_plan(raw: Mapping[str, Any], package_map: PackageMap) -> HarnessPlan:
    """Validate an untrusted JSON-like plan against static package facts."""

    if not isinstance(raw, Mapping):
        raise HarnessPlanValidationError("harness plan must be an object")
    _reject_unknown_keys(raw, {"schema_version", "profile_id", "actions", "attempt_budget"}, "plan")

    if raw.get("schema_version") != PLAN_SCHEMA_VERSION:
        raise HarnessPlanValidationError("unsupported harness plan schema version")
    profile_id = raw.get("profile_id")
    if not isinstance(profile_id, str):
        raise HarnessPlanValidationError("profile_id must be a string")
    try:
        profile = get_profile(profile_id)
    except ValueError as exc:
        raise HarnessPlanValidationError(str(exc)) from exc

    attempt_budget = raw.get("attempt_budget")
    if not isinstance(attempt_budget, int) or not 1 <= attempt_budget <= _MAX_ATTEMPTS:
        raise HarnessPlanValidationError(f"attempt_budget must be between 1 and {_MAX_ATTEMPTS}")

    actions_raw = raw.get("actions")
    if not isinstance(actions_raw, list) or not actions_raw:
        raise HarnessPlanValidationError("actions must be a non-empty list")
    if len(actions_raw) > _MAX_ACTIONS:
        raise HarnessPlanValidationError(f"actions cannot exceed {_MAX_ACTIONS}")

    entrypoint_loaders = _entrypoint_loaders(package_map)
    callable_exports = _callable_exports(package_map)
    actions = [
        _validate_action(item, profile.fixture_ids, entrypoint_loaders, callable_exports)
        for item in actions_raw
    ]
    return HarnessPlan(
        schema_version=PLAN_SCHEMA_VERSION,
        profile_id=profile.profile_id,
        actions=actions,
        attempt_budget=attempt_budget,
    )


def _validate_action(
    raw: Any,
    allowed_fixtures: Iterable[str],
    entrypoint_loaders: Mapping[str, Set[str]],
    callable_exports: Mapping[tuple[str, str], PackageExport],
) -> HarnessAction:
    if not isinstance(raw, Mapping):
        raise HarnessPlanValidationError("each action must be an object")
    _reject_unknown_keys(
        raw,
        {"entrypoint", "loader", "export_name", "operation", "fixtures", "timeout_ms"},
        "action",
    )

    entrypoint = raw.get("entrypoint")
    export_name = raw.get("export_name")
    loader = raw.get("loader")
    operation = raw.get("operation")
    if not isinstance(entrypoint, str) or entrypoint not in entrypoint_loaders:
        raise HarnessPlanValidationError("action references an unknown entrypoint")
    export = callable_exports.get((entrypoint, export_name)) if isinstance(export_name, str) else None
    if export is None:
        raise HarnessPlanValidationError("action references a non-callable or unknown export")
    if loader not in _ALLOWED_LOADERS:
        raise HarnessPlanValidationError("action loader must be import or require")
    if loader not in entrypoint_loaders[entrypoint]:
        raise HarnessPlanValidationError("action loader is unavailable for this entrypoint")
    if operation not in _ALLOWED_OPERATIONS:
        raise HarnessPlanValidationError("only direct export calls are allowed")

    fixtures = raw.get("fixtures")
    if not isinstance(fixtures, list) or not all(isinstance(item, str) for item in fixtures):
        raise HarnessPlanValidationError("fixtures must be a list of fixture identifiers")
    permitted = set(allowed_fixtures)
    if any(item not in permitted for item in fixtures):
        raise HarnessPlanValidationError("action requests fixtures unavailable to this profile")
    if export.kind == "function" and len(fixtures) > len(export.parameters):
        raise HarnessPlanValidationError("action supplies more fixtures than statically known parameters")

    timeout_ms = raw.get("timeout_ms")
    if not isinstance(timeout_ms, int) or not _MIN_TIMEOUT_MS <= timeout_ms <= _MAX_TIMEOUT_MS:
        raise HarnessPlanValidationError(
            f"timeout_ms must be between {_MIN_TIMEOUT_MS} and {_MAX_TIMEOUT_MS}"
        )
    return HarnessAction(
        entrypoint=entrypoint,
        loader=loader,
        export_name=export_name,
        fixture_ids=list(fixtures),
        timeout_ms=timeout_ms,
    )


def _entrypoint_loaders(package_map: PackageMap) -> Dict[str, Set[str]]:
    return {
        entrypoint.specifier: {
            loader
            for loader, path in (
                ("import", entrypoint.import_path),
                ("require", entrypoint.require_path),
            )
            if path
        }
        for entrypoint in package_map.entrypoints
    }


def _callable_exports(package_map: PackageMap) -> Dict[tuple[str, str], PackageExport]:
    # ``unknown`` CommonJS exports are admitted only for a future runtime
    # shape probe.  The renderer still validates typeof target === 'function'.
    return {
        (item.entrypoint, item.name): item
        for item in package_map.exports
        if item.kind in {"function", "unknown"}
    }


def _reject_unknown_keys(raw: Mapping[str, Any], allowed: Set[str], label: str) -> None:
    extra = sorted(set(raw) - allowed)
    if extra:
        raise HarnessPlanValidationError(f"{label} contains unsupported fields: {', '.join(extra)}")
