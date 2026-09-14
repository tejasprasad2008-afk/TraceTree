"""Provider-agnostic, constrained boundary for AI harness planning.

This module intentionally does not configure or call a model provider.  A
caller may supply a client adapter, but the adapter receives only the compact
allowlisted planner context and its response must be one small JSON object
that passes the same gate and schema validation as deterministic plans.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Mapping, Protocol, Union

from .harness_policy import (
    HarnessGateDecision,
    build_planner_context,
    validate_planner_proposal,
)
from .models import HarnessPlan, PackageMap
from .plan_schema import HarnessPlanValidationError


_MAX_RESPONSE_BYTES = 16 * 1024


class HarnessPlannerClient(Protocol):
    """Minimal interface a model-provider adapter must implement."""

    def propose_harness_plan(self, context: Mapping[str, Any]) -> Union[str, Mapping[str, Any]]:
        """Return a JSON object/string containing only a HarnessPlan proposal."""


class HarnessPlannerResponseError(ValueError):
    """Raised when an untrusted planner response is not bounded JSON."""


def request_validated_plan(
    client: HarnessPlannerClient,
    package_map: PackageMap,
    decision: HarnessGateDecision,
) -> HarnessPlan:
    """Request and validate one plan without granting the planner authority.

    The client never sees the package archive, source, raw traces, synthetic
    environment values, credentials, commands, or filesystem paths.  Its JSON
    response cannot bypass the adaptive gate, profile selection, export map,
    fixture catalog, action count, or timeout limits.
    """

    context = build_planner_context(package_map, decision)
    try:
        return _request_once(client, context, package_map, decision)
    except (HarnessPlanValidationError, HarnessPlannerResponseError) as first_error:
        # A single repair pass keeps local/remote costs bounded. The feedback
        # contains only a generic validation failure, never package source,
        # traces, credentials, synthetic values, or rendered code.
        repair_context = dict(context)
        repair_context["previous_validation_error"] = str(first_error)
        repair_context["planner_rule"] = (
            f"{context['planner_rule']} Correct the previous validation error and return a replacement JSON object only."
        )
        return _request_once(client, repair_context, package_map, decision)


def _request_once(
    client: HarnessPlannerClient,
    context: Mapping[str, Any],
    package_map: PackageMap,
    decision: HarnessGateDecision,
) -> HarnessPlan:
    response = client.propose_harness_plan(context)
    proposal = _decode_proposal(response)
    return validate_planner_proposal(proposal, package_map, decision)


def _decode_proposal(response: Union[str, Mapping[str, Any]]) -> Dict[str, Any]:
    if isinstance(response, Mapping):
        try:
            encoded = json.dumps(response, separators=(",", ":"), default=str).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise HarnessPlannerResponseError("planner response cannot be encoded as JSON") from exc
        if len(encoded) > _MAX_RESPONSE_BYTES:
            raise HarnessPlannerResponseError("planner response exceeds 16 KiB")
        return dict(response)
    if not isinstance(response, str):
        raise HarnessPlannerResponseError("planner response must be a JSON object or string")
    encoded = response.encode("utf-8")
    if len(encoded) > _MAX_RESPONSE_BYTES:
        raise HarnessPlannerResponseError("planner response exceeds 16 KiB")
    try:
        value = json.loads(response)
    except json.JSONDecodeError as exc:
        raise HarnessPlannerResponseError("planner response is not valid JSON") from exc
    if not isinstance(value, dict):
        raise HarnessPlannerResponseError("planner response must decode to an object")
    return value
