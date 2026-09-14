"""Versioned catalog of safe synthetic environment profiles.

Profiles describe capabilities, not secret values.  The future sandbox runner
will generate per-run synthetic fixtures from these identifiers.
"""

from __future__ import annotations

from typing import Dict

from .models import EnvironmentProfile


NODE_LIBRARY_V1 = EnvironmentProfile(
    profile_id="node-library-v1",
    version="1",
    description="Node-compatible library runtime with primitive and JSON fixtures.",
    fixture_ids=[
        "string-basic",
        "string-empty",
        "number-zero",
        "boolean-true",
        "json-empty-object",
        "json-empty-array",
    ],
    network_policy="none",
)

DEVELOPER_WORKSTATION_V1 = EnvironmentProfile(
    profile_id="developer-workstation-v1",
    version="1",
    description=(
        "Synthetic developer home with per-run canary files; no real credentials "
        "and no external network access."
    ),
    fixture_ids=[
        "string-basic",
        "json-empty-object",
        "developer-config-path",
    ],
    # The first runner keeps every profile offline.  A later, separately
    # tested profile will add an internal-only sinkhole sidecar.
    network_policy="none",
)

CI_RUNNER_V1 = EnvironmentProfile(
    profile_id="ci-runner-v1",
    version="1",
    description="Synthetic GitHub-style CI workspace with generated event and token canaries.",
    fixture_ids=["string-basic", "json-empty-object", "ci-event"],
    network_policy="none",
)

CLOUD_SERVICE_V1 = EnvironmentProfile(
    profile_id="cloud-service-v1",
    version="1",
    description="Synthetic cloud workload with generated credential and metadata canaries.",
    fixture_ids=["string-basic", "json-empty-object", "cloud-request"],
    network_policy="none",
)

COMMERCE_CLIENT_V1 = EnvironmentProfile(
    profile_id="commerce-client-v1",
    version="1",
    description=(
        "Synthetic checkout-client state with generated payment-token canaries; "
        "this is a Node profile, not a browser emulator."
    ),
    fixture_ids=["string-basic", "json-empty-object", "checkout-payload"],
    network_policy="none",
)

PROFILE_CATALOG: Dict[str, EnvironmentProfile] = {
    NODE_LIBRARY_V1.profile_id: NODE_LIBRARY_V1,
    DEVELOPER_WORKSTATION_V1.profile_id: DEVELOPER_WORKSTATION_V1,
    CI_RUNNER_V1.profile_id: CI_RUNNER_V1,
    CLOUD_SERVICE_V1.profile_id: CLOUD_SERVICE_V1,
    COMMERCE_CLIENT_V1.profile_id: COMMERCE_CLIENT_V1,
}


def get_profile(profile_id: str) -> EnvironmentProfile:
    """Return an explicitly registered profile or raise a policy error."""

    try:
        return PROFILE_CATALOG[profile_id]
    except KeyError as exc:
        raise ValueError(f"unknown environment profile: {profile_id}") from exc
