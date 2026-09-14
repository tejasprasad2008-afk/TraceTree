"""Deterministic adaptive-execution gate and constrained planner boundary."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Set

from .models import CoverageReport, HarnessPlan, PackageMap
from .plan_schema import PLAN_SCHEMA_VERSION, HarnessPlanValidationError, validate_harness_plan
from .profiles import get_profile
from .trace_analysis import TraceEvidence


_CREDENTIAL_TERMS = {
    "credential",
    "secret",
    "token",
    "npmrc",
    ".ssh",
    "aws",
    "github",
    "keychain",
}
_CLOUD_TERMS = {"aws", "azure", "gcp", "google cloud", "kubernetes", "kube", "serviceaccount"}
_CI_TERMS = {"github actions", "github_actions", "gitlab_ci", "circleci", "buildkite", "ci token"}
_COMMERCE_TERMS = {"checkout", "payment", "stripe", "credit card", "credit_card", "customer", "purchase"}
_SEVERITY_SCORE = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass(frozen=True)
class HarnessGateDecision:
    """Why a post-import function harness is or is not allowed to run."""

    should_execute: bool
    suspicion_score: int
    profile_id: Optional[str]
    reasons: List[str]
    allowed_profiles: List[str]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "should_execute": self.should_execute,
            "suspicion_score": self.suspicion_score,
            "profile_id": self.profile_id,
            "reasons": list(self.reasons),
            "allowed_profiles": list(self.allowed_profiles),
        }


def evaluate_harness_gate(
    package_map: PackageMap,
    coverage: CoverageReport,
    trace_evidence: TraceEvidence,
) -> HarnessGateDecision:
    """Gate dynamic function calls on observed suspicion, never coverage alone."""

    score = 0
    reasons: List[str] = []
    credential_targeting = False
    for finding in package_map.static_findings:
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity", "low")).lower()
        finding_score = _SEVERITY_SCORE.get(severity, 1)
        score += finding_score
        label = str(finding.get("rule_name") or finding.get("description") or "static finding")
        reasons.append(f"static finding ({severity}): {label}")
        if _contains_credential_terms(finding):
            credential_targeting = True

    flags = trace_evidence.parsed_data.get("flags", [])
    if isinstance(flags, list) and flags:
        score += min(3, len(flags))
        reasons.append(f"import trace has {len(flags)} suspicious flag(s)")
        credential_targeting = credential_targeting or _contains_credential_terms(flags)
    if trace_evidence.signature_matches:
        score += min(4, len(trace_evidence.signature_matches) * 2)
        reasons.append(f"import trace matched {len(trace_evidence.signature_matches)} behavioral signature(s)")
        credential_targeting = credential_targeting or _contains_credential_terms(
            trace_evidence.signature_matches
        )

    callable_exports = [item for item in package_map.exports if item.kind in {"function", "unknown"}]
    if not callable_exports:
        reasons.append("no statically callable exports are available for a bounded harness")
        return HarnessGateDecision(False, score, None, reasons, [])
    if score == 0:
        reasons.append(
            "baseline import has no static or behavioral suspicion; uncovered exports remain unresolved without a second run"
        )
        return HarnessGateDecision(False, score, None, reasons, [])

    profile_id = _select_profile(package_map, trace_evidence, credential_targeting)
    reasons.append(
        f"bounded harness allowed for {len(callable_exports)} callable export(s) under {profile_id}"
    )
    return HarnessGateDecision(True, score, profile_id, reasons, [profile_id])


def build_planner_context(package_map: PackageMap, decision: HarnessGateDecision) -> Dict[str, Any]:
    """Return the compact, non-executable context an AI planner may receive."""

    profiles = []
    for profile_id in decision.allowed_profiles:
        profile = get_profile(profile_id)
        profiles.append(
            {
                "profile_id": profile.profile_id,
                "fixture_ids": list(profile.fixture_ids),
                "network_policy": profile.network_policy,
            }
        )
    callable_exports = [
        {
            "entrypoint": item.entrypoint,
            "name": item.name,
            "kind": item.kind,
            "parameters": list(item.parameters),
        }
        for item in package_map.exports
        if item.kind in {"function", "unknown"}
    ]
    return {
        "schema_version": PLAN_SCHEMA_VERSION,
        "artifact_sha256": package_map.artifact_sha256,
        "gate": decision.as_dict(),
        "entrypoints": [
            {
                "specifier": entrypoint.specifier,
                "import_available": bool(entrypoint.import_path),
                "require_available": bool(entrypoint.require_path),
            }
            for entrypoint in package_map.entrypoints
        ],
        "callable_exports": callable_exports,
        "profiles": profiles,
        "planner_rule": "Return only a HarnessPlan JSON object. Do not return source code, shell commands, paths, credentials, environment variables, or network requests.",
    }


def build_deterministic_plan(
    package_map: PackageMap, decision: HarnessGateDecision
) -> Optional[HarnessPlan]:
    """Create a conservative first plan before any LLM planner is enabled."""

    if not decision.should_execute or not decision.profile_id:
        return None
    profile = get_profile(decision.profile_id)
    entrypoints = {item.specifier: item for item in package_map.entrypoints}
    actions = []
    for export in package_map.exports:
        if export.kind not in {"function", "unknown"}:
            continue
        entrypoint = entrypoints.get(export.entrypoint)
        if entrypoint is None:
            continue
        fixtures = _fixtures_for_parameters(export.parameters, set(profile.fixture_ids))
        if fixtures is None:
            continue
        loader = "require" if entrypoint.require_path else "import" if entrypoint.import_path else None
        if loader is None:
            continue
        actions.append(
            {
                "entrypoint": export.entrypoint,
                "loader": loader,
                "export_name": export.name,
                "operation": "call",
                "fixtures": fixtures,
                "timeout_ms": 1200,
            }
        )
        if len(actions) == 2:
            break
    if not actions:
        return None
    return validate_planner_proposal(
        {
            "schema_version": PLAN_SCHEMA_VERSION,
            "profile_id": profile.profile_id,
            "attempt_budget": 1,
            "actions": actions,
        },
        package_map,
        decision,
    )


def validate_planner_proposal(
    proposal: Dict[str, Any], package_map: PackageMap, decision: HarnessGateDecision
) -> HarnessPlan:
    """Validate an AI/deterministic proposal and bind it to the gate policy."""

    if not decision.should_execute:
        raise HarnessPlanValidationError("adaptive harness gate did not authorize execution")
    plan = validate_harness_plan(proposal, package_map)
    if plan.profile_id not in decision.allowed_profiles:
        raise HarnessPlanValidationError("planner chose a profile not authorized by the adaptive gate")
    return plan


def _fixtures_for_parameters(parameters: Sequence[str], available: Set[str]) -> Optional[List[str]]:
    count = len(parameters)
    if count == 0:
        return []
    if count == 1 and "string-basic" in available:
        return ["string-basic"]
    if count == 2 and {"string-basic", "json-empty-object"}.issubset(available):
        return ["string-basic", "json-empty-object"]
    return None


def _contains_credential_terms(value: Any) -> bool:
    try:
        text = json.dumps(value, sort_keys=True, default=str).lower()
    except (TypeError, ValueError):
        text = str(value).lower()
    return any(term in text for term in _CREDENTIAL_TERMS)


def _select_profile(
    package_map: PackageMap, trace_evidence: TraceEvidence, credential_targeting: bool
) -> str:
    """Choose one narrow offline profile from evidence labels, never source text."""

    evidence_text = json.dumps(
        {
            "findings": package_map.static_findings,
            "flags": trace_evidence.parsed_data.get("flags", []),
            "signatures": trace_evidence.signature_matches,
        },
        sort_keys=True,
        default=str,
    ).lower()
    if any(term in evidence_text for term in _COMMERCE_TERMS):
        return "commerce-client-v1"
    if any(term in evidence_text for term in _CLOUD_TERMS):
        return "cloud-service-v1"
    if any(term in evidence_text for term in _CI_TERMS):
        return "ci-runner-v1"
    return "developer-workstation-v1" if credential_targeting else "node-library-v1"
