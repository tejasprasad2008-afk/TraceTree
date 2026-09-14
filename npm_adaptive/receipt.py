"""Privacy-preserving receipt for adaptive npm analysis attempts.

The receipt deliberately records evidence summaries and local artifact hashes,
not raw syscall logs, synthetic values, package source, or rendered harness
code.  It is a review object rather than a clean/malicious verdict engine.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterable, Optional

from .coverage import merge_coverage_reports

if TYPE_CHECKING:  # pragma: no cover - type-only to avoid an import cycle
    from .analyzer import AdaptiveAttempt, AdaptiveExecutionResult, AdaptiveNpmResult


ADAPTIVE_RECEIPT_SCHEMA = "tracetree.adaptive_npm_receipt.v1"


def build_adaptive_receipt(
    result: "AdaptiveNpmResult",
    harness_attempt: Optional["AdaptiveAttempt"] = None,
    *,
    execution: Optional["AdaptiveExecutionResult"] = None,
    sandbox_image: Optional[str] = None,
) -> Dict[str, Any]:
    """Build an artifact-bound summary safe to show to a human or planner.

    A lack of observed suspicion is intentionally classified as
    ``inconclusive``, because importing a package does not execute every API
    path.  This prevents a baseline-only analysis from being misrepresented as
    a clean verdict.
    """

    attempts = [result.import_attempt]
    if harness_attempt is not None:
        attempts.append(harness_attempt)
    gate = result.harness_gate
    combined_coverage = (
        execution.combined_coverage
        if execution is not None
        else merge_coverage_reports(result.package_map, [attempt.coverage for attempt in attempts])
    )
    unresolved = execution.unresolved_paths if execution is not None else result.unresolved_paths
    suspicious = bool(gate and gate.suspicion_score > 0)
    classification = "suspicious" if suspicious else "inconclusive"
    if harness_attempt is not None:
        harness_status = "executed"
    elif result.deterministic_harness_plan is not None:
        harness_status = "authorized_not_executed"
    else:
        harness_status = "not_authorized"

    return {
        "schema": ADAPTIVE_RECEIPT_SCHEMA,
        "target": {
            "type": "npm",
            "name": result.artifact.package_name,
            "version": result.artifact.version,
            "artifact_sha256": f"sha256:{result.artifact.sha256}",
        },
        "sandbox": {
            "mode": "fresh-docker-adaptive-npm",
            "network_policy": "disabled-during-package-execution",
            "image": sandbox_image,
            "fresh_container_per_attempt": True,
            "host_bind_mounts": False,
            "root_filesystem_read_only": True,
        },
        "attempts": [_attempt_summary(item) for item in attempts],
        "combined_coverage": combined_coverage.as_dict(),
        "adaptive_gate": gate.as_dict() if gate else None,
        "harness": {
            "status": harness_status,
            "plan": _plan_summary(
                execution.harness_plan if execution is not None else result.deterministic_harness_plan
            ),
        },
        "unresolved_paths": list(unresolved),
        "classification": {
            "decision": classification,
            "reason": _classification_reason(gate, unresolved),
            "review_required": True,
        },
        "privacy": {
            "raw_syscalls_included": False,
            "package_source_included": False,
            "environment_values_included": False,
            "secrets_included": False,
            "rendered_harness_source_included": False,
        },
    }


def _attempt_summary(attempt: "AdaptiveAttempt") -> Dict[str, Any]:
    trace = attempt.trace_evidence
    return {
        "kind": attempt.kind,
        "attempt_id": attempt.run.attempt_id,
        "profile_id": attempt.run.profile_id,
        "outcome": attempt.run.outcome,
        "timed_out": attempt.run.timed_out,
        "coverage": {
            "file_ratio": round(attempt.coverage.file_ratio, 4),
            "executed_files": len(attempt.coverage.executed_files),
            "exercised_exports": list(attempt.coverage.exercised_exports),
            "uncovered_exports": list(attempt.coverage.uncovered_exports),
            "parse_error_count": len(attempt.coverage.parse_errors),
        },
        "behavior": {
            "signature_matches": list(trace.signature_matches),
            "warnings": list(trace.warnings),
        },
        "artifacts": {
            "strace_log_sha256": _file_sha256(attempt.run.trace_path),
            "stdout_sha256": _file_sha256(attempt.run.stdout_path),
            "stderr_sha256": _file_sha256(attempt.run.stderr_path),
        },
    }


def _plan_summary(plan: Any) -> Optional[Dict[str, Any]]:
    if plan is None:
        return None
    return {
        "profile_id": plan.profile_id,
        "attempt_budget": plan.attempt_budget,
        "actions": [
            {
                "entrypoint": action.entrypoint,
                "loader": action.loader,
                "export_name": action.export_name,
                "fixture_ids": list(action.fixture_ids),
            }
            for action in plan.actions
        ],
    }


def _classification_reason(gate: Any, unresolved: Iterable[str]) -> str:
    if gate and gate.suspicion_score > 0:
        return "Static or import-time behavioral evidence triggered adaptive review."
    if any(True for _ in unresolved):
        return "No suspicious behavior was observed in the baseline, but unresolved paths remain."
    return "No suspicious behavior was observed; this evidence is still not a clean verdict."


def _file_sha256(path: Optional[Path]) -> Optional[str]:
    if path is None or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(64 * 1024), b""):
            digest.update(block)
    return f"sha256:{digest.hexdigest()}"
