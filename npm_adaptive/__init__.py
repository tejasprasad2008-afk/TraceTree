"""Adaptive, artifact-correlated npm package analysis.

This package is intentionally isolated from TraceTree's legacy install-time
scanner.  It starts by establishing immutable package identity and a static
map; later phases add constrained harness execution in fresh sandboxes.
"""

from .artifact_store import ArtifactStore, UnsafeArtifactError
from .analyzer import AdaptiveAttempt, AdaptiveExecutionResult, AdaptiveNpmAnalyzer, AdaptiveNpmResult
from .coverage import merge_coverage_reports, summarize_v8_coverage
from .dependencies import DependencyResolver
from .environment import prepare_environment
from .harness_policy import (
    HarnessGateDecision,
    build_deterministic_plan,
    build_planner_context,
    evaluate_harness_gate,
    validate_planner_proposal,
)
from .harness_renderer import render_harness
from .models import DependencyClosure, DependencyInstall, NpmArtifact, PackageMap
from .plan_schema import HarnessPlanValidationError, validate_harness_plan
from .planner import HarnessPlannerClient, HarnessPlannerResponseError, request_validated_plan
from .planner_providers import (
    HarnessPlannerProviderError,
    OllamaHarnessPlannerClient,
    OpenRouterHarnessPlannerClient,
    create_harness_planner_client,
)
from .probe_results import load_import_probe_results
from .registry import NpmRegistryBroker, RegistryIntegrityError, RegistryResolutionError
from .receipt import ADAPTIVE_RECEIPT_SCHEMA, build_adaptive_receipt
from .sandbox_runner import AdaptiveSandboxError, AdaptiveSandboxPolicyError, AdaptiveSandboxRunner
from .static_mapper import build_package_map
from .trace_analysis import TraceEvidence, analyze_trace

__all__ = [
    "ArtifactStore",
    "AdaptiveAttempt",
    "AdaptiveExecutionResult",
    "AdaptiveNpmAnalyzer",
    "AdaptiveNpmResult",
    "AdaptiveSandboxError",
    "AdaptiveSandboxPolicyError",
    "AdaptiveSandboxRunner",
    "ADAPTIVE_RECEIPT_SCHEMA",
    "DependencyResolver",
    "DependencyClosure",
    "DependencyInstall",
    "NpmArtifact",
    "OllamaHarnessPlannerClient",
    "OpenRouterHarnessPlannerClient",
    "PackageMap",
    "HarnessPlanValidationError",
    "HarnessPlannerClient",
    "HarnessPlannerProviderError",
    "HarnessPlannerResponseError",
    "HarnessGateDecision",
    "NpmRegistryBroker",
    "RegistryIntegrityError",
    "RegistryResolutionError",
    "UnsafeArtifactError",
    "build_package_map",
    "create_harness_planner_client",
    "build_deterministic_plan",
    "build_adaptive_receipt",
    "build_planner_context",
    "evaluate_harness_gate",
    "render_harness",
    "prepare_environment",
    "request_validated_plan",
    "load_import_probe_results",
    "merge_coverage_reports",
    "summarize_v8_coverage",
    "TraceEvidence",
    "analyze_trace",
    "validate_harness_plan",
    "validate_planner_proposal",
]
