"""Opt-in command-line entrypoint for adaptive npm analysis.

This is deliberately separate from the legacy ``cascade-analyze --type npm``
command while the new evidence model is validated.  The legacy path continues
to report install-time behavior; this command reports import/harness evidence
for the exact fetched tarball.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyzer import AdaptiveNpmAnalyzer
from .artifact_store import ArtifactStore, UnsafeArtifactError
from .dependencies import DependencyResolver
from .planner_providers import HarnessPlannerProviderError, create_harness_planner_client
from .registry import NpmRegistryBroker, RegistryIntegrityError, RegistryResolutionError
from .receipt import build_adaptive_receipt
from .sandbox_runner import AdaptiveSandboxError, AdaptiveSandboxRunner
from .static_mapper import build_package_map

def scan(
    specifier: str,
    *,
    profile: str = "node-library-v1",
    image: str = "tracetree-adaptive-node:latest",
    state_dir: Path = Path(".tracetree/adaptive"),
    static_only: bool = False,
    run_harness: bool = False,
    planner_provider: str | None = None,
) -> dict:
    """Analyze one immutable npm tarball; never claim unexecuted paths are safe."""

    state_dir = Path(state_dir).resolve()
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    state_dir.chmod(0o700)
    store = ArtifactStore(state_dir / "artifacts")
    broker = NpmRegistryBroker()
    artifact, release = broker.fetch_to_store(specifier, store)
    if static_only:
        package_map = build_package_map(artifact)
        return {
            "artifact": {
                "sha256": artifact.sha256,
                "package_name": artifact.package_name,
                "version": artifact.version,
                "byte_size": artifact.byte_size,
            },
            "registry_release": {
                "requested_specifier": release.requested_specifier,
                "version": release.version,
                "tarball_url": release.tarball_url,
                "integrity": release.integrity,
            },
            "package_map": package_map.as_dict(),
            "verdict_note": "Static evidence only; no package code was executed.",
        }
    analyzer = AdaptiveNpmAnalyzer(
        artifact_store=store,
        runner=AdaptiveSandboxRunner(image=image),
        workspace=state_dir / "runs",
        broker=broker,
    )
    dependency_closure = DependencyResolver(broker, store).resolve(artifact)
    result = analyzer.analyze_artifact(
        artifact,
        profile_id=profile,
        registry_release=release,
        dependency_closure=dependency_closure,
    )
    payload = result.as_dict()
    selected_plan = result.deterministic_harness_plan
    if planner_provider:
        if selected_plan is None:
            payload["model_harness_plan"] = {
                "status": "not_authorized",
                "reason": "No post-import harness plan was authorized by the adaptive gate.",
            }
        else:
            client = create_harness_planner_client(planner_provider)
            selected_plan = analyzer.request_model_harness_plan(result, client)
            payload["model_harness_plan"] = {
                "status": "validated",
                "provider": planner_provider,
                "plan": _plan_summary(selected_plan),
            }
    harness_attempt = None
    execution = None
    if run_harness:
        if selected_plan is None:
            payload["harness_execution"] = {
                "status": "not_authorized",
                "reason": "No post-import harness plan was authorized by the adaptive gate.",
            }
        else:
            harness_attempt = analyzer.run_harness_attempt(
                result.artifact,
                result.package_map,
                selected_plan,
                result.dependency_closure,
            )
            execution = analyzer.finalize_harness_attempt(
                result, selected_plan, harness_attempt
            )
            payload["harness_execution"] = {
                "status": "executed",
                "attempt": harness_attempt.as_dict(),
            }
            payload["adaptive_execution"] = execution.as_dict()
    payload["receipt"] = build_adaptive_receipt(
        result, harness_attempt, execution=execution, sandbox_image=image
    )
    return payload


def _plan_summary(plan) -> dict:
    """Serialize the validated plan, never its rendered JavaScript."""

    return {
        "schema_version": plan.schema_version,
        "profile_id": plan.profile_id,
        "attempt_budget": plan.attempt_budget,
        "actions": [
            {
                "entrypoint": action.entrypoint,
                "loader": action.loader,
                "export_name": action.export_name,
                "fixture_ids": list(action.fixture_ids),
                "timeout_ms": action.timeout_ms,
            }
            for action in plan.actions
        ],
    }


def main(argv: list[str] | None = None) -> int:
    """Run the experimental command without depending on TraceTree's UI CLI."""

    arguments = list(argv) if argv is not None else sys.argv[1:]
    # Keep the documented ``cascade-adaptive-npm scan <specifier>`` form while
    # also allowing the compact ``cascade-adaptive-npm <specifier>`` form.
    if arguments and arguments[0] == "scan":
        arguments = arguments[1:]
    parser = argparse.ArgumentParser(
        description="Experimental artifact-correlated npm import analysis for TraceTree."
    )
    parser.add_argument("specifier", help="Registry package name with optional exact version or dist-tag")
    parser.add_argument("--profile", default="node-library-v1", help="Synthetic sandbox profile")
    parser.add_argument("--image", default="tracetree-adaptive-node:latest", help="Adaptive sandbox image tag")
    parser.add_argument("--state-dir", type=Path, default=Path(".tracetree/adaptive"), help="Artifact/evidence directory")
    parser.add_argument("--static-only", action="store_true", help="Do not execute package code in Docker")
    parser.add_argument(
        "--run-harness",
        action="store_true",
        help="Explicitly execute an authorized post-import harness in a second fresh sandbox",
    )
    parser.add_argument(
        "--planner",
        choices=("ollama", "openrouter"),
        help="Explicitly ask the selected model provider for a validated harness plan",
    )
    args = parser.parse_args(arguments)
    if args.static_only and (args.run_harness or args.planner):
        parser.error("--run-harness and --planner cannot be used with --static-only")
    try:
        payload = scan(
            args.specifier,
            profile=args.profile,
            image=args.image,
            state_dir=args.state_dir,
            static_only=args.static_only,
            run_harness=args.run_harness,
            planner_provider=args.planner,
        )
    except (RegistryResolutionError, RegistryIntegrityError, UnsafeArtifactError, AdaptiveSandboxError, HarnessPlannerProviderError, OSError, ValueError) as exc:
        print(f"adaptive npm scan failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
