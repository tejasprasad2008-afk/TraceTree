from __future__ import annotations

from monitor.analyzers.base import AnalysisFinding, AnalyzerActions, SampleAnalyzer
from orchestrator.ai_mesh import AIMeshOrchestrator, TriageResult  # unchanged


class LegsAnalyzer(SampleAnalyzer):
    """Thin wrapper for all 8 Legs stages via AIMeshOrchestrator.

    Phase B will split into per-stage analyzers with independent thresholds.
    Requires a live Ollama connection — not suitable for offline/dry-run unit tests.

    inputs required:
        parsed_events   list[dict]  from parse_strace_log
        feature_vector  dict        from ml.detector.map_features
        matched_rule    dict        (optional) first YARA/sig match, or {}
        package_metadata dict       (optional) target metadata, or {}
    """

    name = "legs_triage"

    def __init__(
        self,
        ollama_url: str | None = None,
        model: str | None = None,
        dry_run: bool = False,
        verbose: bool = False,
    ) -> None:
        kwargs: dict = {"dry_run": dry_run, "verbose": verbose}
        if ollama_url is not None:
            kwargs["ollama_url"] = ollama_url
        if model is not None:
            kwargs["model"] = model
        self._orchestrator = AIMeshOrchestrator(**kwargs)

    def analyze(self, sample_id: str, inputs: dict, actions: AnalyzerActions) -> None:
        parsed_events: list = inputs["parsed_events"]
        feature_vector: dict = inputs["feature_vector"]
        matched_rule: dict = inputs.get("matched_rule", {})
        package_metadata: dict = inputs.get("package_metadata", {})

        syscall_summary = self._orchestrator.simplify_syscall_log(parsed_events)       # ai_mesh.py:273
        fv_description = self._orchestrator.describe_feature_vector(feature_vector)    # ai_mesh.py:327
        triage: TriageResult = self._orchestrator.triage_false_positive(               # ai_mesh.py:445
            matched_rule, package_metadata
        )

        verdict = "BENIGN" if triage.is_false_positive() else "MALICIOUS"

        actions.raise_finding(AnalysisFinding(
            analyzer_name=self.name,
            sample_id=sample_id,
            verdict=verdict,
            confidence=triage.confidence,
            evidence=[triage.reasoning],
            model_version=self._orchestrator.model,
            raw_output={
                "syscall_summary": syscall_summary,
                "fv_description": fv_description,
                "triage": triage,
            },
        ))
