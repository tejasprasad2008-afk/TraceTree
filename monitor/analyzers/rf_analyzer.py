from __future__ import annotations

from monitor.analyzers.base import AnalysisFinding, AnalyzerActions, SampleAnalyzer
from ml.detector import detect_anomaly  # unchanged — ml/detector.py:354


class RandomForestAnalyzer(SampleAnalyzer):
    """Wraps detect_anomaly(graph_data, parsed_data) -> AnomalyVerdict.

    inputs required:
        graph_data   dict  from build_cascade_graph(parsed_data, sig_matches)
        parsed_data  dict  from parse_strace_log
    """

    name = "rf_classifier"

    def analyze(self, sample_id: str, inputs: dict, actions: AnalyzerActions) -> None:
        graph_data: dict = inputs["graph_data"]
        parsed_data: dict = inputs["parsed_data"]

        result = detect_anomaly(graph_data, parsed_data)  # unchanged, detector.py:354
        # AnomalyVerdict is a 2-tuple (is_malicious, risk_score) for backward compat.
        # ml_probability and reasons are attributes, NOT tuple elements.

        actions.raise_finding(AnalysisFinding(
            analyzer_name=self.name,
            sample_id=sample_id,
            verdict="MALICIOUS" if result.is_malicious else "BENIGN",
            confidence=float(result.ml_probability) if result.ml_probability is not None else float(result.risk_score) / 100.0,
            evidence=list(result.reasons),
            model_version="rf-v1",
            raw_output=result,
        ))
