from __future__ import annotations

from monitor.analyzers.base import AnalysisFinding, AnalyzerActions, SampleAnalyzer
from monitor.yara import scan_with_yara  # unchanged — monitor/yara.py:160


class YaraAnalyzer(SampleAnalyzer):
    name = "yara_pack"

    def analyze(self, sample_id: str, inputs: dict, actions: AnalyzerActions) -> None:
        log_path: str | None = inputs.get("log_path")
        package_dir: str | None = inputs.get("package_dir")  # None and "" both falsy in _collect_files

        matches = scan_with_yara(log_path=log_path, package_dir=package_dir)

        if not matches:
            actions.raise_finding(AnalysisFinding(
                analyzer_name=self.name,
                sample_id=sample_id,
                verdict="BENIGN",
                confidence=0.5,
                evidence=[],
                model_version="yara-builtin",
                raw_output=matches,
            ))
            return

        severities = [m.get("severity", "low") for m in matches]
        high_count = sum(1 for s in severities if s in ("high", "critical"))
        confidence = min(0.5 + 0.1 * len(matches) + 0.2 * high_count, 1.0)

        actions.raise_finding(AnalysisFinding(
            analyzer_name=self.name,
            sample_id=sample_id,
            verdict="MALICIOUS",
            confidence=confidence,
            evidence=[m.get("rule_name", "") for m in matches],
            model_version="yara-builtin",
            raw_output=matches,
        ))
