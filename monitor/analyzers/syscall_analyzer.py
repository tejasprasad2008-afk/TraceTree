from __future__ import annotations

from monitor.analyzers.base import AnalysisFinding, AnalyzerActions, SampleAnalyzer
from monitor.parser import parse_strace_log       # unchanged — monitor/parser.py:285
from monitor.signatures import load_signatures, match_signatures  # signatures.py:34,63


class SyscallAnalyzer(SampleAnalyzer):
    """Wraps parse_strace_log + load_signatures + match_signatures.

    raw_output["sig_matches"] must be forwarded to build_cascade_graph
    before RandomForestAnalyzer runs. See SampleAnalyzer ordering contract.
    """

    name = "syscall_parser"

    def analyze(self, sample_id: str, inputs: dict, actions: AnalyzerActions) -> None:
        log_path: str = inputs["log_path"]

        parsed_data = parse_strace_log(log_path)       # unchanged, parser.py:285

        sigs = load_signatures()                        # no path arg — uses default _SIGNATURES_PATH
        sig_matches = match_signatures(parsed_data, sigs)  # unchanged, signatures.py:63

        severity: float = parsed_data.get("total_severity_score", 0)
        verdict = "MALICIOUS" if (severity > 50 or sig_matches) else "UNCERTAIN"
        confidence = min(severity / 100.0, 1.0)

        actions.raise_finding(AnalysisFinding(
            analyzer_name=self.name,
            sample_id=sample_id,
            verdict=verdict,
            confidence=confidence,
            evidence=[str(m) for m in (sig_matches or [])],
            model_version="parser-v1",
            raw_output={"parsed": parsed_data, "sig_matches": sig_matches},
        ))
