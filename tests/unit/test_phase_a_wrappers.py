"""Phase A parity tests: wrapper output must match direct function calls exactly.

LegsAnalyzer requires a live Ollama connection and is excluded from this suite.
Run it manually or in an integration environment with Ollama available.
"""
import sys
import os

import pytest

# Resolve repo root so imports work regardless of invocation directory
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from monitor.analyzers.base import AnalyzerActions
from monitor.analyzers.yara_analyzer import YaraAnalyzer
from monitor.analyzers.syscall_analyzer import SyscallAnalyzer
from monitor.analyzers.rf_analyzer import RandomForestAnalyzer

from monitor.yara import scan_with_yara
from monitor.parser import parse_strace_log
from monitor.signatures import load_signatures, match_signatures
from ml.detector import detect_anomaly
from graph.builder import build_cascade_graph

LOGS_DIR = os.path.join(REPO_ROOT, "logs")
MALICIOUS_LOG = os.path.join(LOGS_DIR, "malicious_pkg_pip_strace.log")
BENIGN_LOG = os.path.join(LOGS_DIR, "benign_pkg_pip_strace.log")


def _require_log(path: str):
    if not os.path.exists(path):
        pytest.skip(f"log not found: {path}")


# --------------------------------------------------------------------------- #
# YaraAnalyzer
# --------------------------------------------------------------------------- #

class TestYaraAnalyzer:
    def _run(self, log_path: str, sample_id: str = "test"):
        actions = AnalyzerActions(bus=None)
        YaraAnalyzer().analyze(sample_id, {"log_path": log_path}, actions)
        assert len(actions.findings) == 1
        return actions.findings[0]

    def test_malicious_raw_output_matches_direct(self):
        _require_log(MALICIOUS_LOG)
        direct = scan_with_yara(log_path=MALICIOUS_LOG, package_dir=None)
        finding = self._run(MALICIOUS_LOG)
        assert finding.raw_output == direct, (
            f"YaraAnalyzer raw_output diverged from direct call.\n"
            f"direct={direct}\nwrapper={finding.raw_output}"
        )

    def test_benign_raw_output_matches_direct(self):
        _require_log(BENIGN_LOG)
        direct = scan_with_yara(log_path=BENIGN_LOG, package_dir=None)
        finding = self._run(BENIGN_LOG)
        assert finding.raw_output == direct

    def test_malicious_verdict(self):
        _require_log(MALICIOUS_LOG)
        finding = self._run(MALICIOUS_LOG)
        direct = scan_with_yara(log_path=MALICIOUS_LOG, package_dir=None)
        expected_verdict = "MALICIOUS" if direct else "BENIGN"
        assert finding.verdict == expected_verdict

    def test_no_package_dir_defaults_none(self):
        """Confirm omitting package_dir from inputs uses None, not ''."""
        _require_log(BENIGN_LOG)
        actions = AnalyzerActions()
        YaraAnalyzer().analyze("t", {"log_path": BENIGN_LOG}, actions)
        # If this runs without error, None handling is correct
        assert len(actions.findings) == 1


# --------------------------------------------------------------------------- #
# SyscallAnalyzer
# --------------------------------------------------------------------------- #

class TestSyscallAnalyzer:
    def _run(self, log_path: str, sample_id: str = "test"):
        actions = AnalyzerActions(bus=None)
        SyscallAnalyzer().analyze(sample_id, {"log_path": log_path}, actions)
        assert len(actions.findings) == 1
        return actions.findings[0]

    def test_malicious_raw_output_matches_direct(self):
        _require_log(MALICIOUS_LOG)
        parsed_direct = parse_strace_log(MALICIOUS_LOG)
        sigs = load_signatures()
        sig_matches_direct = match_signatures(parsed_direct, sigs)

        finding = self._run(MALICIOUS_LOG)
        assert finding.raw_output["parsed"] == parsed_direct, "parsed_data diverged"
        assert finding.raw_output["sig_matches"] == sig_matches_direct, "sig_matches diverged"

    def test_benign_raw_output_matches_direct(self):
        _require_log(BENIGN_LOG)
        parsed_direct = parse_strace_log(BENIGN_LOG)
        sigs = load_signatures()
        sig_matches_direct = match_signatures(parsed_direct, sigs)

        finding = self._run(BENIGN_LOG)
        assert finding.raw_output["parsed"] == parsed_direct
        assert finding.raw_output["sig_matches"] == sig_matches_direct

    def test_sig_matches_available_for_graph_builder(self):
        """sig_matches from raw_output must be passable to build_cascade_graph."""
        _require_log(MALICIOUS_LOG)
        finding = self._run(MALICIOUS_LOG)
        parsed = finding.raw_output["parsed"]
        sig_matches = finding.raw_output["sig_matches"]
        # build_cascade_graph should not raise with these values
        graph_data = build_cascade_graph(parsed, sig_matches)
        assert graph_data is not None


# --------------------------------------------------------------------------- #
# RandomForestAnalyzer
# --------------------------------------------------------------------------- #

class TestRandomForestAnalyzer:
    def _inputs(self, log_path: str) -> dict:
        parsed = parse_strace_log(log_path)
        sigs = load_signatures()
        sig_matches = match_signatures(parsed, sigs)
        graph_data = build_cascade_graph(parsed, sig_matches)
        return {"graph_data": graph_data, "parsed_data": parsed}

    def _run(self, log_path: str, sample_id: str = "test"):
        inputs = self._inputs(log_path)
        actions = AnalyzerActions(bus=None)
        RandomForestAnalyzer().analyze(sample_id, inputs, actions)
        assert len(actions.findings) == 1
        return actions.findings[0], inputs

    def test_malicious_raw_output_matches_direct(self):
        _require_log(MALICIOUS_LOG)
        finding, inputs = self._run(MALICIOUS_LOG)
        direct = detect_anomaly(inputs["graph_data"], inputs["parsed_data"])
        assert finding.raw_output == direct, (
            f"RandomForestAnalyzer raw_output diverged.\n"
            f"direct={direct}\nwrapper={finding.raw_output}"
        )

    def test_benign_raw_output_matches_direct(self):
        _require_log(BENIGN_LOG)
        finding, inputs = self._run(BENIGN_LOG)
        direct = detect_anomaly(inputs["graph_data"], inputs["parsed_data"])
        assert finding.raw_output == direct

    def test_malicious_verdict_matches_direct(self):
        _require_log(MALICIOUS_LOG)
        finding, inputs = self._run(MALICIOUS_LOG)
        direct = detect_anomaly(inputs["graph_data"], inputs["parsed_data"])
        expected = "MALICIOUS" if direct.is_malicious else "BENIGN"
        assert finding.verdict == expected

    def test_benign_verdict_matches_direct(self):
        _require_log(BENIGN_LOG)
        finding, inputs = self._run(BENIGN_LOG)
        direct = detect_anomaly(inputs["graph_data"], inputs["parsed_data"])
        expected = "MALICIOUS" if direct.is_malicious else "BENIGN"
        assert finding.verdict == expected

    def test_confidence_is_ml_probability(self):
        _require_log(MALICIOUS_LOG)
        finding, inputs = self._run(MALICIOUS_LOG)
        direct = detect_anomaly(inputs["graph_data"], inputs["parsed_data"])
        # AnomalyVerdict: ml_probability is attribute, risk_score is tuple[1]
        expected_conf = float(direct.ml_probability) if direct.ml_probability is not None else float(direct.risk_score) / 100.0
        assert abs(finding.confidence - expected_conf) < 1e-9
