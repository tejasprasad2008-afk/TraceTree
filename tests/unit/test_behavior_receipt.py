import pytest
from orchestrator.ai_mesh import build_behavior_receipt, AIMeshOrchestrator
from ml.detector import AnomalyVerdict

def test_build_behavior_receipt_structure():
    # Setup dummy objects
    verdict = AnomalyVerdict(is_malicious=False, risk_score=15.0, ml_probability=15.0, reasons=["Normal execution pattern"])
    graph_data = {
        "stats": {
            "node_count": 5,
            "edge_count": 4,
            "network_conn_count": 0,
            "file_read_count": 3,
            "file_write_count": 1,
            "total_severity": 1.0,
            "suspicious_network_count": 0,
            "sensitive_file_count": 0,
            "max_severity": 1.0,
        }
    }
    parsed_data = {
        "events": [
            {"type": "clone", "pid": 101},
            {"type": "write", "pid": 100},
        ],
        "stats": {}
    }
    sig_matches = [{"name": "DUMMY_SIGNATURE", "severity": 4.0}]
    temp_patterns = []
    yara_matches = []

    # Run
    receipt = build_behavior_receipt(
        target="example-package@1.2.3",
        target_type="npm",
        verdict=verdict,
        graph_data=graph_data,
        parsed_data=parsed_data,
        sig_matches=sig_matches,
        temp_patterns=temp_patterns,
        yara_matches=yara_matches,
        log_path=None,
        controlled_network=False,
    )

    # Asserts
    assert receipt["schema"] == "tracetree.behavior_receipt.v1"
    assert receipt["target"]["name"] == "example-package"
    assert receipt["target"]["version"] == "1.2.3"
    assert receipt["target"]["type"] == "npm"
    assert receipt["observed_behavior"]["process_count"] == 2  # 1 clone + 1 = 2
    assert receipt["observed_behavior"]["file_write_count"] == 1
    assert receipt["verdict"]["decision"] == "clean"
    assert receipt["verdict"]["confidence"] == 0.15
    assert receipt["verdict"]["review_required"] is True  # True because matched_sigs > 0
    assert receipt["privacy"]["raw_syscalls_included"] is False


def test_analyst_report_generation_mocked(monkeypatch):
    # Setup orchestrator
    orchestrator = AIMeshOrchestrator(dry_run=True)
    
    # Mock LLM call to return expected schema dict
    def mock_invoke_llm(self, prompt):
        return {
            "summary": "This package is clean.",
            "risk_assessment": "Low risk.",
            "recommendation": "SAFE"
        }
    
    monkeypatch.setattr(AIMeshOrchestrator, "_invoke_llm", mock_invoke_llm)
    
    receipt = {
        "schema": "tracetree.behavior_receipt.v1",
        "verdict": {"decision": "clean"}
    }
    
    report = orchestrator.generate_analyst_report(receipt)
    assert report["summary"] == "This package is clean."
    assert report["risk_assessment"] == "Low risk."
    assert report["recommendation"] == "SAFE"
