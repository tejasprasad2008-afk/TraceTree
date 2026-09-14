from graph.builder import build_cascade_graph
from orchestrator.ai_mesh import AIMeshOrchestrator


def test_ordinary_file_reads_do_not_contribute_to_graph_severity():
    parsed = {
        "processes": {"1": {"command": "pip"}},
        "parent_map": {},
        "events": [
            {
                "pid": "1",
                "type": "openat",
                "target": f"/usr/lib/python3.9/module_{index}.py",
                "severity": 0.0,
                "details": {"sensitive": False},
            }
            for index in range(40)
        ],
    }

    graph = build_cascade_graph(parsed)

    assert graph["stats"]["file_read_count"] == 40
    assert graph["stats"]["total_severity"] == 0.0


def test_ai_jury_clears_a_target_with_no_concrete_detection_without_llm():
    result = AIMeshOrchestrator().triage_false_positive(
        {
            "rule_name": "NO_CONCRETE_DETECTION",
            "all_signatures": [],
            "temporal_patterns": [],
            "concrete_evidence_count": 0,
            "severity": 0.0,
        },
        {"target_name": "LOGS.txt", "type": "pip"},
    )

    assert result.is_false_positive()
    assert "Target identity" in result.reasoning
