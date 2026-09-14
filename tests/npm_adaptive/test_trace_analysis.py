from __future__ import annotations

from pathlib import Path

from npm_adaptive.trace_analysis import analyze_trace


def test_trace_analysis_reports_missing_trace_without_claiming_clean(tmp_path: Path):
    evidence = analyze_trace(None, tmp_path)

    assert evidence.parsed_data == {}
    assert evidence.warnings == ["strace trace was not produced"]
    assert evidence.as_dict()["event_count"] == 0
