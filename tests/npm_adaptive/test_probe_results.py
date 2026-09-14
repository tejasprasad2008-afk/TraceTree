from __future__ import annotations

from pathlib import Path

from npm_adaptive.probe_results import load_import_probe_results


def test_import_probe_results_keep_only_valid_bounded_outcomes(tmp_path: Path):
    (tmp_path / "import-results.ndjson").write_text(
        "\n".join(
            [
                '{"event":"import_probe","specifier":"demo","loader":"import","path":"index.mjs","outcome":"ok"}',
                '{"event":"import_probe","specifier":"demo","loader":"require","path":"index.cjs","outcome":"error","error":{"name":"Error","message":"missing dependency"}}',
                '{"event":"other","secret":"ignore"}',
                "not json",
            ]
        ),
        encoding="utf-8",
    )

    assert load_import_probe_results(tmp_path) == [
        {"specifier": "demo", "loader": "import", "path": "index.mjs", "outcome": "ok"},
        {
            "specifier": "demo",
            "loader": "require",
            "path": "index.cjs",
            "outcome": "error",
            "error": {"name": "Error", "message": "missing dependency"},
        },
    ]
