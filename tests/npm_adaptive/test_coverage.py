from __future__ import annotations

import json
from pathlib import Path

from npm_adaptive.coverage import merge_coverage_reports, summarize_v8_coverage
from npm_adaptive.models import CoverageReport, PackageEntrypoint, PackageExport, PackageMap


def _package_map() -> PackageMap:
    return PackageMap(
        artifact_sha256="b" * 64,
        package_name="coverage-pkg",
        package_version="1.0.0",
        module_type="module",
        entrypoints=[
            PackageEntrypoint(
                specifier="coverage-pkg",
                source="exports",
                import_path="dist/index.mjs",
            )
        ],
        exports=[
            PackageExport(
                entrypoint="coverage-pkg",
                name="covered",
                kind="function",
                source_path="dist/index.mjs",
                confidence="high",
            ),
            PackageExport(
                entrypoint="coverage-pkg",
                name="uncovered",
                kind="function",
                source_path="dist/index.mjs",
                confidence="high",
            ),
        ],
        static_findings=[],
        unsupported_paths=[],
    )


def _write_snapshot(path: Path, functions):
    path.write_text(
        json.dumps(
            {
                "result": [
                    {
                        "url": "file:///work/package/dist/index.mjs",
                        "functions": functions,
                    },
                    {
                        "url": "file:///work/node_modules/dependency/index.js",
                        "functions": [
                            {"functionName": "dependency", "ranges": [{"count": 9}]}
                        ],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )


def test_v8_coverage_accumulates_snapshots_and_filters_dependencies(tmp_path: Path):
    coverage_dir = tmp_path / "v8"
    coverage_dir.mkdir()
    _write_snapshot(
        coverage_dir / "coverage-a.json",
        [{"functionName": "covered", "ranges": [{"count": 1}]}],
    )
    _write_snapshot(
        coverage_dir / "coverage-b.json",
        [{"functionName": "uncovered", "ranges": [{"count": 0}]}],
    )

    report = summarize_v8_coverage(coverage_dir, _package_map())

    assert report.target_files == ["dist/index.mjs"]
    assert report.executed_files == ["dist/index.mjs"]
    assert report.executed_function_names == ["covered"]
    assert report.exercised_exports == ["coverage-pkg:covered"]
    assert report.uncovered_exports == ["coverage-pkg:uncovered"]
    assert report.file_ratio == 1.0


def test_v8_coverage_reports_missing_artifact(tmp_path: Path):
    report = summarize_v8_coverage(tmp_path / "missing", _package_map())

    assert report.executed_files == []
    assert report.uncovered_exports == ["coverage-pkg:covered", "coverage-pkg:uncovered"]
    assert report.parse_errors == ["V8 coverage directory was not produced"]


def test_v8_coverage_normalises_commonjs_qualified_function_names(tmp_path: Path):
    coverage_dir = tmp_path / "v8"
    coverage_dir.mkdir()
    _write_snapshot(
        coverage_dir / "coverage.json",
        [{"functionName": "exports.covered", "ranges": [{"count": 1}]}],
    )

    report = summarize_v8_coverage(coverage_dir, _package_map())

    assert report.exercised_exports == ["coverage-pkg:covered"]


def test_coverage_merges_independent_fresh_attempts():
    import_report = CoverageReport(
        target_files=["dist/index.mjs"],
        executed_files=["dist/index.mjs"],
        executed_function_names=["covered"],
        exercised_exports=["coverage-pkg:covered"],
        uncovered_exports=["coverage-pkg:uncovered"],
    )
    harness_report = CoverageReport(
        target_files=["dist/index.mjs"],
        executed_files=["dist/index.mjs"],
        executed_function_names=["uncovered"],
        exercised_exports=["coverage-pkg:uncovered"],
        uncovered_exports=["coverage-pkg:covered"],
    )

    merged = merge_coverage_reports(_package_map(), [import_report, harness_report])

    assert merged.exercised_exports == ["coverage-pkg:covered", "coverage-pkg:uncovered"]
    assert merged.uncovered_exports == []
