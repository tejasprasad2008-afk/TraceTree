"""Normalise native Node V8 coverage without rewriting target source."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import unquote, urlparse

from .models import CoverageReport, PackageMap


def summarize_v8_coverage(
    coverage_dir: Path,
    package_map: PackageMap,
    target_root: Optional[Path] = None,
) -> CoverageReport:
    """Summarise one or more V8 coverage snapshots for the target package.

    ``v8.takeCoverage()`` can write several JSON files and resets counters
    between snapshots.  A function or file is therefore considered observed if
    it has a positive execution count in *any* valid snapshot.
    """

    root = Path(coverage_dir)
    source_paths = _target_source_paths(package_map)
    executed_files: Set[str] = set()
    executed_functions: Set[str] = set()
    parse_errors: List[str] = []

    if not root.is_dir():
        parse_errors.append("V8 coverage directory was not produced")
    else:
        for coverage_file in sorted(root.glob("*.json")):
            try:
                payload = json.loads(coverage_file.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                parse_errors.append(f"invalid V8 coverage file: {coverage_file.name}: {exc}")
                continue
            _merge_snapshot(
                payload,
                source_paths,
                target_root,
                executed_files,
                executed_functions,
            )

    exercised_exports: Set[str] = set()
    uncovered_exports: Set[str] = set()
    for export in package_map.exports:
        identifier = f"{export.entrypoint}:{export.name}"
        source_path = export.source_path
        if source_path in executed_files and _export_name_was_executed(
            export.name, executed_functions
        ):
            exercised_exports.add(identifier)
        else:
            uncovered_exports.add(identifier)

    return CoverageReport(
        target_files=sorted(source_paths),
        executed_files=sorted(executed_files),
        executed_function_names=sorted(executed_functions),
        exercised_exports=sorted(exercised_exports),
        uncovered_exports=sorted(uncovered_exports),
        parse_errors=parse_errors,
    )


def merge_coverage_reports(
    package_map: PackageMap, reports: Iterable[CoverageReport]
) -> CoverageReport:
    """Union coverage from independent fresh attempts for the same artifact.

    Each attempt stays separately reviewable.  The merged view answers only
    which statically mapped exports have been exercised across them; it does
    not imply that all branches or environment-dependent conditions were run.
    """

    collected = list(reports)
    target_files = _target_source_paths(package_map)
    executed_files = {
        file_name
        for report in collected
        for file_name in report.executed_files
        if file_name in target_files
    }
    executed_functions = {
        function_name
        for report in collected
        for function_name in report.executed_function_names
    }
    exercised_exports = {
        identifier
        for report in collected
        for identifier in report.exercised_exports
    }
    all_exports = {f"{export.entrypoint}:{export.name}" for export in package_map.exports}
    parse_errors = sorted(
        {
            error
            for report in collected
            for error in report.parse_errors
        }
    )
    return CoverageReport(
        target_files=sorted(target_files),
        executed_files=sorted(executed_files),
        executed_function_names=sorted(executed_functions),
        exercised_exports=sorted(exercised_exports),
        uncovered_exports=sorted(all_exports - exercised_exports),
        parse_errors=parse_errors,
    )


def _export_name_was_executed(export_name: str, executed_functions: Set[str]) -> bool:
    """Match V8's CJS-qualified names to static public export names."""

    for function_name in executed_functions:
        if function_name == export_name:
            return True
        if export_name != "default" and function_name.endswith(f".{export_name}"):
            return True
    return False


def _target_source_paths(package_map: PackageMap) -> Set[str]:
    paths: Set[str] = set()
    for entrypoint in package_map.entrypoints:
        if entrypoint.import_path:
            paths.add(entrypoint.import_path)
        if entrypoint.require_path:
            paths.add(entrypoint.require_path)
    for export in package_map.exports:
        if export.source_path:
            paths.add(export.source_path)
    return paths


def _merge_snapshot(
    payload: Any,
    target_source_paths: Set[str],
    target_root: Optional[Path],
    executed_files: Set[str],
    executed_functions: Set[str],
) -> None:
    scripts = payload.get("result") if isinstance(payload, dict) else None
    if not isinstance(scripts, list):
        return

    for script in scripts:
        if not isinstance(script, dict):
            continue
        source_path = _match_target_source(
            script.get("url"), target_source_paths, target_root
        )
        if source_path is None:
            continue
        functions = script.get("functions")
        if not isinstance(functions, list):
            continue
        for function in functions:
            if not isinstance(function, dict) or not _was_executed(function):
                continue
            executed_files.add(source_path)
            function_name = function.get("functionName")
            if isinstance(function_name, str) and function_name:
                executed_functions.add(function_name)


def _was_executed(function: Dict[str, Any]) -> bool:
    ranges = function.get("ranges")
    if not isinstance(ranges, list):
        return False
    return any(
        isinstance(coverage_range, dict)
        and isinstance(coverage_range.get("count"), int)
        and coverage_range["count"] > 0
        for coverage_range in ranges
    )


def _match_target_source(
    raw_url: Any,
    target_source_paths: Set[str],
    target_root: Optional[Path],
) -> Optional[str]:
    if not isinstance(raw_url, str) or not raw_url:
        return None
    candidate = _path_from_v8_url(raw_url)
    if candidate is None:
        return None

    if target_root is not None:
        try:
            relative = candidate.resolve().relative_to(Path(target_root).resolve())
            normalized = relative.as_posix()
            if normalized in target_source_paths:
                return normalized
        except (OSError, ValueError):
            pass

    normalized_candidate = candidate.as_posix()
    matches = [
        source_path
        for source_path in target_source_paths
        if normalized_candidate == source_path
        or normalized_candidate.endswith("/" + source_path)
    ]
    return matches[0] if len(matches) == 1 else None


def _path_from_v8_url(raw_url: str) -> Optional[Path]:
    parsed = urlparse(raw_url)
    if parsed.scheme == "file":
        return Path(unquote(parsed.path))
    if parsed.scheme:
        return None
    return Path(raw_url)
