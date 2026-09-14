"""Best-effort static npm package mapping without evaluating package code."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .models import NpmArtifact, PackageEntrypoint, PackageExport, PackageMap

_SOURCE_SUFFIXES = {".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".tsx", ".jsx"}
_SOURCE_LIMIT = 2 * 1024 * 1024

_ESM_FUNCTION = re.compile(
    r"\bexport\s+(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)?\s*\(([^)]*)\)",
    re.MULTILINE,
)
_ESM_CLASS = re.compile(
    r"\bexport\s+(?:default\s+)?class\s+([A-Za-z_$][\w$]*)?\b", re.MULTILINE
)
_ESM_VALUE = re.compile(
    r"\bexport\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)\b", re.MULTILINE
)
_ESM_LIST = re.compile(r"\bexport\s*\{([^}]+)\}", re.MULTILINE)
_CJS_NAMED = re.compile(
    r"\b(?:module\.exports|exports)\.([A-Za-z_$][\w$]*)\s*=", re.MULTILINE
)
_CJS_DEFAULT_FUNCTION = re.compile(
    r"\bmodule\.exports\s*=\s*(?:async\s+)?function\b", re.MULTILINE
)
_TYPE_FUNCTION = re.compile(
    r"(?:export\s+)?(?:declare\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)",
    re.MULTILINE,
)


def build_package_map(artifact: NpmArtifact) -> PackageMap:
    """Build a static package map while preserving uncertainty explicitly."""

    manifest = dict(artifact.manifest)
    package_name = _string_value(manifest.get("name"), artifact.package_name)
    package_version = _string_value(manifest.get("version"), artifact.version)
    module_type = _string_value(manifest.get("type"), "commonjs")
    unsupported: List[str] = []

    entrypoints = _discover_entrypoints(artifact.package_dir, package_name, manifest, unsupported)
    exports: List[PackageExport] = []
    for entrypoint in entrypoints:
        exports.extend(_exports_for_entrypoint(artifact.package_dir, entrypoint, unsupported))

    exports = _merge_exports(exports)
    static_findings = _scan_static_tree(artifact.package_dir)
    unsupported.extend(_discover_unsupported_paths(artifact.package_dir, manifest))

    return PackageMap(
        artifact_sha256=artifact.sha256,
        package_name=package_name,
        package_version=package_version,
        module_type=module_type,
        entrypoints=entrypoints,
        exports=exports,
        static_findings=static_findings,
        unsupported_paths=sorted(set(unsupported)),
    )


def _discover_entrypoints(
    package_dir: Path,
    package_name: str,
    manifest: Dict[str, Any],
    unsupported: List[str],
) -> List[PackageEntrypoint]:
    export_field = manifest.get("exports")
    candidates: List[Tuple[str, Any, str]] = []

    if export_field is not None:
        if isinstance(export_field, dict) and any(key.startswith(".") for key in export_field):
            for subpath, target in export_field.items():
                if isinstance(subpath, str) and subpath.startswith("."):
                    candidates.append((subpath, target, "exports"))
        else:
            candidates.append((".", export_field, "exports"))
    else:
        main_target = manifest.get("main", "index.js")
        candidates.append((".", main_target, "main"))

    types_target = manifest.get("types") or manifest.get("typings")
    entrypoints: List[PackageEntrypoint] = []
    for subpath, target, source in candidates:
        resolved = _resolve_export_target(target)
        import_path = _safe_existing_path(package_dir, resolved.get("import"), unsupported)
        require_path = _safe_existing_path(package_dir, resolved.get("require"), unsupported)
        default_path = _safe_existing_path(package_dir, resolved.get("default"), unsupported)
        if import_path is None:
            import_path = default_path
        if require_path is None:
            require_path = default_path

        if not import_path and not require_path:
            unsupported.append(f"unresolved entrypoint: {subpath}")
        specifier = package_name if subpath == "." else f"{package_name}/{subpath[2:]}"
        types_path = _safe_existing_path(package_dir, types_target, unsupported)
        entrypoints.append(
            PackageEntrypoint(
                specifier=specifier,
                source=source,
                import_path=import_path,
                require_path=require_path,
                types_path=types_path,
                conditions=sorted(resolved.keys()),
            )
        )

    bin_field = manifest.get("bin")
    if bin_field:
        unsupported.append("CLI bin entrypoint requires a dedicated CLI profile")
    if manifest.get("browser"):
        unsupported.append("browser entrypoint requires a dedicated browser profile")
    return entrypoints


def _resolve_export_target(target: Any) -> Dict[str, str]:
    """Flatten the bounded import/require/default branches of an exports value."""

    result: Dict[str, str] = {}
    if isinstance(target, str):
        result["default"] = target
        return result
    if isinstance(target, list):
        for item in target:
            nested = _resolve_export_target(item)
            if nested:
                return nested
        return result
    if not isinstance(target, dict):
        return result

    for condition in ("import", "require", "default", "node"):
        if condition not in target:
            continue
        nested = _resolve_export_target(target[condition])
        if "default" in nested:
            result[condition] = nested["default"]
        elif condition in nested:
            result[condition] = nested[condition]
        for key, value in nested.items():
            if key in ("import", "require") and key not in result:
                result[key] = value
    return result


def _safe_existing_path(
    package_dir: Path, target: Any, unsupported: List[str]
) -> Optional[str]:
    if not isinstance(target, str):
        return None
    candidate = PurePosixPath(target)
    if candidate.is_absolute() or any(part == ".." for part in candidate.parts):
        unsupported.append(f"unsafe manifest path: {target}")
        return None
    relative = target[2:] if target.startswith("./") else target
    resolved = (package_dir / relative).resolve()
    try:
        resolved.relative_to(package_dir.resolve())
    except ValueError:
        unsupported.append(f"unsafe manifest path: {target}")
        return None
    if not resolved.is_file():
        unsupported.append(f"manifest target not present in tarball: {target}")
        return None
    return resolved.relative_to(package_dir).as_posix()


def _exports_for_entrypoint(
    package_dir: Path, entrypoint: PackageEntrypoint, unsupported: List[str]
) -> List[PackageExport]:
    path_candidates = [entrypoint.import_path, entrypoint.require_path]
    exports: List[PackageExport] = []
    for relative_path in dict.fromkeys(path for path in path_candidates if path):
        source_path = package_dir / relative_path
        if source_path.suffix not in _SOURCE_SUFFIXES:
            unsupported.append(f"non-JavaScript entrypoint: {relative_path}")
            continue
        if source_path.stat().st_size > _SOURCE_LIMIT:
            unsupported.append(f"entrypoint too large for static mapping: {relative_path}")
            continue
        text = _read_source(source_path)
        if text is None:
            unsupported.append(f"entrypoint is not readable text: {relative_path}")
            continue
        exports.extend(_parse_exports(entrypoint.specifier, relative_path, text))
        exports.extend(_type_hints(entrypoint, package_dir, relative_path))
    return exports


def _parse_exports(entrypoint: str, source_path: str, text: str) -> List[PackageExport]:
    discovered: List[PackageExport] = []
    for match in _ESM_FUNCTION.finditer(text):
        name = match.group(1) or "default"
        discovered.append(
            PackageExport(
                entrypoint=entrypoint,
                name=name,
                kind="function",
                source_path=source_path,
                confidence="high",
                parameters=_parameters(match.group(2)),
            )
        )
    for match in _ESM_CLASS.finditer(text):
        discovered.append(
            PackageExport(
                entrypoint=entrypoint,
                name=match.group(1) or "default",
                kind="class",
                source_path=source_path,
                confidence="high",
            )
        )
    for match in _ESM_VALUE.finditer(text):
        discovered.append(
            PackageExport(
                entrypoint=entrypoint,
                name=match.group(1),
                kind="value",
                source_path=source_path,
                confidence="high",
            )
        )
    for match in _ESM_LIST.finditer(text):
        for item in match.group(1).split(","):
            name = item.strip().split(" as ")[-1].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", name):
                discovered.append(
                    PackageExport(
                        entrypoint=entrypoint,
                        name=name,
                        kind="unknown",
                        source_path=source_path,
                        confidence="medium",
                    )
                )
    for match in _CJS_NAMED.finditer(text):
        discovered.append(
            PackageExport(
                entrypoint=entrypoint,
                name=match.group(1),
                kind="unknown",
                source_path=source_path,
                confidence="medium",
            )
        )
    if _CJS_DEFAULT_FUNCTION.search(text):
        discovered.append(
            PackageExport(
                entrypoint=entrypoint,
                name="default",
                kind="function",
                source_path=source_path,
                confidence="medium",
            )
        )
    return discovered


def _type_hints(
    entrypoint: PackageEntrypoint, package_dir: Path, source_path: str
) -> List[PackageExport]:
    if not entrypoint.types_path:
        return []
    type_path = package_dir / entrypoint.types_path
    if type_path.stat().st_size > _SOURCE_LIMIT:
        return []
    text = _read_source(type_path)
    if text is None:
        return []
    return [
        PackageExport(
            entrypoint=entrypoint.specifier,
            name=match.group(1),
            kind="function",
            source_path=source_path,
            confidence="type-hint",
            parameters=_parameters(match.group(2)),
        )
        for match in _TYPE_FUNCTION.finditer(text)
    ]


def _merge_exports(exports: Iterable[PackageExport]) -> List[PackageExport]:
    merged: Dict[Tuple[str, str], PackageExport] = {}
    rank = {"high": 4, "medium": 3, "type-hint": 2, "low": 1}
    for export in exports:
        key = (export.entrypoint, export.name)
        current = merged.get(key)
        if current is None or rank.get(export.confidence, 0) > rank.get(current.confidence, 0):
            merged[key] = export
        elif current.parameters == [] and export.parameters:
            merged[key] = PackageExport(
                entrypoint=current.entrypoint,
                name=current.name,
                kind=current.kind,
                source_path=current.source_path,
                confidence=current.confidence,
                parameters=export.parameters,
            )
    return sorted(merged.values(), key=lambda item: (item.entrypoint, item.name))


def _scan_static_tree(package_dir: Path) -> List[Dict[str, Any]]:
    """Reuse TraceTree's existing static YARA layer when available."""

    try:
        from monitor.yara import scan_with_yara

        findings = scan_with_yara(package_dir=str(package_dir))
        return findings if isinstance(findings, list) else []
    except Exception:
        # Static scan availability must be reflected by a future finding, not
        # make artifact mapping fail.  The package map still records all paths.
        return []


def _discover_unsupported_paths(package_dir: Path, manifest: Dict[str, Any]) -> List[str]:
    unsupported: List[str] = []
    if any(path.suffix == ".node" for path in package_dir.rglob("*.node")):
        unsupported.append("native addon present; JavaScript coverage is incomplete")
    if manifest.get("gypfile"):
        unsupported.append("node-gyp package requires a dedicated native-addon policy")
    if manifest.get("type") not in (None, "commonjs", "module"):
        unsupported.append(f"unknown package type: {manifest.get('type')}")
    return unsupported


def _read_source(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _parameters(raw: str) -> List[str]:
    return [item.strip().split("=")[0].strip() for item in raw.split(",") if item.strip()]


def _string_value(value: Any, fallback: str) -> str:
    return value if isinstance(value, str) and value else fallback
