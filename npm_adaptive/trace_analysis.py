"""Reusable, side-effect-free adapter for TraceTree trace evidence stages."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class TraceEvidence:
    """Normalised findings derived from one adaptive strace artifact."""

    trace_path: Optional[Path]
    parsed_data: Dict[str, Any]
    signature_matches: List[Dict[str, Any]]
    temporal_patterns: List[Dict[str, Any]]
    yara_matches: List[Dict[str, Any]]
    ngram_data: Dict[str, Any]
    warnings: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "trace_path": str(self.trace_path) if self.trace_path else None,
            "event_count": len(self.parsed_data.get("events", [])),
            "flags": list(self.parsed_data.get("flags", [])),
            "signature_matches": list(self.signature_matches),
            "temporal_patterns": list(self.temporal_patterns),
            "yara_matches": list(self.yara_matches),
            "ngram": {
                "total_syscalls": self.ngram_data.get("total_syscalls", 0),
                "fingerprint": self.ngram_data.get("fingerprint", ""),
            },
            "warnings": list(self.warnings),
        }


def analyze_trace(trace_path: Optional[Path], package_dir: Path) -> TraceEvidence:
    """Run existing parser/signature/YARA/n-gram stages on one trace.

    This adapter deliberately does not decide a clean/malicious verdict and
    does not call an LLM.  It lets both legacy and adaptive paths share the
    same deterministic evidence collectors while callers preserve their own
    lifecycle and confidence semantics.
    """

    if trace_path is None or not Path(trace_path).is_file():
        return TraceEvidence(
            trace_path=trace_path,
            parsed_data={},
            signature_matches=[],
            temporal_patterns=[],
            yara_matches=[],
            ngram_data={},
            warnings=["strace trace was not produced"],
        )

    from monitor.ngrams import detect_suspicious_ngrams, extract_ngrams
    from monitor.parser import parse_strace_log
    from monitor.signatures import load_signatures, match_signatures
    from monitor.timeline import detect_temporal_patterns
    from monitor.yara import scan_with_yara

    trace = Path(trace_path)
    warnings: List[str] = []
    parsed_data: Dict[str, Any] = {}
    signature_matches: List[Dict[str, Any]] = []
    temporal_patterns: List[Dict[str, Any]] = []
    yara_matches: List[Dict[str, Any]] = []
    ngram_data: Dict[str, Any] = {}

    try:
        parsed_data = parse_strace_log(str(trace))
    except Exception as exc:
        warnings.append(f"strace parser failed: {exc}")
        return TraceEvidence(
            trace_path=trace,
            parsed_data={},
            signature_matches=[],
            temporal_patterns=[],
            yara_matches=[],
            ngram_data={},
            warnings=warnings,
        )

    try:
        signature_matches = match_signatures(parsed_data, load_signatures())
    except Exception as exc:
        warnings.append(f"signature analysis failed: {exc}")
    try:
        if parsed_data.get("has_timestamps"):
            temporal_patterns = detect_temporal_patterns(parsed_data)
    except Exception as exc:
        warnings.append(f"timeline analysis failed: {exc}")
    try:
        yara_matches = scan_with_yara(log_path=str(trace), package_dir=str(package_dir))
    except Exception as exc:
        warnings.append(f"YARA analysis failed: {exc}")
    try:
        ngram_data = extract_ngrams(str(trace), n=3)
        suspicious = detect_suspicious_ngrams(ngram_data)
        if suspicious:
            parsed_data.setdefault("stats", {})["suspicious_ngram_count"] = len(suspicious)
    except Exception as exc:
        warnings.append(f"n-gram analysis failed: {exc}")

    return TraceEvidence(
        trace_path=trace,
        parsed_data=parsed_data,
        signature_matches=signature_matches,
        temporal_patterns=temporal_patterns,
        yara_matches=yara_matches,
        ngram_data=ngram_data,
        warnings=warnings,
    )
