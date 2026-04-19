"""
SARIF (Static Analysis Results Interchange Format) report export for TraceTree.

Generates SARIF 2.1.0 JSON reports from TraceTree analysis results, enabling
integration with CI/CD pipelines, GitHub Security tab, Azure DevOps, and
other tools that consume SARIF.

Usage:
    from monitor.sarif import generate_sarif_report

    sarif_json = generate_sarif_report(
        target="requests",
        parsed_data=parsed_data,
        graph_data=graph_data,
        signature_matches=sig_matches,
        temporal_patterns=temp_patterns,
        yara_matches=yara_matches,
        ngram_data=ngram_data,
        is_malicious=True,
        confidence=85.5,
    )
"""

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

# Patterns that indicate sensitive data — redact these from SARIF output
_SENSITIVE_PATTERNS = [
    # AWS keys
    (re.compile(r'AKIA[0-9A-Z]{16}'), '[REDACTED:AWS_ACCESS_KEY]'),
    # Private keys
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA )?PRIVATE KEY-----', re.DOTALL), '[REDACTED:PRIVATE_KEY]'),
    # SSH private keys (single line variant)
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'), '[REDACTED:PRIVATE_KEY]'),
    # Base64 blobs > 100 chars (likely encoded secrets/payloads)
    (re.compile(r'[A-Za-z0-9+/]{100,}={0,2}'), '[REDACTED:BASE64_BLOB]'),
    # Generic secrets in key=value format
    (re.compile(r'(?:secret|password|token|api_key|apikey|access_key)\s*[=:]\s*\S+', re.IGNORECASE), '[REDACTED:SECRET]'),
]


def _sanitize_sarif_value(value: Any) -> Any:
    """Recursively sanitize SARIF output to remove sensitive data."""
    if isinstance(value, str):
        result = value
        for pattern, replacement in _SENSITIVE_PATTERNS:
            result = pattern.sub(replacement, result)
        return result
    elif isinstance(value, list):
        return [_sanitize_sarif_value(item) for item in value]
    elif isinstance(value, dict):
        return {k: _sanitize_sarif_value(v) for k, v in value.items()}
    return value

# --------------------------------------------------------------------------- #
#  Public API
# --------------------------------------------------------------------------- #


def generate_sarif_report(
    target: str,
    parsed_data: Dict[str, Any],
    graph_data: Dict[str, Any],
    signature_matches: Optional[List[Dict[str, Any]]] = None,
    temporal_patterns: Optional[List[Dict[str, Any]]] = None,
    yara_matches: Optional[List[Dict[str, Any]]] = None,
    ngram_data: Optional[Dict[str, Any]] = None,
    is_malicious: bool = False,
    confidence: float = 0.0,
    output_path: Optional[str] = None,
) -> str:
    """
    Generate a SARIF 2.1.0 report from TraceTree analysis results.

    Args:
        target: The package/file that was analyzed.
        parsed_data: Output of monitor.parser.parse_strace_log().
        graph_data: Output of graph.builder.build_cascade_graph().
        signature_matches: List of matched behavioral signatures.
        temporal_patterns: List of detected temporal patterns.
        yara_matches: List of YARA rule matches.
        ngram_data: N-gram fingerprint data.
        is_malicious: Final verdict.
        confidence: Confidence score (0-100).
        output_path: If provided, write the SARIF JSON to this path.

    Returns:
        SARIF JSON string.
    """
    run = _build_sarif_run(
        target=target,
        parsed_data=parsed_data,
        graph_data=graph_data,
        signature_matches=signature_matches or [],
        temporal_patterns=temporal_patterns or [],
        yara_matches=yara_matches or [],
        ngram_data=ngram_data or {},
        is_malicious=is_malicious,
        confidence=confidence,
    )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }

    # Sanitize to remove sensitive data (credentials, keys, base64 blobs)
    sarif = _sanitize_sarif_value(sarif)

    sarif_json = json.dumps(sarif, indent=2, default=str)

    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(sarif_json, encoding="utf-8")

    return sarif_json


# --------------------------------------------------------------------------- #
#  SARIF run builder
# --------------------------------------------------------------------------- #


def _build_sarif_run(
    target: str,
    parsed_data: Dict[str, Any],
    graph_data: Dict[str, Any],
    signature_matches: List[Dict[str, Any]],
    temporal_patterns: List[Dict[str, Any]],
    yara_matches: List[Dict[str, Any]],
    ngram_data: Dict[str, Any],
    is_malicious: bool,
    confidence: float,
) -> Dict[str, Any]:
    """Build a single SARIF run dict."""
    results: List[Dict[str, Any]] = []

    # --- Signature match results ---
    for sig in signature_matches:
        results.append({
            "ruleId": f"signature/{sig['name']}",
            "ruleIndex": _rule_index("signature", sig["name"]),
            "level": _severity_to_sarif_level(sig.get("severity", 5)),
            "message": {
                "text": f"Behavioral signature matched: {sig['name']} — {sig['description']}",
            },
            "properties": {
                "evidence": sig.get("evidence", []),
                "confidence_boost": sig.get("confidence_boost", 0.0),
            },
        })

    # --- Temporal pattern results ---
    for tp in temporal_patterns:
        results.append({
            "ruleId": f"temporal/{tp['pattern_name']}",
            "ruleIndex": _rule_index("temporal", tp["pattern_name"]),
            "level": _severity_to_sarif_level(tp.get("severity", 5)),
            "message": {
                "text": f"Temporal pattern detected: {tp['pattern_name']} — {tp.get('description', '')}",
            },
            "properties": {
                "events": tp.get("events", []),
                "time_span_ms": tp.get("time_span_ms", 0),
            },
        })

    # --- YARA match results ---
    for ym in yara_matches:
        results.append({
            "ruleId": f"yara/{ym['rule_name']}",
            "ruleIndex": _rule_index("yara", ym["rule_name"]),
            "level": _severity_to_sarif_level(_yara_severity_to_num(ym.get("severity", "medium"))),
            "message": {
                "text": f"YARA rule matched: {ym['rule_name']} — {ym['description']}",
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": ym.get("file_path", ""),
                    },
                },
            }],
            "properties": {
                "matched_strings": ym.get("matched_strings", []),
            },
        })

    # --- N-gram suspicious pattern results ---
    if ngram_data:
        from monitor.ngrams import detect_suspicious_ngrams
        suspicious_ng = detect_suspicious_ngrams(ngram_data)
        for sg in suspicious_ng:
            results.append({
                "ruleId": f"ngram/{sg['ngram']}",
                "ruleIndex": _rule_index("ngram", sg["ngram"]),
                "level": "error",
                "message": {
                    "text": f"Suspicious syscall n-gram: {sg['ngram']} — {sg['description']} (count: {sg['count']})",
                },
                "properties": {
                    "fingerprint": ngram_data.get("fingerprint", ""),
                    "total_syscalls": ngram_data.get("total_syscalls", 0),
                },
            })

    # --- Overall verdict result ---
    results.append({
        "ruleId": "tracetree/verdict",
        "ruleIndex": 0,
        "level": "error" if is_malicious else "none",
        "message": {
            "text": f"Final verdict: {'MALICIOUS' if is_malicious else 'CLEAN'} (confidence: {confidence:.1f}%)",
        },
        "properties": {
            "is_malicious": is_malicious,
            "confidence": confidence,
            "target": target,
        },
    })

    return {
        "tool": {
            "driver": {
                "name": "TraceTree",
                "version": "1.0.0",
                "informationUri": "https://github.com/tracetree/tracetree",
                "rules": _build_sarif_rules(
                    signature_matches, temporal_patterns, yara_matches, ngram_data
                ),
            },
        },
        "results": results,
        "invocations": [{
            "executionSuccessful": True,
            "endTimeUtc": datetime.now(timezone.utc).isoformat(),
            "toolConfigurationNotifications": [{
                "level": "note",
                "message": {
                    "text": f"Analyzed target: {target} | Events: {len(parsed_data.get('events', []))} | "
                            f"Graph nodes: {graph_data.get('stats', {}).get('node_count', 0)}",
                },
            }],
        }],
    }


# --------------------------------------------------------------------------- #
#  SARIF rule definitions
# --------------------------------------------------------------------------- #

# Cache for rule index lookups
_rule_indices: Dict[str, int] = {}


def _rule_index(category: str, name: str) -> int:
    """Get or assign a rule index."""
    key = f"{category}/{name}"
    if key not in _rule_indices:
        _rule_indices[key] = len(_rule_indices)
    return _rule_indices[key]


def _build_sarif_rules(
    signature_matches: List[Dict[str, Any]],
    temporal_patterns: List[Dict[str, Any]],
    yara_matches: List[Dict[str, Any]],
    ngram_data: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Build the SARIF rules array."""
    rules: List[Dict[str, Any]] = []

    # Verdict rule (always present)
    rules.append({
        "id": "tracetree/verdict",
        "name": "TraceTree Verdict",
        "shortDescription": {
            "text": "Overall malicious/clean verdict from TraceTree behavioral analysis",
        },
        "fullDescription": {
            "text": "TraceTree combines syscall tracing, behavioral signatures, temporal patterns, YARA rules, and n-gram fingerprinting to detect supply chain attacks.",
        },
        "defaultConfiguration": {
            "level": "error",
        },
        "properties": {
            "tags": ["supply-chain", "behavioral-analysis", "runtime"],
        },
    })

    # Signature rules
    seen = set()
    for sig in signature_matches:
        if sig["name"] not in seen:
            seen.add(sig["name"])
            rules.append({
                "id": f"signature/{sig['name']}",
                "name": sig["name"],
                "shortDescription": {
                    "text": sig.get("description", ""),
                },
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(sig.get("severity", 5)),
                },
                "properties": {
                    "tags": ["behavioral-signature"],
                },
            })

    # Temporal rules
    seen = set()
    for tp in temporal_patterns:
        if tp["pattern_name"] not in seen:
            seen.add(tp["pattern_name"])
            rules.append({
                "id": f"temporal/{tp['pattern_name']}",
                "name": tp["pattern_name"],
                "shortDescription": {
                    "text": tp.get("description", ""),
                },
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(tp.get("severity", 5)),
                },
                "properties": {
                    "tags": ["temporal-pattern"],
                },
            })

    # YARA rules
    seen = set()
    for ym in yara_matches:
        if ym["rule_name"] not in seen:
            seen.add(ym["rule_name"])
            rules.append({
                "id": f"yara/{ym['rule_name']}",
                "name": ym["rule_name"],
                "shortDescription": {
                    "text": ym.get("description", ""),
                },
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(_yara_severity_to_num(ym.get("severity", "medium"))),
                },
                "properties": {
                    "tags": ["yara"],
                },
            })

    # N-gram rules
    if ngram_data:
        from monitor.ngrams import detect_suspicious_ngrams
        suspicious_ng = detect_suspicious_ngrams(ngram_data)
        seen = set()
        for sg in suspicious_ng:
            if sg["ngram"] not in seen:
                seen.add(sg["ngram"])
                rules.append({
                    "id": f"ngram/{sg['ngram']}",
                    "name": f"Suspicious N-gram: {sg['ngram']}",
                    "shortDescription": {
                        "text": sg.get("description", ""),
                    },
                    "defaultConfiguration": {
                        "level": "error",
                    },
                    "properties": {
                        "tags": ["n-gram-fingerprint"],
                    },
                })

    return rules


# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #


def _severity_to_sarif_level(severity: float) -> str:
    """Map numeric severity to SARIF level."""
    if severity >= 8:
        return "error"
    elif severity >= 5:
        return "warning"
    elif severity >= 1:
        return "note"
    return "none"


def _yara_severity_to_num(severity: str) -> float:
    """Map YARA severity string to numeric."""
    mapping = {"critical": 10.0, "high": 8.0, "medium": 5.0, "low": 2.0}
    return mapping.get(severity.lower(), 5.0)
