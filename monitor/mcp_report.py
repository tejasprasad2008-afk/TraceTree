"""
MCP RCE Detection Report Template

Generates structured detection reports for MCP-specific RCE indicators
with CVE correlation, attack family classification, and confidence scoring.

Usage:
    from monitor.mcp_report import generate_mcp_rce_report

    report = generate_mcp_rce_report(
        target="mcp-server-filesystem",
        matches=mcp_signature_matches,
        yara_matches=yara_results,
        mcp_features=extracted_features,
        strace_log="/path/to/strace.log"
    )
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
#  CVE Database for MCP RCE (OX Security April 2026 Disclosure)
# --------------------------------------------------------------------------- #

CVE_DATABASE = {
    "CVE-2026-30623": {
        "title": "LiteLLM Configuration-Based Remote Code Execution",
        "description": "Arbitrary code execution via custom_llm_provider field in LiteLLM configuration files",
        "severity": "critical",
        "cvss_score": 9.8,
        "attack_family": "json_config_rce",
        "affected_products": ["LiteLLM <= 1.50.0", "MCP servers using LiteLLM integration"],
        "fix_version": "LiteLLM 1.51.0",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-30623",
            "https://github.com/BerriAI/litellm/security/advisories",
        ],
    },
    "CVE-2026-30624": {
        "title": "MCP UI Injection via Tool Response Manipulation",
        "description": "Unauthenticated code execution through HTML/Markdown/SVG injection in MCP tool responses",
        "severity": "high",
        "cvss_score": 8.5,
        "attack_family": "ui_injection",
        "affected_products": ["MCP clients rendering tool responses without sanitization"],
        "fix_version": "Client-side input validation required",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-30624",
            "https://spec.modelcontextprotocol.io/security",
        ],
    },
    "CVE-2026-30625": {
        "title": "MCP Marketplace Registry Poisoning",
        "description": "Supply chain attack via typosquatting and dependency confusion in MCP server registries",
        "severity": "critical",
        "cvss_score": 9.1,
        "attack_family": "marketplace_poisoning",
        "affected_products": ["npm MCP server packages", "pip MCP server packages"],
        "fix_version": "Registry-side validation required",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-30625",
            "https://www.ox.security/research/mcp-supply-chain",
        ],
    },
    "CVE-2026-30626": {
        "title": "MCP Command Injection via Tool Arguments",
        "description": "Shell metacharacter injection and reverse shell execution through unsanitized tool arguments",
        "severity": "critical",
        "cvss_score": 9.8,
        "attack_family": "command_execution",
        "affected_products": ["MCP servers executing shell commands with user input"],
        "fix_version": "Input sanitization and allowlist validation required",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-30626",
        ],
    },
    "CVE-2026-30627": {
        "title": "MCP Reverse Shell via Tool Invocation",
        "description": "Outbound reverse shell establishment through malicious tool argument sequences",
        "severity": "critical",
        "cvss_score": 9.9,
        "attack_family": "command_execution",
        "affected_products": ["MCP servers with shell execution capabilities"],
        "fix_version": "Network restriction and command allowlisting required",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-30627",
        ],
    },
    "CVE-2026-30628": {
        "title": "MCP Environment Variable Injection",
        "description": "Code execution via NODE_OPTIONS, PYTHONPATH, and LD_PRELOAD manipulation in MCP configs",
        "severity": "high",
        "cvss_score": 8.8,
        "attack_family": "json_config_rce",
        "affected_products": ["MCP servers loading environment from config files"],
        "fix_version": "Environment variable allowlisting required",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-30628",
        ],
    },
    "CVE-2026-30629": {
        "title": "MCP YAML Deserialization RCE",
        "description": "Arbitrary code execution through unsafe YAML deserialization in MCP configuration",
        "severity": "critical",
        "cvss_score": 9.8,
        "attack_family": "json_config_rce",
        "affected_products": ["MCP servers using PyYAML or js-yaml without SafeLoader"],
        "fix_version": "Use SafeLoader/safeLoad for YAML parsing",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-30629",
        ],
    },
    "CVE-2026-30630": {
        "title": "MCP Server-Side Template Injection",
        "description": "Remote code execution via Handlebars/Jinja template injection in MCP tool configurations",
        "severity": "high",
        "cvss_score": 8.6,
        "attack_family": "json_config_rce",
        "affected_products": ["MCP servers using templating engines with user input"],
        "fix_version": "Sandboxed template execution required",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-30630",
        ],
    },
    "CVE-2026-30631": {
        "title": "MCP DNS-Based Data Exfiltration",
        "description": "Covert data exfiltration via DNS query encoding post-compromise",
        "severity": "high",
        "cvss_score": 7.5,
        "attack_family": "command_execution",
        "affected_products": ["MCP servers with DNS access"],
        "fix_version": "DNS query monitoring and restriction required",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-30631",
        ],
    },
}


# --------------------------------------------------------------------------- #
#  Report Generation
# --------------------------------------------------------------------------- #


def generate_mcp_rce_report(
    target: str,
    matches: List[Dict[str, Any]],
    yara_matches: Optional[List[Dict[str, Any]]] = None,
    mcp_features: Optional[Dict[str, Any]] = None,
    strace_log: Optional[str] = None,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generate a comprehensive MCP RCE detection report.

    Args:
        target: Target MCP server name or path
        matches: List of matched MCP signatures from match_mcp_signatures()
        yara_matches: Optional list of YARA rule matches
        mcp_features: Optional dict with extracted MCP features
        strace_log: Path to the strace log file analyzed
        output_path: Optional path to save JSON report

    Returns:
        Report dict with full detection analysis
    """
    report = {
        "metadata": {
            "report_type": "MCP RCE Detection Report",
            "generated_at": datetime.now().isoformat(),
            "target": target,
            "analyzer_version": "TraceTree 1.0.0",
            "disclosure_reference": "OX Security April 2026",
        },
        "summary": _generate_summary(matches, yara_matches),
        "detections": _format_detections(matches),
        "yara_findings": yara_matches or [],
        "cve_correlations": _correlate_cves(matches),
        "attack_timeline": _build_timeline(matches, mcp_features),
        "recommendations": _generate_recommendations(matches),
        "evidence_summary": _summarize_evidence(matches, mcp_features),
    }

    # Include strace log path if provided
    if strace_log:
        report["metadata"]["strace_log"] = strace_log

    # Save to file if output path specified
    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        log.info("MCP RCE report saved to %s", output_path)

    return report


def _generate_summary(
    matches: List[Dict[str, Any]],
    yara_matches: Optional[List[Dict[str, Any]]],
) -> Dict[str, Any]:
    """Generate executive summary of detection results."""
    total_detections = len(matches) + (len(yara_matches) if yara_matches else 0)

    # Count by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for match in matches:
        sev = match.get("severity", 0)
        if sev >= 9:
            severity_counts["critical"] += 1
        elif sev >= 7:
            severity_counts["high"] += 1
        elif sev >= 4:
            severity_counts["medium"] += 1
        else:
            severity_counts["low"] += 1

    # Count by attack family
    family_counts = {}
    for match in matches:
        family = match.get("attack_family", "unknown")
        family_counts[family] = family_counts.get(family, 0) + 1

    # Determine overall risk level
    if severity_counts["critical"] > 0:
        overall_risk = "critical"
    elif severity_counts["high"] > 0:
        overall_risk = "high"
    elif severity_counts["medium"] > 0:
        overall_risk = "medium"
    else:
        overall_risk = "low"

    # Calculate max confidence
    max_confidence = 0.0
    for match in matches:
        conf = match.get("detection_confidence", 0.0)
        if conf > max_confidence:
            max_confidence = conf

    return {
        "total_detections": total_detections,
        "signature_matches": len(matches),
        "yara_matches": len(yara_matches) if yara_matches else 0,
        "overall_risk_level": overall_risk,
        "max_detection_confidence": round(max_confidence, 2),
        "severity_breakdown": severity_counts,
        "attack_family_breakdown": family_counts,
    }


def _format_detections(matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Format individual detection matches for the report."""
    detections = []

    for match in matches:
        detection = {
            "signature_name": match.get("name", "unknown"),
            "description": match.get("description", ""),
            "severity": match.get("severity", 0),
            "attack_family": match.get("attack_family", "unknown"),
            "detection_confidence": match.get("detection_confidence", 0.0),
            "cve_references": match.get("cve_references", []),
            "mitre_techniques": match.get("mitre_techniques", []),
            "evidence": match.get("evidence", []),
            "matched_events_count": len(match.get("matched_events", [])),
        }
        detections.append(detection)

    # Sort by confidence descending
    detections.sort(key=lambda d: d["detection_confidence"], reverse=True)

    return detections


def _correlate_cves(matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Correlate detections with CVE database."""
    cve_correlations = []
    seen_cves = set()

    for match in matches:
        for cve_id in match.get("cve_references", []):
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)

            cve_info = CVE_DATABASE.get(cve_id, {})
            correlation = {
                "cve_id": cve_id,
                "title": cve_info.get("title", "Unknown"),
                "description": cve_info.get("description", ""),
                "severity": cve_info.get("severity", "unknown"),
                "cvss_score": cve_info.get("cvss_score", 0.0),
                "attack_family": cve_info.get("attack_family", "unknown"),
                "affected_products": cve_info.get("affected_products", []),
                "fix_version": cve_info.get("fix_version", "N/A"),
                "references": cve_info.get("references", []),
                "matched_signatures": [],
            }

            # Find all signatures that reference this CVE
            for m in matches:
                if cve_id in m.get("cve_references", []):
                    correlation["matched_signatures"].append(m.get("name", "unknown"))

            cve_correlations.append(correlation)

    # Sort by CVSS score descending
    cve_correlations.sort(key=lambda c: c["cvss_score"], reverse=True)

    return cve_correlations


def _build_timeline(
    matches: List[Dict[str, Any]],
    mcp_features: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Build attack timeline from matched events."""
    timeline = []

    for match in matches:
        matched_events = match.get("matched_events", [])
        for event in matched_events:
            timeline.append({
                "timestamp": event.get("timestamp", 0),
                "syscall": event.get("type", "unknown"),
                "target": event.get("target", ""),
                "signature": match.get("name", "unknown"),
                "attack_family": match.get("attack_family", "unknown"),
            })

    # Sort by timestamp
    timeline.sort(key=lambda t: t["timestamp"])

    return timeline


def _generate_recommendations(matches: List[Dict[str, Any]]) -> List[str]:
    """Generate actionable recommendations based on detections."""
    recommendations = set()

    # Check for command execution
    cmd_exec = any(
        m.get("attack_family") == "command_execution"
        for m in matches
    )
    if cmd_exec:
        recommendations.add(
            "CRITICAL: Implement strict input validation and sanitization for all MCP tool arguments. "
            "Use allowlists for permitted commands and reject shell metacharacters."
        )
        recommendations.add(
            "Deploy network restrictions to prevent outbound connections to unknown destinations. "
            "Use egress filtering to block reverse shell patterns."
        )

    # Check for UI injection
    ui_injection = any(
        m.get("attack_family") == "ui_injection"
        for m in matches
    )
    if ui_injection:
        recommendations.add(
            "HIGH: Implement content sanitization for all MCP tool responses before rendering. "
            "Use HTML/Markdown sanitizers and CSP headers to prevent XSS."
        )

    # Check for marketplace poisoning
    marketplace = any(
        m.get("attack_family") == "marketplace_poisoning"
        for m in matches
    )
    if marketplace:
        recommendations.add(
            "CRITICAL: Verify MCP server package integrity using checksums and signatures. "
            "Use private registries with allowlisting to prevent typosquatting attacks."
        )

    # Check for config-based RCE
    config_rce = any(
        m.get("attack_family") == "json_config_rce"
        for m in matches
    )
    if config_rce:
        recommendations.add(
            "CRITICAL: Use safe YAML/JSON parsers (e.g., SafeLoader for PyYAML). "
            "Never execute code from configuration files without strict validation."
        )
        recommendations.add(
            "Implement environment variable allowlisting and reject NODE_OPTIONS, "
            "PYTHONPATH, and LD_PRELOAD from untrusted configs."
        )

    # General recommendations
    if matches:
        recommendations.add(
            "MONITORING: Deploy runtime behavioral analysis (e.g., TraceTree) to detect "
            "anomalous syscall patterns indicative of RCE attempts."
        )
        recommendations.add(
            "SANDBOXING: Execute all MCP servers in isolated containers with restricted "
            "network access and minimal filesystem permissions."
        )

    return sorted(recommendations)


def _summarize_evidence(
    matches: List[Dict[str, Any]],
    mcp_features: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Summarize key evidence across all detections."""
    all_evidence = []
    all_syscalls = set()
    all_network_dests = set()

    for match in matches:
        all_evidence.extend(match.get("evidence", []))
        for event in match.get("matched_events", []):
            all_syscalls.add(event.get("type", ""))
            if event.get("type") == "connect":
                all_network_dests.add(event.get("target", ""))

    return {
        "total_evidence_items": len(all_evidence),
        "unique_syscalls_observed": sorted(all_syscalls),
        "network_destinations": sorted(all_network_dests),
        "key_evidence_samples": all_evidence[:10],  # Top 10 evidence items
        "mcp_feature_flags": mcp_features.get("flags", []) if mcp_features else [],
    }


# --------------------------------------------------------------------------- #
#  Convenience Functions
# --------------------------------------------------------------------------- #


def get_cve_details(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Get detailed information about a specific CVE.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2026-30623")

    Returns:
        CVE details dict or None if not found
    """
    return CVE_DATABASE.get(cve_id)


def search_cves_by_family(family: str) -> List[Dict[str, Any]]:
    """
    Search for CVEs by attack family.

    Args:
        family: Attack family name

    Returns:
        List of CVE dicts matching the family
    """
    return [
        {**cve, "cve_id": cve_id}
        for cve_id, cve in CVE_DATABASE.items()
        if cve.get("attack_family") == family
    ]


def calculate_overall_confidence(matches: List[Dict[str, Any]]) -> float:
    """
    Calculate overall detection confidence from multiple matches.

    Uses weighted average based on severity and confidence scores.

    Args:
        matches: List of matched signature dicts

    Returns:
        Overall confidence score (0.0-1.0)
    """
    if not matches:
        return 0.0

    total_weight = 0.0
    weighted_sum = 0.0

    for match in matches:
        severity = match.get("severity", 0)
        confidence = match.get("detection_confidence", 0.0)

        # Weight by severity (higher severity = more weight)
        weight = severity / 10.0
        total_weight += weight
        weighted_sum += (confidence * weight)

    if total_weight == 0:
        return 0.0

    return round(weighted_sum / total_weight, 2)
