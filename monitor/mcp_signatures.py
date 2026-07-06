"""
MCP-specific RCE detection signatures for TraceTree.

Extends TraceTree's behavioral signature matching engine to detect
Model Context Protocol (MCP) server attacks including:
- UI injection payloads (unauthenticated)
- Marketplace poisoning (registry injection)
- JSON config-based RCE (LiteLLM CVE-2026-30623 style)
- Command execution patterns (shell metacharacters, reverse shells)

These signatures are loaded alongside data/signatures.json and provide
MCP-specific detection capabilities based on the OX Security April 2026 disclosure.

Usage:
    from monitor.mcp_signatures import load_mcp_signatures, match_mcp_signatures

    sigs = load_mcp_signatures()
    matches = match_mcp_signatures(parsed_data, mcp_features)
"""

import logging
from typing import List, Dict, Any, Optional
from monitor.signatures import match_signatures

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
#  MCP RCE Signatures
# --------------------------------------------------------------------------- #
#
# Each signature follows the same structure as data/signatures.json but
# includes MCP-specific fields:
#   - attack_family: The exploit family (ui_injection, marketplace_poisoning, etc.)
#   - cve_references: List of CVE IDs this signature correlates with
#   - mitre_techniques: MITRE ATT&CK technique IDs
#   - detection_confidence: Base confidence score (0.0-1.0)

MCP_SIGNATURES = [
    {
        "name": "mcp_ui_injection_exec",
        "description": "MCP UI injection leading to code execution — HTML/SVG/Markdown payload triggered shell spawn",
        "severity": 9,
        "syscalls": ["execve", "connect"],
        "files": [],
        "network": {
            "ports": [80, 443],
            "known_hosts": []
        },
        "sequence": [
            ["execve", "shell"],
            ["connect", "external"]
        ],
        "confidence_boost": 30.0,
        "attack_family": "ui_injection",
        "cve_references": ["CVE-2026-30624"],
        "mitre_techniques": ["T1189", "T1059.007"],
        "detection_confidence": 0.85,
    },
    {
        "name": "mcp_marketplace_poisoning",
        "description": "MCP marketplace poisoning — postinstall script execution with network exfiltration",
        "severity": 10,
        "syscalls": ["execve", "connect", "clone"],
        "files": [
            "package.json",
            "postinstall",
            ".npmrc",
            "setup.py"
        ],
        "network": {
            "ports": [80, 443, 4443],
            "known_hosts": []
        },
        "sequence": [
            ["execve", "non_standard"],
            ["connect", "external"],
            ["clone", None]
        ],
        "confidence_boost": 35.0,
        "attack_family": "marketplace_poisoning",
        "cve_references": ["CVE-2026-30625"],
        "mitre_techniques": ["T1195.001", "T1059.004"],
        "detection_confidence": 0.90,
    },
    {
        "name": "mcp_config_rce_litellm",
        "description": "MCP JSON config RCE (LiteLLM style) — arbitrary code execution via custom_llm_provider injection",
        "severity": 10,
        "syscalls": ["execve", "openat", "read", "connect"],
        "files": [
            "config.json",
            "config.yaml",
            "litellm",
            ".env"
        ],
        "network": {
            "ports": [80, 443],
            "known_hosts": []
        },
        "sequence": [
            ["openat", "secret"],
            ["execve", "non_standard"],
            ["connect", "external"]
        ],
        "confidence_boost": 35.0,
        "attack_family": "json_config_rce",
        "cve_references": ["CVE-2026-30623"],
        "mitre_techniques": ["T1059.006", "T1574.007"],
        "detection_confidence": 0.95,
    },
    {
        "name": "mcp_command_injection_shell",
        "description": "MCP command injection — shell metacharacter exploitation leading to arbitrary command execution",
        "severity": 10,
        "syscalls": ["execve", "clone", "connect"],
        "files": [],
        "network": {
            "ports": [],
            "known_hosts": []
        },
        "sequence": [
            ["execve", "shell"],
            ["clone", None],
            ["connect", "external"]
        ],
        "confidence_boost": 35.0,
        "attack_family": "command_execution",
        "cve_references": ["CVE-2026-30626"],
        "mitre_techniques": ["T1059.004", "T1059.006"],
        "detection_confidence": 0.92,
    },
    {
        "name": "mcp_reverse_shell_injection",
        "description": "MCP reverse shell injection — tool argument manipulation creating outbound shell connection",
        "severity": 10,
        "syscalls": ["execve", "connect", "dup2", "clone"],
        "files": [],
        "network": {
            "ports": [4444, 5555, 8080, 1234],
            "known_hosts": []
        },
        "sequence": [
            ["connect", "external"],
            ["dup2", None],
            ["execve", "shell"]
        ],
        "confidence_boost": 40.0,
        "attack_family": "command_execution",
        "cve_references": ["CVE-2026-30626", "CVE-2026-30627"],
        "mitre_techniques": ["T1059.004", "T1059.006", "T1059.007"],
        "detection_confidence": 0.98,
    },
    {
        "name": "mcp_registry_suspicious_download",
        "description": "MCP registry poisoning — download from suspicious registry followed by execution",
        "severity": 9,
        "syscalls": ["connect", "execve", "write"],
        "files": [
            "package.json",
            "requirements.txt",
            "setup.py"
        ],
        "network": {
            "ports": [80, 443, 8080],
            "known_hosts": []
        },
        "sequence": [
            ["connect", "external"],
            ["write", None],
            ["execve", "non_standard"]
        ],
        "confidence_boost": 30.0,
        "attack_family": "marketplace_poisoning",
        "cve_references": ["CVE-2026-30625"],
        "mitre_techniques": ["T1195.001", "T1105"],
        "detection_confidence": 0.88,
    },
    {
        "name": "mcp_env_variable_injection",
        "description": "MCP environment variable injection — NODE_OPTIONS/PYTHONPATH/LD_PRELOAD manipulation for code execution",
        "severity": 9,
        "syscalls": ["execve", "openat", "mmap"],
        "files": [
            ".env",
            "config.json",
            "config.yaml"
        ],
        "network": {
            "ports": [],
            "known_hosts": []
        },
        "sequence": [
            ["openat", "secret"],
            ["execve", "non_standard"],
            ["mmap", None]
        ],
        "confidence_boost": 30.0,
        "attack_family": "json_config_rce",
        "cve_references": ["CVE-2026-30628"],
        "mitre_techniques": ["T1574.007", "T1059.006"],
        "detection_confidence": 0.87,
    },
    {
        "name": "mcp_yaml_deserialization",
        "description": "MCP YAML deserialization RCE — unsafe YAML load executing Python/Node code",
        "severity": 10,
        "syscalls": ["execve", "openat", "read", "connect"],
        "files": [
            "config.yaml",
            "config.yml",
            ".yaml"
        ],
        "network": {
            "ports": [80, 443],
            "known_hosts": []
        },
        "sequence": [
            ["openat", None],
            ["read", None],
            ["execve", "shell"],
            ["connect", "external"]
        ],
        "confidence_boost": 35.0,
        "attack_family": "json_config_rce",
        "cve_references": ["CVE-2026-30629"],
        "mitre_techniques": ["T1059.006", "T1059.007"],
        "detection_confidence": 0.93,
    },
    {
        "name": "mcp_template_injection",
        "description": "MCP template injection (Handlebars/Jinja) — server-side template execution leading to RCE",
        "severity": 9,
        "syscalls": ["execve", "openat", "connect"],
        "files": [
            "config.json",
            "template",
            ".html"
        ],
        "network": {
            "ports": [80, 443],
            "known_hosts": []
        },
        "sequence": [
            ["openat", None],
            ["execve", "non_standard"],
            ["connect", "external"]
        ],
        "confidence_boost": 30.0,
        "attack_family": "json_config_rce",
        "cve_references": ["CVE-2026-30630"],
        "mitre_techniques": ["T1059.007", "T1059.006"],
        "detection_confidence": 0.86,
    },
    {
        "name": "mcp_dns_exfiltration",
        "description": "MCP DNS-based data exfiltration — encoding stolen data in DNS queries post-injection",
        "severity": 8,
        "syscalls": ["connect", "sendto", "socket"],
        "files": [],
        "network": {
            "ports": [53, 5353],
            "known_hosts": []
        },
        "sequence": [
            ["sendto", None],
            ["socket", None],
            ["connect", "external"]
        ],
        "confidence_boost": 25.0,
        "attack_family": "command_execution",
        "cve_references": ["CVE-2026-30631"],
        "mitre_techniques": ["T1048.001", "T1071.004"],
        "detection_confidence": 0.82,
    },
]


# --------------------------------------------------------------------------- #
#  Public API
# --------------------------------------------------------------------------- #


def load_mcp_signatures() -> List[Dict[str, Any]]:
    """
    Load MCP-specific RCE signatures.

    Returns:
        List of MCP signature dicts with additional fields:
        - attack_family: The exploit family classification
        - cve_references: List of CVE IDs this signature correlates with
        - mitre_techniques: MITRE ATT&CK technique IDs
        - detection_confidence: Base confidence score (0.0-1.0)
    """
    log.info("Loaded %d MCP RCE signatures", len(MCP_SIGNATURES))
    return list(MCP_SIGNATURES)


def match_mcp_signatures(
    parsed_data: Dict[str, Any],
    mcp_features: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Match parsed strace events against MCP RCE signatures.

    Args:
        parsed_data: Output of monitor.parser.parse_strace_log().
        mcp_features: Optional dict with MCP-specific features from
                     mcp.features.extract_mcp_features().

    Returns:
        List of matched MCP signature dicts, each augmented with:
        - evidence: list of event descriptions that triggered the match
        - matched_events: list of the actual event dicts
        - attack_family: The exploit family
        - cve_references: CVE correlations
        - mitre_techniques: MITRE ATT&CK techniques
        - detection_confidence: Confidence score
    """
    # Import the standard signature matcher

    # Load MCP signatures
    mcp_sigs = load_mcp_signatures()

    # Use the standard matcher (it will work with our extended signature format)
    matches = match_signatures(parsed_data, mcp_sigs)

    # Add MCP-specific metadata to matches
    for match in matches:
        # Find the original signature to get MCP fields
        orig_sig = next(
            (s for s in mcp_sigs if s["name"] == match["name"]),
            None
        )
        if orig_sig:
            match["attack_family"] = orig_sig.get("attack_family", "unknown")
            match["cve_references"] = orig_sig.get("cve_references", [])
            match["mitre_techniques"] = orig_sig.get("mitre_techniques", [])
            match["detection_confidence"] = orig_sig.get("detection_confidence", 0.0)

    return matches


def get_signature_by_cve(cve_id: str) -> List[Dict[str, Any]]:
    """
    Get all MCP signatures that reference a specific CVE.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2026-30623")

    Returns:
        List of matching signature dicts
    """
    return [
        sig for sig in MCP_SIGNATURES
        if cve_id in sig.get("cve_references", [])
    ]


def get_signatures_by_family(family: str) -> List[Dict[str, Any]]:
    """
    Get all MCP signatures for a specific attack family.

    Args:
        family: Attack family name (e.g., "command_execution", "ui_injection")

    Returns:
        List of matching signature dicts
    """
    return [
        sig for sig in MCP_SIGNATURES
        if sig.get("attack_family") == family
    ]


def get_all_cve_references() -> List[str]:
    """
    Get all unique CVE references across all MCP signatures.

    Returns:
        Sorted list of unique CVE IDs
    """
    cves = set()
    for sig in MCP_SIGNATURES:
        cves.update(sig.get("cve_references", []))
    return sorted(cves)


def get_all_attack_families() -> List[str]:
    """
    Get all unique attack families across all MCP signatures.

    Returns:
        Sorted list of unique attack family names
    """
    families = set()
    for sig in MCP_SIGNATURES:
        family = sig.get("attack_family")
        if family:
            families.add(family)
    return sorted(families)
