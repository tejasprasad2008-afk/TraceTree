"""
Rule-based threat classification for MCP servers.

This sits on top of TraceTree's existing RandomForest/IsolationForest ML
classifier and adds MCP-specific threat categories based on extracted
features and adversarial probe results.

Threat categories:
    COMMAND_INJECTION        — shell spawned in response to tool arguments
    CREDENTIAL_EXFILTRATION  — reads secrets + network connection shortly after
    COVERT_NETWORK_CALL      — outbound connection to unexpected destination
    PATH_TRAVERSAL           — reads outside working directory / sensitive paths
    EXCESSIVE_PROCESS_SPAWNING — many child processes relative to tool calls
    PROMPT_INJECTION_VECTOR  — suspicious patterns in tool manifest
"""

from typing import Dict, Any, List, Optional


# Each threat category has a name, severity, and a check function.
THREAT_CATEGORIES = [
    {
        "name": "COMMAND_INJECTION",
        "severity": "critical",
        "description": "Shell process spawned in response to adversarial tool arguments, "
                       "indicating the server executes unsanitized input.",
    },
    {
        "name": "CREDENTIAL_EXFILTRATION",
        "severity": "critical",
        "description": "Server reads credential-related files (.env, ~/.aws, SSH keys) "
                       "followed by a network connection, indicating potential data theft.",
    },
    {
        "name": "COVERT_NETWORK_CALL",
        "severity": "high",
        "description": "Outbound network connection to an unexpected destination during "
                       "a tool call, suggesting covert data exfiltration or C2 communication.",
    },
    {
        "name": "PATH_TRAVERSAL",
        "severity": "high",
        "description": "Server reads files outside its working directory, especially "
                       "sensitive system files, indicating a path traversal vulnerability.",
    },
    {
        "name": "EXCESSIVE_PROCESS_SPAWNING",
        "severity": "medium",
        "description": "Server spawns a disproportionate number of child processes relative "
                       "to the number of tool invocations.",
    },
    {
        "name": "PROMPT_INJECTION_VECTOR",
        "severity": "high",
        "description": "Tool descriptions or parameter descriptions contain zero-width "
                       "characters, hidden unicode, or prompt injection language patterns.",
    },
]


def classify_mcp_threats(
    features: Dict[str, Any],
    prompt_injection_findings: Optional[List[Dict[str, Any]]] = None,
    adversarial_log: Optional[List[Dict[str, Any]]] = None,
    server_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Evaluate extracted MCP features against rule-based threat categories.

    Args:
        features: Dict from extract_mcp_features().
        prompt_injection_findings: From MCPClient.prompt_injection_findings.
        adversarial_log: From MCPClient.adversarial_log.
        server_type: Detected server type for baseline comparison.

    Returns:
        List of triggered threat dicts, each with:
        - name: str (threat category name)
        - severity: str (low/medium/high/critical)
        - description: str
        - evidence: list of str (specific evidence strings)
    """
    threats = []
    prompt_findings = prompt_injection_findings or []

    for category in THREAT_CATEGORIES:
        evidence = _check_threat(category["name"], features, prompt_findings, adversarial_log)
        if evidence:
            threats.append({
                "name": category["name"],
                "severity": category["severity"],
                "description": category["description"],
                "evidence": evidence,
            })

    return threats


def _check_threat(
    category_name: str,
    features: Dict[str, Any],
    prompt_findings: List[Dict[str, Any]],
    adversarial_log: Optional[List[Dict[str, Any]]],
) -> List[str]:
    """
    Check a single threat category. Returns a list of evidence strings
    if the threat is triggered, empty list otherwise.
    """
    if category_name == "COMMAND_INJECTION":
        return _check_command_injection(features, adversarial_log)

    elif category_name == "CREDENTIAL_EXFILTRATION":
        return _check_credential_exfiltration(features)

    elif category_name == "COVERT_NETWORK_CALL":
        return _check_covert_network(features)

    elif category_name == "PATH_TRAVERSAL":
        return _check_path_traversal(features)

    elif category_name == "EXCESSIVE_PROCESS_SPAWNING":
        return _check_excessive_spawning(features)

    elif category_name == "PROMPT_INJECTION_VECTOR":
        return _check_prompt_injection(prompt_findings)

    return []


def _check_command_injection(
    features: Dict[str, Any],
    adversarial_log: Optional[List[Dict[str, Any]]],
) -> List[str]:
    evidence = []

    if features.get("shell_spawned_on_injection"):
        evidence.append("Shell process spawned during or near adversarial probe")

    if features.get("behavior_change_on_adversarial_input"):
        evidence.append(
            f"Syscall pattern changed significantly under adversarial input "
            f"(delta: {features['adversarial_syscall_delta']} syscalls)"
        )

    if features.get("shell_invoked", 0) > 0 and adversarial_log:
        # Check if any adversarial probe caused the server to crash
        crashed = sum(1 for r in adversarial_log if r.get("server_crashed"))
        if crashed > 0:
            evidence.append(f"{crashed} adversarial probe(s) caused the server to crash")

    return evidence


def _check_credential_exfiltration(features: Dict[str, Any]) -> List[str]:
    evidence = []

    sensitive_paths = features.get("sensitive_paths_accessed", [])
    cred_paths = [p for p in sensitive_paths if any(
        marker in p.lower() for marker in (".env", ".aws", ".ssh", "id_rsa", "id_ed25519",
                                           ".gnupg", "credential", "token", "secret")
    )]

    if cred_paths:
        evidence.append(f"Credential-related files accessed: {', '.join(cred_paths[:5])}")

    if cred_paths and features.get("total_network_connections", 0) > 0:
        evidence.append(
            "Network connection detected shortly after credential file access — "
            "potential exfiltration"
        )

    return evidence


def _check_covert_network(features: Dict[str, Any]) -> List[str]:
    evidence = []

    unexpected = features.get("unexpected_outbound_connections", 0)
    if unexpected > 0:
        evidence.append(f"{unexpected} unexpected outbound connection(s) detected")

    dns_during_tool = features.get("dns_lookups_during_tool_call", 0)
    if dns_during_tool > 0:
        evidence.append(f"DNS resolution during tool call: {dns_during_tool} instance(s)")

    return evidence


def _check_path_traversal(features: Dict[str, Any]) -> List[str]:
    evidence = []

    outside = features.get("reads_outside_working_dir", 0)
    if outside > 0:
        evidence.append(f"{outside} file read(s) outside working directory")

    sensitive = features.get("reads_sensitive_paths", 0)
    if sensitive > 0:
        sensitive_paths = features.get("sensitive_paths_accessed", [])
        evidence.append(
            f"{sensitive} sensitive file access(es): "
            f"{', '.join(sensitive_paths[:5])}"
        )

    return evidence


def _check_excessive_spawning(features: Dict[str, Any]) -> List[str]:
    evidence = []

    spawned = features.get("child_process_spawned", 0)
    events_by_tool = features.get("events_by_tool", {})
    tool_call_count = len([k for k in events_by_tool if k != "unattributed"])

    if tool_call_count > 0 and spawned > tool_call_count * 3:
        evidence.append(
            f"{spawned} child processes spawned across {tool_call_count} tool calls "
            f"(ratio: {spawned / tool_call_count:.1f}x)"
        )
    elif spawned > 10:
        evidence.append(f"{spawned} child processes spawned (absolute threshold exceeded)")

    return evidence


def _check_prompt_injection(
    findings: List[Dict[str, Any]],
) -> List[str]:
    evidence = []

    for finding in findings:
        tool_name = finding.get("tool_name", "unknown")
        location = finding.get("location", "unknown")
        for item in finding.get("findings", []):
            evidence.append(f"[{tool_name}] {location}: {item}")

    return evidence


def compute_risk_score(threats: List[Dict[str, Any]]) -> str:
    """
    Compute an overall risk rating from the list of triggered threats.

    Returns one of: "low", "medium", "high", "critical".
    """
    if not threats:
        return "low"

    severity_scores = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    max_severity = max(
        severity_scores.get(t["severity"], 0) for t in threats
    )
    threat_count = len(threats)

    if max_severity >= 4 or threat_count >= 4:
        return "critical"
    elif max_severity >= 3 or threat_count >= 3:
        return "high"
    elif max_severity >= 2 or threat_count >= 2:
        return "medium"
    else:
        return "low"
