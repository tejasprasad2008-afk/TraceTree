"""
Temporal execution analysis for TraceTree.

Detects time-based behavioral patterns from the ordered, timestamped
stream of parsed syscall events.

Usage:
    from monitor.timeline import detect_temporal_patterns

    patterns = detect_temporal_patterns(parsed_data)
    # Returns list of detected temporal patterns with evidence
"""

from typing import List, Dict, Any, Optional

# --------------------------------------------------------------------------- #
#  Temporal pattern definitions
#  Each pattern has:
#    - name: unique identifier
#    - description: human-readable summary
#    - severity: 1-10
#    - check_fn: function(events) -> list of matches
#
#  Each match has:
#    - pattern_name, severity, description
#    - start_time_ms, end_time_ms (relative to first event)
#    - time_window_ms: duration of the pattern
#    - evidence_events: list of event dicts that triggered the match
# --------------------------------------------------------------------------- #

# Sensitive file patterns (same as in parser.py, duplicated to avoid circular import)
_SENSITIVE_FILE_PATTERNS = [
    "/etc/shadow", "/etc/passwd", ".aws/credentials", ".ssh/id_rsa",
    ".ssh/id_ed25519", ".npmrc", ".pypirc", ".env", ".git-credentials",
    "/proc/self/environ", "/root/.bash_history", "/var/run/secrets",
]

# Known-safe network destinations (PyPI, npm, GitHub CDN — these don't count as "external")
_KNOWN_SAFE_PREFIXES = (
    "151.101.", "104.16.", "104.17.", "52.85.", "54.230.",
    "13.107.", "52.96.", "40.79.", "140.82.121.", "140.82.112.",
    "185.199.108.", "185.199.109.", "185.199.110.", "185.199.111.",
    "199.232.", "99.84.", "99.86.", "13.224.", "13.225.",
    "13.226.", "13.227.", "3.160.", "3.162.", "3.164.", "3.165.",
    "3.166.", "3.167.", "3.168.", "205.251.", "13.249.",
)

# Benign binaries (same as parser)
_BENIGN_BINARIES = frozenset([
    "/usr/local/bin/pip", "/usr/bin/pip",
    "/usr/local/bin/python", "/usr/bin/python",
    "/usr/local/bin/python3", "/usr/bin/python3",
    "/usr/bin/sh", "/usr/local/bin/sh",
    "/bin/sh", "/bin/bash",
    "/usr/local/bin/npm", "/usr/bin/npm",
    "/usr/local/bin/node", "/usr/bin/node",
    "/usr/bin/ip", "/sbin/ip",
])


def _is_sensitive_file(target: str) -> bool:
    """Check if a file path is sensitive."""
    return any(pat in target for pat in _SENSITIVE_FILE_PATTERNS)


def _is_external_connect(event: Dict[str, Any]) -> bool:
    """Check if a connect event goes to an external (non-registry) destination."""
    if event.get("type") != "connect":
        return False
    target = event.get("target", "")
    ip = target.split(":")[0] if ":" in target else target
    return not any(ip.startswith(p) for p in _KNOWN_SAFE_PREFIXES)


def _is_shell_execve(target: str) -> bool:
    """Check if an execve target is a shell binary."""
    return target in ("/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash",
                       "/usr/bin/sh", "/usr/bin/bash")


def _is_non_standard_execve(target: str) -> bool:
    """Check if an execve target is NOT a known benign binary."""
    return target not in _BENIGN_BINARIES


def _format_time_window(start_ms: float, end_ms: float) -> str:
    """Format a time window in human-readable form."""
    if end_ms < 1000:
        return f"{start_ms:.0f}-{end_ms:.0f} ms"
    elif start_ms < 1000:
        return f"{start_ms:.0f} ms - {end_ms / 1000:.1f} s"
    return f"{start_ms / 1000:.1f} s - {end_ms / 1000:.1f} s"


# --------------------------------------------------------------------------- #
#  Pattern checkers
# --------------------------------------------------------------------------- #


def _check_credential_scan_then_exfil(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect: openat on sensitive file → connect external within 5 seconds.
    This is the classic credential theft pattern: read secrets, then exfiltrate.
    """
    matches: List[Dict[str, Any]] = []
    window_ms = 5000.0

    for i, e_read in enumerate(events):
        if e_read["type"] not in ("openat", "read", "write"):
            continue
        if not _is_sensitive_file(e_read.get("target", "")):
            continue

        # Look for a connect to external destination within the time window
        read_time = e_read.get("relative_ms", 0.0)
        for e_conn in events[i + 1:]:
            if e_conn.get("relative_ms", 0.0) - read_time > window_ms:
                break  # Past the window
            if _is_external_connect(e_conn):
                matches.append({
                    "pattern_name": "credential_scan_then_exfil",
                    "severity": 9,
                    "description": "Sensitive file read followed by external connection within 5s",
                    "start_time_ms": round(read_time, 2),
                    "end_time_ms": round(e_conn.get("relative_ms", 0.0), 2),
                    "time_window_ms": round(e_conn.get("relative_ms", 0.0) - read_time, 2),
                    "evidence_events": [e_read, e_conn],
                })
                break  # One match per read event

    return matches


def _check_rapid_file_enumeration(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect: 10+ openat calls within 1 second.
    This is typical scanning behavior — malware probing for credentials/configs.
    """
    matches: List[Dict[str, Any]] = []
    window_ms = 1000.0
    threshold = 10

    openat_events = [e for e in events if e["type"] in ("openat", "read")]
    if len(openat_events) < threshold:
        return matches

    # Sliding window: for each event, count openat events within the next 1 second
    for i, start_evt in enumerate(openat_events):
        start_time = start_evt.get("relative_ms", 0.0)
        window_events = [start_evt]
        for e in openat_events[i + 1:]:
            if e.get("relative_ms", 0.0) - start_time > window_ms:
                break
            window_events.append(e)

        if len(window_events) >= threshold:
            end_time = window_events[-1].get("relative_ms", 0.0)
            matches.append({
                "pattern_name": "rapid_file_enumeration",
                "severity": 7,
                "description": f"{len(window_events)} file accesses within 1 second (scanning behavior)",
                "start_time_ms": round(start_time, 2),
                "end_time_ms": round(end_time, 2),
                "time_window_ms": round(end_time - start_time, 2),
                "evidence_events": window_events[:5] + [{"_summary": f"... and {len(window_events) - 5} more"}] if len(window_events) > 5 else window_events,
            })
            break  # One match is enough

    return matches


def _check_burst_process_spawn(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect: 5+ clone/execve within 2 seconds.
    Fork bombs, rapid process spawning for privilege escalation or resource exhaustion.
    """
    matches: List[Dict[str, Any]] = []
    window_ms = 2000.0
    threshold = 5

    spawn_events = [e for e in events if e["type"] in ("clone", "fork", "vfork", "execve")]
    if len(spawn_events) < threshold:
        return matches

    for i, start_evt in enumerate(spawn_events):
        start_time = start_evt.get("relative_ms", 0.0)
        window_events = [start_evt]
        for e in spawn_events[i + 1:]:
            if e.get("relative_ms", 0.0) - start_time > window_ms:
                break
            window_events.append(e)

        if len(window_events) >= threshold:
            end_time = window_events[-1].get("relative_ms", 0.0)
            matches.append({
                "pattern_name": "burst_process_spawn",
                "severity": 7,
                "description": f"{len(window_events)} process spawns within 2 seconds",
                "start_time_ms": round(start_time, 2),
                "end_time_ms": round(end_time, 2),
                "time_window_ms": round(end_time - start_time, 2),
                "evidence_events": window_events,
            })
            break

    return matches


def _check_delayed_payload(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect: significant gap (>10s) then sudden burst of suspicious activity.
    Dropper behavior — the payload waits before executing malicious actions.
    """
    matches: List[Dict[str, Any]] = []
    gap_threshold_ms = 10000.0  # 10 seconds

    if len(events) < 3:
        return matches

    # Find gaps between consecutive events
    for i in range(1, len(events)):
        prev_time = events[i - 1].get("relative_ms", 0.0)
        curr_time = events[i].get("relative_ms", 0.0)
        gap = curr_time - prev_time

        if gap > gap_threshold_ms:
            # Look for suspicious activity after the gap
            post_gap_events = events[i:]
            suspicious_count = 0
            burst_events = []
            for e in post_gap_events[:20]:  # Check first 20 events after gap
                e_sev = e.get("severity", 0.0)
                if e_sev >= 5.0:
                    suspicious_count += 1
                    burst_events.append(e)

            if suspicious_count >= 2:
                end_time = burst_events[-1].get("relative_ms", 0.0) if burst_events else curr_time
                matches.append({
                    "pattern_name": "delayed_payload",
                    "severity": 8,
                    "description": f"{suspicious_count} suspicious events after {gap / 1000:.1f}s gap (dropper behavior)",
                    "start_time_ms": round(prev_time, 2),
                    "end_time_ms": round(end_time, 2),
                    "time_window_ms": round(gap + (end_time - curr_time), 2),
                    "evidence_events": [events[i - 1]] + burst_events[:5],
                })
                break  # One match is enough

    return matches


def _check_connect_then_shell(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect: connect external → execve /bin/sh within 3 seconds.
    Classic reverse shell setup: connect to attacker, then spawn shell.
    """
    matches: List[Dict[str, Any]] = []
    window_ms = 3000.0

    for i, e_conn in enumerate(events):
        if not _is_external_connect(e_conn):
            continue

        conn_time = e_conn.get("relative_ms", 0.0)
        for e_exec in events[i + 1:]:
            if e_exec.get("relative_ms", 0.0) - conn_time > window_ms:
                break
            if e_exec["type"] == "execve" and _is_shell_execve(e_exec.get("target", "")):
                matches.append({
                    "pattern_name": "connect_then_shell",
                    "severity": 10,
                    "description": "External connection followed by shell execution within 3s",
                    "start_time_ms": round(conn_time, 2),
                    "end_time_ms": round(e_exec.get("relative_ms", 0.0), 2),
                    "time_window_ms": round(e_exec.get("relative_ms", 0.0) - conn_time, 2),
                    "evidence_events": [e_conn, e_exec],
                })
                break

    return matches


# --------------------------------------------------------------------------- #
#  Public API
# --------------------------------------------------------------------------- #

# All pattern checkers in order of severity (highest first)
_PATTERN_CHECKERS = [
    _check_connect_then_shell,          # severity 10
    _check_credential_scan_then_exfil,   # severity 9
    _check_delayed_payload,              # severity 8
    _check_rapid_file_enumeration,       # severity 7
    _check_burst_process_spawn,          # severity 7
]


def detect_temporal_patterns(parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Analyze the ordered, timestamped event stream for temporal patterns.

    Args:
        parsed_data: Output of ``monitor.parser.parse_strace_log()``.
                     Events must have ``relative_ms`` fields (set by parser
                     when strace was run with ``-t`` flag).

    Returns:
        List of detected temporal pattern dicts, sorted by severity descending.
        Each dict has:
          - pattern_name: str
          - severity: int (1-10)
          - description: str
          - start_time_ms: float
          - end_time_ms: float
          - time_window_ms: float
          - evidence_events: List[Dict]
    """
    events = parsed_data.get("events", [])
    if not events:
        return []

    # Sort events by sequence_id to ensure correct temporal order
    events_sorted = sorted(events, key=lambda e: e.get("sequence_id", 0))

    all_matches: List[Dict[str, Any]] = []
    for checker in _PATTERN_CHECKERS:
        all_matches.extend(checker(events_sorted))

    # Sort by severity descending, then by start time
    all_matches.sort(key=lambda m: (-m["severity"], m["start_time_ms"]))
    return all_matches


def summarize_patterns(patterns: List[Dict[str, Any]]) -> str:
    """
    Produce a human-readable summary of detected temporal patterns.

    Returns a multi-line string suitable for display in the CLI.
    """
    if not patterns:
        return "No temporal patterns detected."

    lines = []
    for p in patterns:
        sev = p["severity"]
        sev_icon = "🔴" if sev >= 8 else "🟡" if sev >= 5 else "🟢"
        time_str = _format_time_window(p["start_time_ms"], p["end_time_ms"])
        lines.append(f"{sev_icon} [bold]{p['pattern_name']}[/] (severity {sev}/10)")
        lines.append(f"   [dim]Window: {time_str} — {p['description']}[/]")
        lines.append("")

    return "\n".join(lines)
