"""
MCP-specific feature extraction.

Parses the strace log from the MCP sandbox run and extracts features
grouped by tool-call activity: network behavior, process behavior,
filesystem behavior, and injection response metrics.
"""

import re
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path


# Sensitive paths that an MCP server should generally not access
SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "/root/.ssh", "/home/", "/.ssh/", "id_rsa", "id_ed25519",
    "/.aws/", "/.aws_credentials", "/.env", ".env",
    "/.gnupg/", "/.bash_history", "/.zsh_history",
    "/proc/", "/sys/",
]

# Shell binaries — spawning these is suspicious unless the tool is a shell tool
SHELL_BINARIES = ["/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash",
                  "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/zsh",
                  "cmd.exe", "powershell.exe", "powershell"]

# DNS-related syscalls / patterns
DNS_PORTS = {"53"}


def extract_mcp_features(
    log_path: str,
    call_log: Optional[List[Dict[str, Any]]] = None,
    adversarial_log: Optional[List[Dict[str, Any]]] = None,
    server_type: Optional[str] = None,
    allowlist_domains: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Parse a strace log from an MCP server run and extract MCP-specific features.

    Args:
        log_path: Path to the strace log file.
        call_log: List of tool call records from MCPClient (for timestamp attribution).
        adversarial_log: List of adversarial probe records from MCPClient.
        server_type: Known server type baseline (filesystem, github, postgres, etc.).
        allowlist_domains: Domains that are expected for this server type.

    Returns:
        Dict with all extracted MCP-specific features.
    """
    if not Path(log_path).exists():
        return _empty_features()

    events = _parse_strace_log(log_path)

    # Build timestamp → tool name mapping from call_log
    tool_timeline = []
    if call_log:
        for call in call_log:
            tool_timeline.append((call["timestamp"], call["tool_name"]))

    features = {
        # Network behavior
        "unexpected_outbound_connections": 0,
        "dns_lookups_during_tool_call": 0,
        "connection_count_per_tool_call": {},
        "total_network_connections": 0,
        "unique_destinations": set(),

        # Process behavior
        "child_process_spawned": 0,
        "shell_invoked": 0,
        "unexpected_binary_execution": 0,
        "execve_targets": [],

        # Filesystem behavior
        "reads_outside_working_dir": 0,
        "reads_sensitive_paths": 0,
        "writes_during_readonly_tool": 0,
        "sensitive_paths_accessed": [],

        # Injection response
        "behavior_change_on_adversarial_input": False,
        "shell_spawned_on_injection": False,
        "adversarial_syscall_delta": 0,

        # General
        "total_syscalls": len(events),
        "syscall_counts": {},
        "events_by_tool": {},
    }

    allowlist = set(allowlist_domains or [])
    working_dir = "/mcp-server"  # Default container mount point

    # Track state per event
    shell_spawned_in_adversarial = False
    normal_shell_count = 0
    adversarial_shell_count = 0

    # Get adversarial timestamps
    adversarial_timestamps = set()
    if adversarial_log:
        for probe in adversarial_log:
            adversarial_timestamps.add(probe["timestamp"])

    # --- Pass 1: classify events ---
    for evt in events:
        syscall = evt["syscall"]
        args = evt["args"]
        timestamp = evt.get("timestamp", 0)

        # Attribute to a tool call
        active_tool = _attribute_to_tool(tool_timeline, timestamp)
        tool_key = active_tool if active_tool else "unattributed"

        if tool_key not in features["events_by_tool"]:
            features["events_by_tool"][tool_key] = []
        features["events_by_tool"][tool_key].append(evt)

        # Count syscalls
        features["syscall_counts"][syscall] = features["syscall_counts"].get(syscall, 0) + 1

        # --- Network ---
        if syscall in ("connect", "sendto", "socket"):
            features["total_network_connections"] += 1
            dest = _extract_destination(args)
            if dest:
                features["unique_destinations"].add(dest)

                if tool_key not in features["connection_count_per_tool_call"]:
                    features["connection_count_per_tool_call"][tool_key] = 0
                features["connection_count_per_tool_call"][tool_key] += 1

                # Check if destination is unexpected
                if allowlist and not any(allowed in dest for allowed in allowlist):
                    features["unexpected_outbound_connections"] += 1

                # DNS detection
                port_match = re.search(r':(\d+)', dest)
                if port_match and port_match.group(1) in DNS_PORTS:
                    features["dns_lookups_during_tool_call"] += 1

        # --- Process ---
        if syscall in ("execve", "clone", "fork"):
            features["child_process_spawned"] += 1

        if syscall == "execve":
            binary = _extract_binary(args)
            if binary:
                features["execve_targets"].append(binary)
                if binary in SHELL_BINARIES:
                    features["shell_invoked"] += 1
                    if timestamp in adversarial_timestamps or _is_near_adversarial(
                        timestamp, adversarial_timestamps
                    ):
                        adversarial_shell_count += 1
                        shell_spawned_in_adversarial = True
                    else:
                        normal_shell_count += 1

        # --- Filesystem ---
        if syscall in ("openat", "open", "stat", "access"):
            filepath = _extract_filepath(args)
            if filepath:
                is_sensitive = any(sp in filepath for sp in SENSITIVE_PATHS)
                is_outside = not filepath.startswith(working_dir)

                if is_sensitive:
                    features["reads_sensitive_paths"] += 1
                    features["sensitive_paths_accessed"].append(filepath)

                if is_outside and not is_sensitive:
                    features["reads_outside_working_dir"] += 1
                elif is_outside and is_sensitive:
                    features["reads_outside_working_dir"] += 1

    # --- Pass 2: adversarial comparison ---
    if adversarial_log and call_log:
        normal_syscall_count = sum(
            len(evts)
            for tool_name, evts in features["events_by_tool"].items()
            if tool_name not in ("unattributed",)
        )
        adversarial_syscall_count = sum(
            len(evts)
            for tool_name, evts in features["events_by_tool"].items()
            if _is_adversarial_tool_call(tool_name, adversarial_log)
        )

        delta = abs(normal_syscall_count - adversarial_syscall_count)
        features["adversarial_syscall_delta"] = delta
        features["behavior_change_on_adversarial_input"] = delta > 5

        features["shell_spawned_on_injection"] = shell_spawned_in_adversarial

    # Convert sets to lists for JSON serialization
    features["unique_destinations"] = list(features["unique_destinations"])

    # Add baseline comparison if server_type is known
    if server_type:
        baseline = _get_baseline(server_type)
        features["baseline_comparison"] = _compare_to_baseline(features, baseline)

    return features


def _parse_strace_log(log_path: str) -> List[Dict[str, Any]]:
    """
    Parse a strace log file into a list of event dicts.
    Extended version of monitor.parser for MCP-specific detail extraction.
    """
    line_pattern = re.compile(
        r'^(\d+)\s+([a-zA-Z0-9_]+)\((.*)$'
    )
    events = []
    timestamp_counter = 0

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = line_pattern.match(line.strip())
            if not match:
                continue

            pid = match.group(1)
            syscall = match.group(2)
            args_raw = match.group(3)

            timestamp_counter += 1
            events.append({
                "pid": pid,
                "syscall": syscall,
                "args": args_raw,
                "timestamp": timestamp_counter,
            })

    return events


def _attribute_to_tool(
    timeline: List[Tuple[float, str]],
    event_timestamp: float,
) -> Optional[str]:
    """
    Given a sorted list of (timestamp, tool_name) pairs, find which tool
    was active at the given event timestamp.  Uses the most recent tool
    whose timestamp is <= event_timestamp.
    """
    if not timeline:
        return None

    # Simple approach: timestamps in strace log are sequential integers
    # while call_log timestamps are wall-clock.  We map proportionally.
    if len(timeline) == 1:
        return timeline[0][1]

    idx = min(int(event_timestamp) % len(timeline), len(timeline) - 1)
    return timeline[idx][1]


def _is_adversarial_tool_call(tool_name: str, adversarial_log: List[Dict]) -> bool:
    """Check if this tool_name appears in the adversarial log."""
    return any(
        record["tool_name"] == tool_name
        for record in adversarial_log
    )


def _is_near_adversarial(timestamp: float, adversarial_timestamps: set) -> bool:
    """
    Check if this timestamp is within ±5 of any adversarial timestamp.
    Uses the sequential counter-based timestamps from strace.
    """
    return any(abs(timestamp - ts) <= 5 for ts in adversarial_timestamps)


def _extract_destination(args: str) -> Optional[str]:
    """Extract IP:port or domain:port from syscall args."""
    ip_match = re.search(r'sin_addr=inet_addr\("([^"]+)"\)', args)
    port_match = re.search(r'sin_port=htons\(([0-9]+)\)', args)

    if ip_match:
        ip = ip_match.group(1)
        port = port_match.group(1) if port_match else "?"
        return f"{ip}:{port}"

    # Also try to find sockaddr patterns
    addr_match = re.search(r'({.*?})', args)
    if addr_match:
        return addr_match.group(1)

    return None


def _extract_binary(args: str) -> Optional[str]:
    """Extract the binary path from an execve syscall."""
    binary_match = re.match(r'^"([^"]+)"', args)
    if binary_match:
        return binary_match.group(1)
    return None


def _extract_filepath(args: str) -> Optional[str]:
    """Extract a file path from openat/stat/access syscall args."""
    file_match = re.search(r',\s*"([^"]+)"', args)
    if file_match:
        return file_match.group(1)
    return None


def _empty_features() -> Dict[str, Any]:
    return {
        "unexpected_outbound_connections": 0,
        "dns_lookups_during_tool_call": 0,
        "connection_count_per_tool_call": {},
        "total_network_connections": 0,
        "unique_destinations": [],
        "child_process_spawned": 0,
        "shell_invoked": 0,
        "unexpected_binary_execution": 0,
        "execve_targets": [],
        "reads_outside_working_dir": 0,
        "reads_sensitive_paths": 0,
        "writes_during_readonly_tool": 0,
        "sensitive_paths_accessed": [],
        "behavior_change_on_adversarial_input": False,
        "shell_spawned_on_injection": False,
        "adversarial_syscall_delta": 0,
        "total_syscalls": 0,
        "syscall_counts": {},
        "events_by_tool": {},
        "baseline_comparison": {},
    }


# ------------------------------------------------------------------ #
#  Known MCP server baselines
# ------------------------------------------------------------------ #

KNOWN_BASELINES = {
    "filesystem": {
        "description": "Filesystem MCP server — read/write/list files",
        "expected_syscalls": {"openat", "read", "write", "getdents", "getdents64", "stat", "lstat", "access"},
        "allow_network": False,
        "allow_process_spawn": False,
        "allow_sensitive_read": False,
        "allow_write_paths": "within specified directories only",
    },
    "github": {
        "description": "GitHub MCP server — API interactions",
        "expected_syscalls": {"openat", "read", "connect", "socket", "sendto", "recvfrom", "write"},
        "allow_network": True,
        "expected_domains": {"api.github.com", "github.com"},
        "allow_process_spawn": False,
        "allow_sensitive_read": True,  # may read config/auth files
    },
    "postgres": {
        "description": "Postgres/database MCP server — SQL query execution",
        "expected_syscalls": {"openat", "read", "write", "connect", "socket", "sendto", "recvfrom"},
        "allow_network": True,
        "expected_domains": set(),  # configured DB host
        "allow_process_spawn": False,
        "allow_sensitive_read": False,
        "allow_write_paths": "temp only",
    },
    "fetch": {
        "description": "Web fetch/browser MCP server — HTTP requests",
        "expected_syscalls": {"openat", "read", "write", "connect", "socket", "sendto", "recvfrom"},
        "allow_network": True,
        "expected_domains": set(),  # user-specified URLs
        "allow_process_spawn": False,
        "allow_sensitive_read": False,
        "allow_write_paths": "none",
    },
    "shell": {
        "description": "Shell/execution MCP server — explicit command execution",
        "expected_syscalls": {"openat", "read", "write", "execve", "clone", "fork", "connect"},
        "allow_network": False,
        "allow_process_spawn": True,  # by design
        "allow_sensitive_read": False,
        "allow_write_paths": "none",
    },
}


def detect_server_type(
    package_name: str,
    tool_descriptions: List[str],
) -> Optional[str]:
    """
    Auto-detect the MCP server type from the package name and tool
    descriptions.
    """
    name_lower = package_name.lower()
    combined_text = " ".join(tool_descriptions).lower()

    if any(k in name_lower for k in ("filesystem", "file-server", "file_server")):
        return "filesystem"
    if any(k in name_lower for k in ("github", "gh-", "gh_")):
        return "github"
    if any(k in name_lower for k in ("postgres", "pg-", "database", "db-", "sql")):
        return "postgres"
    if any(k in name_lower for k in ("fetch", "browser", "web-", "http")):
        return "fetch"
    if any(k in name_lower for k in ("shell", "exec", "command", "terminal")):
        return "shell"

    # Fallback: check tool descriptions
    if "filesystem" in combined_text or "read file" in combined_text or "write file" in combined_text:
        return "filesystem"
    if "github" in combined_text or "repository" in combined_text:
        return "github"
    if "postgres" in combined_text or "sql query" in combined_text:
        return "postgres"
    if "fetch url" in combined_text or "browse" in combined_text:
        return "fetch"
    if "shell" in combined_text or "execute command" in combined_text:
        return "shell"

    return None


def _get_baseline(server_type: str) -> Dict[str, Any]:
    """Get the known baseline for a server type."""
    return KNOWN_BASELINES.get(server_type, {})


def _compare_to_baseline(
    features: Dict[str, Any],
    baseline: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Compare extracted features against the known baseline for this server type.
    Returns a dict with deviation flags.
    """
    if not baseline:
        return {"status": "unknown", "reason": "no known baseline for this server type"}

    deviations = []

    # Check network
    if not baseline.get("allow_network") and features["total_network_connections"] > 0:
        deviations.append(
            f"Unexpected network connections: {features['total_network_connections']}"
        )

    # Check process spawning
    if not baseline.get("allow_process_spawn") and features["child_process_spawned"] > 0:
        deviations.append(
            f"Unexpected process spawning: {features['child_process_spawned']} instances"
        )

    # Check sensitive path reads
    if not baseline.get("allow_sensitive_read") and features["reads_sensitive_paths"] > 0:
        deviations.append(
            f"Unexpected sensitive path access: {features['reads_sensitive_paths']} accesses"
        )

    # Check shell invocation
    if (
        not baseline.get("allow_process_spawn")
        and features["shell_invoked"] > 0
    ):
        deviations.append(
            f"Shell binary invoked: {features['shell_invoked']} times"
        )

    return {
        "status": "deviant" if deviations else "within_baseline",
        "deviations": deviations,
    }
