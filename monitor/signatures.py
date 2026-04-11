"""
Behavioral signature matching engine for TraceTree.

Loads signatures from data/signatures.json and matches parsed strace events
against each pattern.  Returns a list of matched signatures with concrete
evidence (the specific events that triggered each match).

Usage:
    from monitor.signatures import load_signatures, match_signatures

    sigs = load_signatures()
    matches = match_signatures(parsed_data, sigs)
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
#  Path constants
# --------------------------------------------------------------------------- #

_SIGNATURES_PATH = Path(__file__).parent.parent / "data" / "signatures.json"

# --------------------------------------------------------------------------- #
#  Known benign hosts for network classification (re-used from parser)
# --------------------------------------------------------------------------- #

KNOWN_SAFE_NETWORKS = frozenset([
    "151.101.", "104.16.", "104.17.", "52.85.", "54.230.",
    "13.107.", "52.96.", "40.79.", "140.82.121.", "140.82.112.",
    "185.199.108.", "185.199.109.", "185.199.110.", "185.199.111.",
    "199.232.", "99.84.", "99.86.", "13.224.", "13.225.", "13.226.",
    "13.227.", "3.160.", "3.162.", "3.164.", "3.165.", "3.166.",
    "3.167.", "3.168.", "205.251.", "13.249.",
])

BENIGN_BINARIES = frozenset([
    "/usr/local/bin/pip", "/usr/bin/pip",
    "/usr/local/bin/python", "/usr/bin/python",
    "/usr/local/bin/python3", "/usr/bin/python3",
    "/usr/bin/sh", "/usr/local/bin/sh",
    "/bin/sh", "/bin/bash",
    "/usr/local/bin/npm", "/usr/bin/npm",
    "/usr/local/bin/node", "/usr/bin/node",
    "/usr/bin/ip", "/sbin/ip",
])

# --------------------------------------------------------------------------- #
#  Public API
# --------------------------------------------------------------------------- #


def load_signatures(path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Load behavioral signatures from the JSON file.

    Args:
        path: Optional override path to the JSON file.

    Returns:
        List of signature dicts, each with keys:
        name, description, severity, syscalls, files, network, sequence,
        confidence_boost.
    """
    sig_path = Path(path) if path else _SIGNATURES_PATH
    if not sig_path.exists():
        log.warning("Signatures file not found at %s — no signatures loaded", sig_path)
        return []

    try:
        with open(sig_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        log.error("Failed to parse signatures JSON: %s", e)
        return []

    signatures = data.get("signatures", [])
    log.info("Loaded %d behavioral signatures from %s", len(signatures), sig_path)
    return signatures


def match_signatures(
    parsed_data: Dict[str, Any],
    signatures: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Match parsed strace events against the signature library.

    Args:
        parsed_data: Output of monitor.parser.parse_strace_log().
        signatures: List of signature dicts from load_signatures().

    Returns:
        List of matched signature dicts, each augmented with:
          - evidence: list of event descriptions that triggered the match
          - matched_events: list of the actual event dicts
    """
    events = parsed_data.get("events", [])
    flags = parsed_data.get("flags", [])
    network_dests = parsed_data.get("network_destinations", [])

    matches: List[Dict[str, Any]] = []

    for sig in signatures:
        result = _match_single_signature(sig, events, flags, network_dests)
        if result is not None:
            matches.append(result)

    # Sort by severity descending
    matches.sort(key=lambda m: m["severity"], reverse=True)
    return matches


# --------------------------------------------------------------------------- #
#  Single-signature matching
# --------------------------------------------------------------------------- #


def _match_single_signature(
    sig: Dict[str, Any],
    events: List[Dict[str, Any]],
    flags: List[str],
    network_dests: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """
    Check if a single signature matches the parsed events.

    Returns the signature dict with added evidence, or None if no match.
    """
    name = sig["name"]
    sequence = sig.get("sequence")

    if sequence:
        return _match_sequence(sig, events, network_dests)
    else:
        return _match_unordered(sig, events, network_dests)


def _match_unordered(
    sig: Dict[str, Any],
    events: List[Dict[str, Any]],
    network_dests: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """
    Unordered matching: all required syscalls must appear somewhere in the
    event list, plus at least one file pattern match (if files are specified)
    and at least one network pattern match (if network rules are specified).
    """
    event_types = {e["type"] for e in events}
    required_syscalls = set(sig.get("syscalls", []))

    if not required_syscalls.issubset(event_types):
        return None

    evidence: List[str] = []
    matched_events: List[Dict[str, Any]] = []

    # Check file patterns
    file_patterns = sig.get("files", [])
    if file_patterns:
        file_match = _check_file_patterns(events, file_patterns)
        if file_match:
            evidence.extend(file_match["evidence"])
            matched_events.extend(file_match["events"])
        else:
            return None

    # Check network patterns
    net_rules = sig.get("network", {})
    if net_rules:
        net_match = _check_network_patterns(events, network_dests, net_rules)
        if net_match:
            evidence.extend(net_match["evidence"])
            matched_events.extend(net_match["events"])
        else:
            return None

    if not evidence:
        # Syscalls matched but no file/network evidence — still match
        # if no file/network rules were specified
        if not file_patterns and not net_rules:
            evidence.append(f"All required syscalls present: {sorted(required_syscalls)}")
            for e in events:
                if e["type"] in required_syscalls:
                    matched_events.append(e)
        else:
            return None

    return _build_result(sig, evidence, matched_events)


def _match_sequence(
    sig: Dict[str, Any],
    events: List[Dict[str, Any]],
    network_dests: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """
    Ordered matching: the signature defines a sequence of (syscall, condition)
    pairs that must appear in order (not necessarily consecutively).
    """
    sequence = sig.get("sequence")
    if not sequence:
        return None

    evidence: List[str] = []
    matched_events: List[Dict[str, Any]] = []

    seq_idx = 0
    for event in events:
        if seq_idx >= len(sequence):
            break

        req_type, condition = sequence[seq_idx]

        if event["type"] != req_type:
            continue

        # Check condition
        if condition and not _check_sequence_condition(event, condition, network_dests):
            continue

        # Match found for this step
        desc = _describe_event(event, condition)
        evidence.append(f"Step {seq_idx + 1}: {desc}")
        matched_events.append(event)
        seq_idx += 1

    if seq_idx < len(sequence):
        # Didn't complete the full sequence
        return None

    return _build_result(sig, evidence, matched_events)


# --------------------------------------------------------------------------- #
#  Condition checkers
# --------------------------------------------------------------------------- #


def _check_sequence_condition(
    event: Dict[str, Any],
    condition: str,
    network_dests: List[Dict[str, Any]],
) -> bool:
    """
    Check a single sequence condition against an event.

    Conditions:
      "external"        — connect to non-loopback, non-registry IP
      "shell"           — execve of /bin/sh, /bin/bash, etc.
      "non_standard"    — execve of a binary NOT in BENIGN_BINARIES
      "sensitive"       — openat of a sensitive file (matches parser's logic)
      "secret"          — openat of .env, .npmrc, .aws, .ssh, etc.
      "cron_path"       — openat/write to crontab-related paths
      "pool_port"       — connect to a known mining pool port
      "exfil_host"      — connect to a known paste/file-share host
      "PROT_EXEC"       — mprotect with PROT_EXEC flag
      null/None         — always matches
    """
    if condition is None:
        return True

    evt_type = event["type"]
    target = event.get("target", "")
    details = event.get("details", {})

    if condition == "external":
        if evt_type == "connect":
            cat = details.get("category", "") if isinstance(details, dict) else ""
            # Any connection that isn't to a known-safe registry counts as external
            return cat != "safe_registry"
        return False

    if condition == "shell":
        if evt_type == "execve":
            shell_binaries = {"/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash",
                              "/usr/bin/sh", "/usr/bin/bash"}
            return target in shell_binaries
        return False

    if condition == "non_standard":
        if evt_type == "execve":
            return target not in BENIGN_BINARIES
        return False

    if condition == "sensitive":
        sensitive_patterns = [
            "/etc/shadow", "/etc/passwd", ".aws/", ".ssh/",
            ".npmrc", ".pypirc", ".env", ".git-credentials",
            "/proc/self/environ", "/root/.bash_history",
            "/var/run/secrets",
        ]
        return any(p in target for p in sensitive_patterns)

    if condition == "secret":
        secret_patterns = [".env", ".npmrc", ".aws/credentials", ".ssh/id_rsa"]
        return any(p in target for p in secret_patterns)

    if condition == "cron_path":
        cron_patterns = ["/var/spool/cron", "crontab", "/etc/cron.d",
                         "/etc/crontab", ".cron"]
        return any(p in target for p in cron_patterns)

    if condition == "pool_port":
        if evt_type == "connect":
            port_str = target.split(":")[-1] if ":" in target else ""
            pool_ports = {"3333", "4444", "14444", "45700", "8333", "9999", "14433"}
            # Handle both decimal and hex port formats
            try:
                port_num = int(port_str, 16) if port_str.lower().startswith("0x") else int(port_str)
                return str(port_num) in pool_ports
            except ValueError:
                return port_str in pool_ports
        return False

    if condition == "exfil_host":
        if evt_type == "connect":
            ip = target.split(":")[0] if ":" in target else target
            exfil_hosts = {
                "pastebin.com", "transfer.sh", "file.io", "0x0.st",
                "termbin.com", "ptpb.pw", "hastebin.com", "paste.ee",
                "rentry.co", "ghostbin.co", "dpaste.com", "paste.ubuntu.com",
            }
            # We can't do DNS reverse lookup on IPs, so check if the IP
            # is NOT in our known-safe list (i.e., it's an unknown external)
            is_unknown = not any(ip.startswith(p) for p in KNOWN_SAFE_NETWORKS)
            return is_unknown
        return False

    if condition == "PROT_EXEC":
        if evt_type == "mprotect":
            # Check event details first (set by parser), fall back to target string
            details = event.get("details", {})
            if isinstance(details, dict) and details.get("has_prot_exec"):
                return True
            return "PROT_EXEC" in target
        return False

    return False


# --------------------------------------------------------------------------- #
#  File pattern matching
# --------------------------------------------------------------------------- #


def _check_file_patterns(
    events: List[Dict[str, Any]],
    patterns: List[str],
) -> Optional[Dict[str, Any]]:
    """
    Check if any event's target matches any of the file patterns.

    Returns {"evidence": [...], "events": [...]} or None.
    """
    evidence: List[str] = []
    matched: List[Dict[str, Any]] = []

    for event in events:
        if event["type"] not in ("openat", "read", "write"):
            continue
        target = event.get("target", "")
        for pat in patterns:
            if pat in target:
                evidence.append(f"Accessed sensitive file: {target} (matches pattern '{pat}')")
                matched.append(event)
                break  # one pattern match per event is enough

    if not matched:
        return None

    return {"evidence": evidence, "events": matched}


# --------------------------------------------------------------------------- #
#  Network pattern matching
# --------------------------------------------------------------------------- #


def _check_network_patterns(
    events: List[Dict[str, Any]],
    network_dests: List[Dict[str, Any]],
    rules: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """
    Check network events against the signature's network rules.

    Rules may specify:
      ports: list of port numbers to flag
      known_hosts: list of hostnames to flag
      ip_patterns: list of IP prefix patterns (unused for now, reserved)

    Returns {"evidence": [...], "events": [...]} or None.
    """
    required_ports = set(rules.get("ports", []))
    known_hosts = rules.get("known_hosts", [])

    if not required_ports and not known_hosts:
        # No network rules means "any external connection" suffices
        # Check if there's at least one connect event
        connect_events = [e for e in events if e["type"] == "connect"]
        if connect_events:
            return {
                "evidence": [f"Outbound connection: {e['target']}" for e in connect_events[:3]],
                "events": connect_events,
            }
        return None

    evidence: List[str] = []
    matched: List[Dict[str, Any]] = []

    for event in events:
        if event["type"] != "connect":
            continue
        target = event.get("target", "")
        details = event.get("details", {})
        ip = target.split(":")[0] if ":" in target else target
        port_str = target.split(":")[-1] if ":" in target else ""

        try:
            port = int(port_str, 16) if port_str.lower().startswith("0x") else int(port_str)
        except ValueError:
            port = 0

        # Check port match
        if required_ports and port in required_ports:
            evidence.append(f"Connection to suspicious port {port}: {target}")
            matched.append(event)
            continue

        # Check known host match (by IP prefix — approximate)
        if known_hosts:
            # We don't have DNS resolution, so we check if the IP is
            # NOT in our known-safe list (suspicious external)
            is_unknown = not any(ip.startswith(p) for p in KNOWN_SAFE_NETWORKS)
            is_external = details.get("category", "") in ("suspicious", "unknown")
            if is_unknown and is_external:
                evidence.append(f"Connection to external host: {target}")
                matched.append(event)

    if not matched:
        return None

    return {"evidence": evidence, "events": matched}


# --------------------------------------------------------------------------- #
#  Result building
# --------------------------------------------------------------------------- #


def _describe_event(event: Dict[str, Any], condition: Optional[str]) -> str:
    """Human-readable description of an event in context of a condition."""
    evt_type = event["type"]
    target = event.get("target", "")

    if evt_type == "connect":
        return f"connect {target}"
    if evt_type == "execve":
        return f"execve {target}"
    if evt_type in ("openat", "read", "write"):
        return f"{evt_type} {target}"
    if evt_type == "mprotect":
        return f"mprotect ({target})"
    if evt_type == "dup2":
        return f"dup2 (fd redirection)"
    return f"{evt_type} {target}"


def _build_result(
    sig: Dict[str, Any],
    evidence: List[str],
    matched_events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build the final matched signature dict."""
    return {
        "name": sig["name"],
        "description": sig["description"],
        "severity": sig["severity"],
        "evidence": evidence,
        "matched_events": matched_events,
        "confidence_boost": sig.get("confidence_boost", 0.0),
    }
