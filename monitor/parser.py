import re
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path

# --------------------------------------------------------------------------- #
#  Syscall severity weights
#  Higher number = more likely to be part of a malicious chain.
#  A value of 0 means "benign in isolation" but still tracked.
# --------------------------------------------------------------------------- #

SEVERITY_WEIGHTS: Dict[str, float] = {
    # Process execution — critical when target is suspicious
    "execve": 5.0,
    "clone": 1.0,
    "fork": 1.0,
    "vfork": 1.0,
    # Network — high when destination is unknown/suspicious
    "connect": 1.0,
    "sendto": 2.0,
    "socket": 2.0,
    # File access — high for sensitive paths
    "openat": 0.5,
    "read": 0.1,
    "write": 0.2,
    # Privilege / persistence
    "chmod": 1.5,
    "chown": 1.0,
    # Cleanup / anti-forensics
    "unlink": 0.5,
    "unlinkat": 0.5,
    # Memory (code injection vector)
    "mmap": 0.5,
    "mprotect": 2.0,
    "madvise": 0.1,
    # DNS resolution
    "getaddrinfo": 0.3,
    # Environment / user info
    "getuid": 0.1,
    "geteuid": 0.1,
    "getcwd": 0.1,
    # Pipes / IPC (used in C2)
    "pipe": 0.5,
    "pipe2": 0.5,
    "dup2": 2.0,
}

# Known-benign binaries that are expected during a normal pip/npm install.
# execve of anything else raises a severity-adjusted flag.
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

# Paths that are clearly benign when accessed during an install.
BENIGN_PATH_PREFIXES = (
    "/usr/lib/python",
    "/usr/local/lib/python",
    "/usr/local/lib/node",
    "/usr/lib/node",
    "/tmp/",
    "/var/cache",
    "/home/node",
    "/root/.cache",
    "/root/.npm",
    "/root/.local",
    "/usr/include",
    "/usr/share",
    "/proc/",
    "/sys/",
    "/etc/ld.so",
    "/etc/gai",
    "/etc/hostname",
    "/etc/resolv",
    "/etc/nsswitch",
    "/etc/hosts",
)

# Known PyPI / npm / package registry destinations — flagged with LOW severity.
KNOWN_SAFE_NETWORKS = frozenset([
    "151.101.",        # PyPI CDN (Fastly)
    "104.16.",         # PyPI (Cloudflare)
    "104.17.",
    "151.101.0.",
    "151.101.64.",
    "151.101.128.",
    "151.101.192.",
    "52.85.",          # npm CDN
    "54.230.",
    "13.107.",         # GitHub / Azure
    "52.96.",
    "40.79.",
    "140.82.121.",     # github.com
    "140.82.112.",
    "185.199.108.",    # raw.githubusercontent.com
    "185.199.109.",
    "185.199.110.",
    "185.199.111.",
    "199.232.",        # npm registry (jsDelivr / CloudFront)
    "99.84.",
    "99.86.",
    "13.224.",         # CloudFront
    "13.225.",
    "13.226.",
    "13.227.",
    "3.160.",
    "3.162.",
    "3.164.",
    "3.165.",
    "3.166.",
    "3.167.",
    "3.168.",
    "99.84.",
    "99.86.",
    "205.251.",        # AWS CloudFront
    "13.249.",
])

# Suspicious destinations — these always raise an alert.
SUSPICIOUS_DEST_PATTERNS = [
    re.compile(r"^169\.254\."),  # cloud metadata endpoint
    re.compile(r"^0\.0\.0\.0$"),
    re.compile(r"^255\."),
]

# Sensitive file patterns for openat/read/write.
SENSITIVE_FILE_PATTERNS = [
    re.compile(r"/etc/passwd"),
    re.compile(r"/etc/shadow"),
    re.compile(r"\.ssh/"),
    re.compile(r"\.aws/"),
    re.compile(r"\.kube/config"),
    re.compile(r"\.env$"),
    re.compile(r"\.npmrc$"),
    re.compile(r"\.pypirc$"),
    re.compile(r"\.git-credentials"),
    re.compile(r"\.netrc"),
    re.compile(r"/proc/self/environ"),
    re.compile(r"/proc/net/"),
    re.compile(r"/proc/\d+/"),
    re.compile(r"/crontab"),
    re.compile(r"^/tmp/\.[^/]+"),   # hidden files in /tmp
    re.compile(r"\.bash_history$"),
    re.compile(r"/etc/cron"),
    re.compile(r"/root/\.bash_history"),
    re.compile(r"/var/run/secrets"),
]

# Known C2 / exfiltration ports.
SUSPICIOUS_PORTS = frozenset([
    4444, 4445, 5555, 8888, 9999, 1337, 31337, 1234, 6666, 6667, 6697,
    8443, 1080, 9001, 9030,
])

# --------------------------------------------------------------------------- #
#  Multi-line strace reassembly
#  strace wraps long lines like:
#    1234 openat(AT_FDCWD, "/very/long/...", O_RDONLY
#    ) = 3
#  We need to join continuation lines until we see " = <result>".
# --------------------------------------------------------------------------- #

_RETURN_RE = re.compile(r"\)\s*=\s*(.+)$")


def _reassemble_lines(lines: List[str]) -> List[str]:
    """
    Join strace continuation lines into complete syscall entries.

    Returns a list where each element is a single logical syscall line.
    """
    assembled: List[str] = []
    current_parts: List[str] = []

    for raw in lines:
        line = raw.rstrip("\n\r")
        if not line:
            continue

        # If we're not accumulating, check if this line starts a syscall.
        if not current_parts:
            # A syscall line can start with:
            #   1. An optional timestamp: HH:MM:SS.ffffff
            #   2. Optional [pid] bracket format OR bare pid
            #   3. The syscall name
            # We need to match BOTH formats:
            #   "100 00:00:00 execve(..."        (bare pid before timestamp)
            #   "00:00:00.000000 [100] execve(..."  (timestamp before bracketed pid)
            _START_RE = re.compile(
                r"^\s*(\d+\s+)?"                      # optional bare pid first
                r"(\d{2}:\d{2}:\d{2}(?:\.\d+)?)?\s*"   # optional timestamp, decimal optional
                r"(?:\[\s*\d+\s*\]\s*)?"       # optional [pid] bracketed
                r"[a-zA-Z_]\w*\("                       # syscall name + paren
            )
            if _START_RE.match(line):
                current_parts.append(line)
                # If this single line already has the return value, emit it immediately
                if _RETURN_RE.search(line):
                    assembled.append(" ".join(current_parts))
                    current_parts = []
            # If it doesn't start a syscall, skip it (strace header, summary, etc.)
            continue

        # We're in the middle of a multi-line entry — keep appending.
        current_parts.append(line)

        # If this line contains the return value, the entry is complete.
        if _RETURN_RE.search(line):
            assembled.append(" ".join(current_parts))
            current_parts = []

    # If a syscall was never terminated with " = ...", emit what we have
    # (happens if strace was killed mid-syscall).
    if current_parts:
        assembled.append(" ".join(current_parts))

    return assembled


# --------------------------------------------------------------------------- #
#  Main parser
# --------------------------------------------------------------------------- #

# Matches:  [pid] syscall_name(args
# With strace -t, lines are prefixed with:  HH:MM:SS.ffffff  [pid] syscall(...)
# The timestamp part is optional (backward compat with un-timestamped logs).
_LINE_RE = re.compile(
    r"""^\s*
        (\d+\s+)?                      # optional bare pid first (non-bracketed)
        (\d{2}:\d{2}:\d{2}(?:\.\d+)?)?\s*   # optional timestamp, decimal optional
        (?:\[\s*(\d+)\s*\]\s*)?       # optional [pid bracketed]
        ([a-zA-Z_]\w*)                 # syscall name
        \((.*)                         # opening paren + rest of args
    """,
    re.VERBOSE,
)

# Matches the return value at the end:  ) = <result>
# Also captures the trailing part after ") =" for return value extraction.
_RET_RE = re.compile(r"\)\s*=\s*(-?\d+)\s*$")


def _classify_destination(ip: str, port: Optional[str] = None) -> Dict[str, Any]:
    """
    Classify a network destination by IP and port.

    Returns:
        {
            "ip": str,
            "port": str or None,
            "category": str,          # "safe_registry" | "known_benign" | "suspicious" | "unknown"
            "risk_score": float,       # 0.0 - 10.0
            "notes": List[str],        # human-readable reasons
        }
    """
    notes: List[str] = []
    category = "unknown"
    risk: float = 3.0  # default: unknown network activity gets a moderate score

    # Check against suspicious patterns first.
    for pat in SUSPICIOUS_DEST_PATTERNS:
        if pat.match(ip):
            category = "suspicious"
            risk = 8.0
            if ip.startswith("169.254"):
                notes.append("Cloud metadata endpoint (169.254.x.x) — common C2/exfil target")
            elif ip.startswith("127."):
                notes.append("Loopback connection — may indicate local service abuse")
            elif ip.startswith(("10.", "172.", "192.168.")):
                notes.append("Private IP range from container — unusual, possible lateral movement")
            break

    # Check known safe registries.
    if category == "unknown":
        for prefix in KNOWN_SAFE_NETWORKS:
            if ip.startswith(prefix):
                category = "safe_registry"
                risk = 0.0
                notes.append("Known package registry / CDN endpoint")
                break

    # Check suspicious ports.
    try:
        port_str = port or ""
        port_num = int(port_str, 16) if port_str.lower().startswith("0x") else int(port_str) if port_str else 0
    except ValueError:
        port_num = 0

    if port_num in SUSPICIOUS_PORTS:
        if category == "unknown":
            category = "suspicious"
            risk = 9.0
        else:
            risk = max(risk, 8.5)
        notes.append(f"Suspicious port {port_num}")

    # Port 443/80 to unknown public IPs should be tracked as external unknown.
    if category == "unknown":
        # Treat private and loopback ranges separately from public IPs.
        if port_num in (80, 443) and not ip.startswith(("10.", "127.", "172.", "192.168.")):
            category = "external_unknown"
            risk = 6.0
            notes.append("Public web service on standard port to unknown host")
        elif port_num not in (80, 443) and port_num != 0:
            category = "suspicious"
            risk = 8.0
            notes.append("Unknown host on non-standard port")

    return {
        "ip": ip,
        "port": port,
        "category": category,
        "risk_score": risk,
        "notes": notes,
    }


def _is_sensitive_path(filepath: str) -> bool:
    """Return True if the file path matches a sensitive file pattern."""
    for pat in SENSITIVE_FILE_PATTERNS:
        if pat.search(filepath):
            return True
    return False


def _is_benign_path(filepath: str) -> bool:
    """Return True if the file path is clearly benign (stdlib / cache / system config)."""
    for prefix in BENIGN_PATH_PREFIXES:
        if filepath.startswith(prefix):
            return True
    return False


def _is_benign_binary(binary: str) -> bool:
    """Return True if the binary is expected during a normal install."""
    return binary in BENIGN_BINARIES


def parse_strace_log(log_path: str) -> Dict[str, Any]:
    """
    Parse a strace log generated by the sandbox.

    Handles:
    - Multi-line syscall entries (strace wraps long args across lines).
    - Optional [pid] prefix format.
    - Syscalls: clone, fork, vfork, execve, connect, openat, read,
      write, unlink, unlinkat, chmod, mmap, mprotect, sendto, socket,
      getaddrinfo, dup2, pipe, pipe2.

    Flags are context-aware:
    - connect to PyPI/npm is NOT flagged as suspicious.
    - connect to 169.254.x.x (cloud metadata), private IPs, or suspicious
      ports IS flagged.
    - openat of /etc/passwd, .ssh/, .env etc. IS flagged.
    - execve of unexpected binaries IS flagged.
    - dup2 + connect chain IS flagged (reverse shell pattern).

    Returns:
        {
            "processes": {pid: {...}},
            "parent_map": {child: parent},
            "events": [{"pid", "type", "target", "severity", "details"}],
            "flags": [unique suspicious flag strings],
            "network_destinations": [{"ip", "port", "category", "risk_score", "notes"}],
            "total_severity_score": float,
        }
    """
    processes: Dict[str, Dict[str, Any]] = {}
    parent_map: Dict[str, str] = {}
    syscalls_executed: List[Dict[str, Any]] = []
    suspicious_flags: List[str] = []
    network_destinations: List[Dict[str, Any]] = []
    total_severity: float = 0.0

    log_file = Path(log_path)
    if not log_file.exists():
        return {
            "processes": {},
            "parent_map": {},
            "events": [],
            "flags": [],
            "network_destinations": [],
            "total_severity_score": 0.0,
        }

    raw_lines = log_file.read_text(encoding="utf-8", errors="ignore").splitlines()
    lines = _reassemble_lines(raw_lines)

    # Temporal tracking: convert timestamps to relative milliseconds from first event
    _first_timestamp_ms: float = 0.0
    _has_timestamps = False

    def _parse_timestamp(ts_str: str) -> float:
        """Convert HH:MM:SS.ffffff to milliseconds since epoch-like zero."""
        if not ts_str:
            return 0.0
        parts = ts_str.split(":")
        if len(parts) != 3:
            return 0.0
        h, m, s = int(parts[0]), int(parts[1]), float(parts[2])
        return (h * 3600 + m * 60 + s) * 1000.0  # ms

    # Track sequences for chain detection: (prev_type, prev_target) per pid
    pid_history: Dict[str, List[str]] = {}
    sequence_id = 0

    for line in lines:
        m = _LINE_RE.match(line)
        if not m:
            continue

        # Regex groups with timestamp: 1=bare_pid, 2=timestamp, 3=[pid], 4=syscall, 5=args
        ts_str = m.group(2)
        pid = m.group(3) or (m.group(1).strip() if m.group(1) else "0")
        syscall = m.group(4)
        args_raw = m.group(5)

        # Parse timestamp
        absolute_ms = _parse_timestamp(ts_str)
        if absolute_ms > 0:
            _has_timestamps = True
            if _first_timestamp_ms == 0:
                _first_timestamp_ms = absolute_ms
        relative_ms = absolute_ms - _first_timestamp_ms if _has_timestamps and _first_timestamp_ms > 0 else 0.0

        # Initialize process record
        if pid not in processes:
            processes[pid] = {
                "pid": pid,
                "command": "unknown",
                "children": [],
                "network": [],
                "files": [],
                "syscall_counts": {},
            }
        proc = processes[pid]
        proc["syscall_counts"][syscall] = proc["syscall_counts"].get(syscall, 0) + 1

        # Severity base for this syscall type
        severity = SEVERITY_WEIGHTS.get(syscall, 0.0)

        # Build common temporal fields for every event
        def _make_event(evt_type: str, target: str, sev: float, details: Dict[str, Any]) -> Dict[str, Any]:
            nonlocal sequence_id
            sequence_id += 1
            return {
                "pid": pid,
                "type": evt_type,
                "target": target,
                "severity": sev,
                "details": details,
                "timestamp": ts_str or "",
                "sequence_id": sequence_id,
                "relative_ms": round(relative_ms, 2),
            }

        # ------------------------------------------------------------------ #
        #  clone / fork / vfork — track parent-child
        # ------------------------------------------------------------------ #
        if syscall in ("clone", "fork", "vfork"):
            res_match = _RET_RE.search(args_raw)
            if res_match:
                child_pid = res_match.group(1)
                parent_map[child_pid] = pid
                proc["children"].append(child_pid)
            syscalls_executed.append(_make_event(
                syscall,
                f"child_pid={res_match.group(1) if res_match else '?'}",
                severity,
                {},
            ))

        # ------------------------------------------------------------------ #
        #  execve — what binary is being launched?
        # ------------------------------------------------------------------ #
        elif syscall == "execve":
            binary_match = re.match(r'"([^"]+)"', args_raw)
            if binary_match:
                target_bin = binary_match.group(1)
                proc["command"] = target_bin.split("/")[-1]
                is_benign = _is_benign_binary(target_bin)
                if not is_benign:
                    severity = max(severity, 7.0)
                    suspicious_flags.append(
                        f"Process {pid} spawned unexpected binary: {target_bin}"
                    )
                syscalls_executed.append(_make_event(
                    "execve",
                    target_bin,
                    severity,
                    {"benign": is_benign},
                ))

        # ------------------------------------------------------------------ #
        #  connect — where is it trying to reach?
        # ------------------------------------------------------------------ #
        elif syscall == "connect":
            ip_match = re.search(r'sin_addr=inet_addr\("([^"]+)"\)', args_raw)
            port_match = re.search(r'sin_port=htons\((0x[0-9a-fA-F]+|[0-9]+)\)', args_raw)
            if ip_match:
                ip = ip_match.group(1)
                port = port_match.group(1) if port_match else None
                target = f"{ip}:{port}" if port else ip

                classification = _classify_destination(ip, port)
                network_destinations.append(classification)
                proc["network"].append(target)

                severity = classification["risk_score"]
                if classification["category"] == "suspicious":
                    for note in classification["notes"]:
                        suspicious_flags.append(f"Network: {target} — {note}")

                syscalls_executed.append(_make_event(
                    "connect",
                    target,
                    severity,
                    classification,
                ))

        # ------------------------------------------------------------------ #
        #  openat / read / write / unlink — file access
        # ------------------------------------------------------------------ #
        elif syscall in ("openat", "read", "write", "unlink", "unlinkat", "chmod"):
            file_match = re.search(r',\s*"([^"]+)"', args_raw)
            if file_match:
                filepath = file_match.group(1)
                proc["files"].append(filepath)

                if _is_sensitive_path(filepath) and not _is_benign_path(filepath):
                    severity = max(severity, 8.0)
                    suspicious_flags.append(
                        f"Sensitive file access ({syscall}): {filepath}"
                    )

                syscalls_executed.append(_make_event(
                    syscall,
                    filepath,
                    severity,
                    {"sensitive": _is_sensitive_path(filepath)},
                ))

        # ------------------------------------------------------------------ #
        #  mmap / mprotect — memory operations (code injection vector)
        # ------------------------------------------------------------------ #
        elif syscall in ("mmap", "mprotect"):
            # mprotect with PROT_EXEC on RW memory is a red flag
            has_prot_exec = "PROT_EXEC" in args_raw
            if has_prot_exec:
                severity = max(severity, 9.0)
                suspicious_flags.append(
                    f"Executable memory mapping ({syscall}) in PID {pid} — possible code injection"
                )
            syscalls_executed.append(_make_event(
                syscall,
                f"flags={args_raw.split(',')[0] if ',' in args_raw else args_raw[:80]}",
                severity,
                {"has_prot_exec": has_prot_exec},
            ))

        # ------------------------------------------------------------------ #
        #  sendto / socket — raw socket creation
        # ------------------------------------------------------------------ #
        elif syscall in ("sendto", "socket"):
            if "AF_INET" in args_raw:
                proc["network"].append("AF_INET_SOCKET")
                severity = max(severity, 5.0)
                suspicious_flags.append(
                    f"Raw socket or sendto (AF_INET) detected in PID {pid}"
                )
                syscalls_executed.append(_make_event(
                    syscall,
                    "AF_INET",
                    severity,
                    {},
                ))

        # ------------------------------------------------------------------ #
        #  dup2 — reverse shell indicator (especially after connect)
        # ------------------------------------------------------------------ #
        elif syscall == "dup2":
            severity = max(severity, 6.0)
            # Check if there was a recent connect in this pid
            hist = pid_history.get(pid, [])
            if "connect" in hist:
                severity = 9.0
                suspicious_flags.append(
                    f"Reverse shell pattern: connect followed by dup2 in PID {pid}"
                )
            syscalls_executed.append(_make_event(
                "dup2",
                "fd_redirection",
                severity,
                {},
            ))

        # ------------------------------------------------------------------ #
        #  getaddrinfo — DNS resolution
        # ------------------------------------------------------------------ #
        elif syscall == "getaddrinfo":
            syscalls_executed.append(_make_event(
                "getaddrinfo",
                "dns_lookup",
                severity,
                {},
            ))

        # ------------------------------------------------------------------ #
        #  getuid / geteuid / getcwd — recon
        # ------------------------------------------------------------------ #
        elif syscall in ("getuid", "geteuid", "getcwd"):
            hist = pid_history.get(pid, [])
            # getuid right after a connect is suspicious (exfil user context)
            if "connect" in hist and syscall in ("getuid", "geteuid"):
                severity = max(severity, 4.0)
            syscalls_executed.append(_make_event(
                syscall,
                syscall,
                severity,
                {},
            ))

        # ------------------------------------------------------------------ #
        #  pipe / pipe2 — IPC (used in C2 channels)
        # ------------------------------------------------------------------ #
        elif syscall in ("pipe", "pipe2"):
            syscalls_executed.append(_make_event(
                syscall,
                "pipe",
                severity,
                {},
            ))

        # ------------------------------------------------------------------ #
        #  Any other syscall — track it but don't flag
        # ------------------------------------------------------------------ #
        else:
            syscalls_executed.append(_make_event(
                syscall,
                "other",
                0.0,
                {},
            ))

        # Update total severity
        total_severity += severity

        # Track per-pid syscall history for chain detection
        if pid not in pid_history:
            pid_history[pid] = []
        pid_history[pid].append(syscall)

    # Detect credential theft chains: clone → execve → openat /etc/shadow
    for evt_list in [syscalls_executed]:
        for i in range(len(evt_list) - 2):
            e0, e1, e2 = evt_list[i], evt_list[i + 1], evt_list[i + 2]
            if (
                e0["type"] in ("clone", "fork", "vfork")
                and e1["type"] == "execve"
                and e2["type"] == "openat"
                and _is_sensitive_path(e2["target"])
            ):
                suspicious_flags.append(
                    f"Credential theft chain detected: "
                    f"PID {e0['pid']} clone→execve→openat {e2['target']}"
                )
                total_severity += 10.0

    return {
        "processes": processes,
        "parent_map": parent_map,
        "events": syscalls_executed,
        "flags": list(set(suspicious_flags)),
        "network_destinations": network_destinations,
        "total_severity_score": round(total_severity, 2),
        "has_timestamps": _has_timestamps,
        "event_count": len(syscalls_executed),
    }
