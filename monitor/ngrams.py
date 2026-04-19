"""
Syscall N-gram Fingerprinting for TraceTree.

Extracts syscall sequence n-grams from strace logs to create behavioral
fingerprints. These fingerprints can be compared across packages to detect
similar malicious patterns, cluster packages by behavior, and identify
packages that mimic known malware families.

Usage:
    from monitor.ngrams import extract_ngrams, ngram_similarity

    ngrams = extract_ngrams("/path/to/strace.log", n=3)
    sim = ngram_similarity(ngrams_a, ngrams_b)
"""

import logging
from collections import Counter
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
#  N-gram extraction
# --------------------------------------------------------------------------- #

# Syscall categories used to normalize sequences (reduces noise from minor
# variations while preserving behavioral intent).
_SYSCALL_CATEGORY_MAP = {
    # Process creation / control
    "execve": "proc_exec",
    "fork": "proc_fork",
    "vfork": "proc_fork",
    "clone": "proc_fork",
    "clone3": "proc_fork",
    "exit": "proc_exit",
    "exit_group": "proc_exit",
    "wait4": "proc_wait",
    "waitid": "proc_wait",

    # File operations
    "openat": "file_open",
    "open": "file_open",
    "openat2": "file_open",
    "creat": "file_open",
    "read": "file_read",
    "write": "file_write",
    "close": "file_close",
    "unlink": "file_delete",
    "unlinkat": "file_delete",
    "rename": "file_rename",
    "renameat": "file_rename",
    "renameat2": "file_rename",
    "chmod": "file_chmod",
    "fchmod": "file_chmod",
    "fchmodat": "file_chmod",
    "chown": "file_chown",
    "fchown": "file_chown",
    "fchownat": "file_chown",

    # Network operations
    "socket": "net_socket",
    "connect": "net_connect",
    "bind": "net_bind",
    "listen": "net_listen",
    "accept": "net_accept",
    "accept4": "net_accept",
    "sendto": "net_send",
    "sendmsg": "net_send",
    "recvfrom": "net_recv",
    "recvmsg": "net_recv",
    "shutdown": "net_shutdown",

    # Memory operations
    "mmap": "mem_map",
    "mprotect": "mem_protect",
    "munmap": "mem_unmap",
    "brk": "mem_brk",
    "madvise": "mem_advise",

    # IPC
    "pipe": "ipc_pipe",
    "pipe2": "ipc_pipe",
    "shmget": "ipc_shm",
    "shmat": "ipc_shm",
    "msgsnd": "ipc_msg",
    "msgrcv": "ipc_msg",

    # Information gathering
    "getuid": "info_uid",
    "geteuid": "info_uid",
    "getgid": "info_gid",
    "getegid": "info_gid",
    "getcwd": "info_cwd",
    "getpid": "info_pid",
    "getppid": "info_pid",
    "uname": "info_uname",
    "getenv": "info_env",

    # Privilege escalation
    "setuid": "priv_setuid",
    "setgid": "priv_setgid",
    "setreuid": "priv_setuid",
    "setregid": "priv_setgid",
    "capset": "priv_cap",

    # Time
    "clock_gettime": "time_get",
    "nanosleep": "time_sleep",
    "sleep": "time_sleep",
}


def extract_ngrams(
    log_path: str,
    n: int = 3,
    max_ngrams: int = 500,
) -> Dict[str, Any]:
    """
    Extract syscall n-grams from a strace log.

    Args:
        log_path: Path to the strace log file.
        n: N-gram size (default 3 for trigrams).
        max_ngrams: Maximum number of distinct n-grams to return.

    Returns:
        Dict with keys:
          - ngrams: dict of {ngram_tuple: count}
          - categories: list of syscall categories in order
          - total_syscalls: total number of syscalls parsed
          - unique_ngrams: count of distinct n-grams
          - top_ngrams: list of (ngram, count) tuples, sorted by frequency
          - fingerprint: SHA-256 hash string of the top-50 n-grams (for comparison)
    """
    import hashlib

    categories = _parse_syscall_categories(log_path)
    if not categories:
        return {
            "ngrams": {},
            "categories": [],
            "total_syscalls": 0,
            "unique_ngrams": 0,
            "top_ngrams": [],
            "fingerprint": "",
        }

    # Generate n-grams
    ngram_counts = Counter()
    for i in range(len(categories) - n + 1):
        ngram = tuple(categories[i : i + n])
        ngram_counts[ngram] += 1

    total_syscalls = len(categories)
    unique_ngrams = len(ngram_counts)

    # Get top n-grams (capped)
    top_ngrams = ngram_counts.most_common(max_ngrams)

    # Create a deterministic fingerprint from the top 50 n-grams
    fingerprint_input = "|".join(
        f"{','.join(ng)}:{cnt}" for ng, cnt in ngram_counts.most_common(50)
    )
    fingerprint = hashlib.sha256(fingerprint_input.encode()).hexdigest()  # full 64-char SHA-256

    # Convert tuple keys to string for JSON serialization
    ngrams_serializable = {",".join(ng): cnt for ng, cnt in ngram_counts.items()}

    return {
        "ngrams": ngrams_serializable,
        "categories": categories,
        "total_syscalls": total_syscalls,
        "unique_ngrams": unique_ngrams,
        "top_ngrams": [(",".join(ng), cnt) for ng, cnt in top_ngrams],
        "fingerprint": fingerprint,
    }


def _parse_syscall_categories(log_path: str) -> List[str]:
    """
    Parse a strace log and return a list of syscall categories in order.
    Streams the file line-by-line to avoid loading entire file into memory.
    """
    categories: List[str] = []
    max_lines = 500000  # Cap at 500K lines to prevent OOM on massive strace logs
    line_count = 0

    try:
        with open(log_path, 'r', errors='replace') as f:
            for line in f:
                line_count += 1
                if line_count > max_lines:
                    log.warning("Strace log truncated at %d lines (max %d)", line_count, max_lines)
                    break

                line = line.strip()
                if not line:
                    continue

                # Strace -f -t format: [PID] timestamp syscall(args) = result
                # Example: "1234 12:34:56.789012 open(\"/etc/passwd\", O_RDONLY) = 3"
                # or: "1234 <... open resumed>) = 3"
                parts = line.split(None, 3)
                if len(parts) < 2:
                    continue

                idx = 0
                # Skip numeric PID token if present
                if parts[idx].isdigit():
                    idx += 1
                # Skip timestamp token (contains ':') if present
                if idx < len(parts) and ':' in parts[idx]:
                    idx += 1
                # Now parts[idx] should be the syscall token
                if idx >= len(parts):
                    continue

                syscall = parts[idx]
                if syscall.startswith("<..."):
                    # Continuation line — try to find the actual syscall name
                    if idx + 1 < len(parts) and "(" in parts[idx + 1]:
                        syscall = parts[idx + 1].split("(")[0]
                    else:
                        continue
                elif "(" in syscall:
                    syscall = syscall.split("(")[0]

                # Map to category
                category = _SYSCALL_CATEGORY_MAP.get(syscall, syscall)
                categories.append(category)
    except Exception as e:
        log.warning("Failed to read strace log for n-gram extraction: %s", e)
        return []

    return categories


# --------------------------------------------------------------------------- #
#  Similarity metrics
# --------------------------------------------------------------------------- #


def ngram_similarity(
    ngrams_a: Dict[str, Any],
    ngrams_b: Dict[str, Any],
) -> float:
    """
    Compute Jaccard-like similarity between two n-gram fingerprint dicts.

    Returns a float between 0.0 (completely different) and 1.0 (identical).
    """
    set_a = set(ngrams_a.get("ngrams", {}).keys())
    set_b = set(ngrams_b.get("ngrams", {}).keys())

    if not set_a or not set_b:
        return 0.0

    intersection = len(set_a & set_b)
    union = len(set_a | set_b)

    return intersection / union if union > 0 else 0.0


def weighted_ngram_similarity(
    ngrams_a: Dict[str, Any],
    ngrams_b: Dict[str, Any],
) -> float:
    """
    Compute weighted cosine similarity between two n-gram frequency vectors.

    More accurate than Jaccard for comparing behavioral fingerprints because
    it accounts for n-gram frequencies, not just presence/absence.
    """
    import math

    vec_a = ngrams_a.get("ngrams", {})
    vec_b = ngrams_b.get("ngrams", {})

    if not vec_a or not vec_b:
        return 0.0

    # Union of all keys
    all_keys = set(vec_a.keys()) | set(vec_b.keys())

    # Dot product
    dot = sum(float(vec_a.get(k, 0)) * float(vec_b.get(k, 0)) for k in all_keys)

    # Magnitudes
    mag_a = math.sqrt(sum(float(v) ** 2 for v in vec_a.values()))
    mag_b = math.sqrt(sum(float(v) ** 2 for v in vec_b.values()))

    if mag_a == 0 or mag_b == 0:
        return 0.0

    return dot / (mag_a * mag_b)


# --------------------------------------------------------------------------- #
#  Suspicious n-gram detection
# --------------------------------------------------------------------------- #

# Known suspicious n-gram patterns commonly seen in malware
_SUSPICIOUS_NGRAMS = {
    "net_connect,net_send,file_write": "Network exfiltration pattern",
    "net_connect,proc_exec,net_send": "C2 communication with command execution",
    "file_open,info_uid,file_read": "Credential harvesting pattern",
    "proc_fork,proc_exec,net_connect": "Spawn and connect pattern",
    "mem_protect,proc_exec": "Executable memory injection",
    "info_cwd,file_open,file_read": "Reconnaissance pattern",
    "file_chmod,proc_exec": "Make executable and run",
    "net_connect,net_recv,file_write": "Download and save pattern",
    "priv_setuid,proc_exec": "Privilege escalation pattern",
    "file_open,file_write,file_delete": "Overwrite and cleanup pattern",
}


def detect_suspicious_ngrams(
    ngrams: Dict[str, Any],
) -> List[Dict[str, str]]:
    """
    Check extracted n-grams against known suspicious patterns.

    Returns a list of dicts with keys: ngram, description, count.
    """
    suspicious: List[Dict[str, str]] = []
    ngram_counts = ngrams.get("ngrams", {})

    for pattern, description in _SUSPICIOUS_NGRAMS.items():
        if pattern in ngram_counts:
            suspicious.append({
                "ngram": pattern,
                "description": description,
                "count": str(ngram_counts[pattern]),
            })

    return suspicious
