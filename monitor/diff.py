"""
Diff-Based Behavioral Comparison for TraceTree.

Compares two analysis results (parsed_data + graph_data dicts) to identify
behavioral differences. Useful for:
  - Comparing a suspicious package against a known-clean version
  - Detecting typosquatting by comparing against the legitimate package
  - Regression testing after package updates

Usage:
    from monitor.diff import diff_analysis

    diff = diff_analysis(result_a, result_b)
    print(diff["summary"])
"""

import logging
from typing import Dict, Any, List, Optional

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
#  Public API
# --------------------------------------------------------------------------- #


def diff_analysis(
    result_a: Dict[str, Any],
    result_b: Dict[str, Any],
    label_a: str = "baseline",
    label_b: str = "candidate",
) -> Dict[str, Any]:
    """
    Compare two analysis results and produce a behavioral diff.

    Args:
        result_a: Dict from a previous analysis (keys: parsed_data, graph_data,
                  signature_matches, temporal_patterns, yara_matches, ngram_data).
        result_b: Dict from the new analysis to compare against A.
        label_a: Human-readable label for result A.
        label_b: Human-readable label for result B.

    Returns:
        Dict with keys:
          - summary: One-line summary of the diff.
          - verdict: "similar", "divergent", or "suspicious".
          - syscall_diff: Dict of added/removed/changed syscall counts.
          - network_diff: Dict of added/removed network destinations.
          - file_diff: Dict of added/removed file accesses.
          - signature_diff: Dict of signatures only in A or only in B.
          - severity_diff: Change in total/max severity.
          - ngram_similarity: Float 0.0-1.0 (from n-gram module if available).
          - details: List of human-readable diff observations.
    """
    parsed_a = result_a.get("parsed_data", {})
    parsed_b = result_b.get("parsed_data", {})
    graph_a = result_a.get("graph_data", {})
    graph_b = result_b.get("graph_data", {})
    sigs_a = result_a.get("signature_matches", [])
    sigs_b = result_b.get("signature_matches", [])
    ngrams_a = result_a.get("ngram_data", {})
    ngrams_b = result_b.get("ngram_data", {})

    details: List[str] = []

    # --- Syscall count diff ---
    events_a = parsed_a.get("events", [])
    events_b = parsed_b.get("events", [])
    syscall_counts_a = _count_syscall_types(events_a)
    syscall_counts_b = _count_syscall_types(events_b)

    added_syscalls = {}
    removed_syscalls = {}
    changed_syscalls = {}
    all_types = set(syscall_counts_a.keys()) | set(syscall_counts_b.keys())
    for stype in all_types:
        count_a = syscall_counts_a.get(stype, 0)
        count_b = syscall_counts_b.get(stype, 0)
        if count_a == 0 and count_b > 0:
            added_syscalls[stype] = count_b
        elif count_a > 0 and count_b == 0:
            removed_syscalls[stype] = count_a
        elif count_a != count_b:
            changed_syscalls[stype] = (count_a, count_b)

    syscall_diff = {
        "added": added_syscalls,
        "removed": removed_syscalls,
        "changed": changed_syscalls,
    }

    if added_syscalls:
        details.append(f"[bold]{label_b}[/] introduces {len(added_syscalls)} new syscall type(s): "
                       f"{', '.join(added_syscalls.keys())}")
    if removed_syscalls:
        details.append(f"[bold]{label_b}[/] removes {len(removed_syscalls)} syscall type(s) "
                       f"present in [bold]{label_a}[/]")

    # --- Network destination diff ---
    net_a = _extract_network_destinations(events_a)
    net_b = _extract_network_destinations(events_b)
    net_added = net_b - net_a
    net_removed = net_a - net_b
    network_diff = {
        "added": sorted(net_added),
        "removed": sorted(net_removed),
    }
    if net_added:
        details.append(f"[bold]{label_b}[/] connects to {len(net_added)} new destination(s): "
                       f"{', '.join(sorted(net_added)[:5])}")

    # --- File access diff ---
    files_a = _extract_file_accesses(events_a)
    files_b = _extract_file_accesses(events_b)
    files_added = files_b - files_a
    files_removed = files_a - files_b
    file_diff = {
        "added": sorted(files_added)[:20],
        "removed": sorted(files_removed)[:20],
    }
    if files_added:
        sensitive_added = [f for f in files_added if _is_sensitive_file(f)]
        if sensitive_added:
            details.append(f"[bold red]⚠[/] [bold]{label_b}[/] accesses {len(sensitive_added)} "
                           f"new sensitive file(s): {', '.join(sorted(sensitive_added)[:5])}")

    # --- Signature diff ---
    sig_names_a = {s["name"] for s in sigs_a}
    sig_names_b = {s["name"] for s in sigs_b}
    sig_diff = {
        "only_in_a": sorted(sig_names_a - sig_names_b),
        "only_in_b": sorted(sig_names_b - sig_names_a),
    }
    if sig_diff["only_in_b"]:
        details.append(f"[bold red]⚠[/] [bold]{label_b}[/] triggers {len(sig_diff['only_in_b'])} "
                       f"signature(s) not seen in [bold]{label_a}[/]: "
                       f"{', '.join(sig_diff['only_in_b'][:5])}")

    # --- Severity diff ---
    stats_a = graph_a.get("stats", {})
    stats_b = graph_b.get("stats", {})
    severity_diff = {
        "total_a": stats_a.get("total_severity", 0.0),
        "total_b": stats_b.get("total_severity", 0.0),
        "max_a": stats_a.get("max_severity", 0.0),
        "max_b": stats_b.get("max_severity", 0.0),
    }
    total_delta = severity_diff["total_b"] - severity_diff["total_a"]
    if total_delta > 5.0:
        details.append(f"[bold red]⚠[/] Total severity increased by [bold]{total_delta:.1f}[/] "
                       f"({severity_diff['total_a']:.1f} → {severity_diff['total_b']:.1f})")

    # --- N-gram similarity ---
    ngram_similarity = 0.0
    if ngrams_a and ngrams_b:
        try:
            from monitor.ngrams import ngram_similarity as _ngram_sim
            ngram_similarity = _ngram_sim(ngrams_a, ngrams_b)
        except ImportError:
            pass

    # --- Verdict ---
    verdict = _compute_verdict(
        added_syscalls=added_syscalls,
        net_added=net_added,
        sensitive_files_added=len([f for f in files_added if _is_sensitive_file(f)]),
        new_sigs=len(sig_diff["only_in_b"]),
        severity_delta=total_delta,
        ngram_similarity=ngram_similarity,
    )

    # --- Summary ---
    if verdict == "suspicious":
        summary = f"[bold red]SUSPICIOUS[/] — {label_b} exhibits significant behavioral divergence from {label_a}"
    elif verdict == "divergent":
        summary = f"[bold yellow]DIVERGENT[/] — {label_b} differs from {label_a} in notable ways"
    else:
        summary = f"[bold green]SIMILAR[/] — {label_b} behaves similarly to {label_a}"

    return {
        "summary": summary,
        "verdict": verdict,
        "syscall_diff": syscall_diff,
        "network_diff": network_diff,
        "file_diff": file_diff,
        "signature_diff": sig_diff,
        "severity_diff": severity_diff,
        "ngram_similarity": round(ngram_similarity, 4),
        "details": details,
    }


# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #


def _count_syscall_types(events: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count occurrences of each syscall type."""
    counts: Dict[str, int] = {}
    for evt in events:
        stype = evt.get("type", "unknown")
        counts[stype] = counts.get(stype, 0) + 1
    return counts


def _extract_network_destinations(events: List[Dict[str, Any]]) -> set:
    """Extract unique network destinations from events."""
    dests = set()
    for evt in events:
        if evt.get("type") == "connect":
            dests.add(evt.get("target", ""))
    return dests


def _extract_file_accesses(events: List[Dict[str, Any]]) -> set:
    """Extract unique file paths from events."""
    files = set()
    for evt in events:
        if evt.get("type") in ("openat", "read", "write", "unlink"):
            target = evt.get("target", "")
            if target and not target.startswith("/proc/") and not target.startswith("/dev/"):
                files.add(target)
    return files


def _is_sensitive_file(path: str) -> bool:
    """Check if a file path is considered sensitive."""
    sensitive = [
        "/etc/shadow", "/etc/passwd", ".aws/", ".ssh/",
        ".npmrc", ".pypirc", ".env", ".git-credentials",
        "/proc/self/environ", "/root/.bash_history",
        "/var/run/secrets",
    ]
    return any(p in path for p in sensitive)


def _compute_verdict(
    added_syscalls: dict,
    net_added: set,
    sensitive_files_added: int,
    new_sigs: int,
    severity_delta: float,
    ngram_similarity: float,
) -> str:
    """Compute a diff verdict: similar, divergent, or suspicious."""
    score = 0

    # New syscall types (especially network/privilege ones)
    dangerous_syscalls = {"connect", "execve", "setuid", "setgid", "mprotect"}
    for sc in added_syscalls:
        if sc in dangerous_syscalls:
            score += 3
        else:
            score += 1

    # New network destinations
    score += min(len(net_added), 5)

    # New sensitive file accesses
    score += sensitive_files_added * 3

    # New signature matches
    score += new_sigs * 5

    # Severity increase
    if severity_delta > 20:
        score += 5
    elif severity_delta > 10:
        score += 3
    elif severity_delta > 5:
        score += 1

    # N-gram similarity (low similarity = more suspicious)
    if ngram_similarity < 0.3:
        score += 3
    elif ngram_similarity < 0.5:
        score += 1

    if score >= 15:
        return "suspicious"
    elif score >= 5:
        return "divergent"
    return "similar"
