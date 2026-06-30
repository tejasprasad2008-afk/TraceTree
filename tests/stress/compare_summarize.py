import time
import tracemalloc
from typing import List, Dict, Any

# --- Original Implementation (simulated) ---

def _count_syscall_types_orig(events: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for evt in events:
        stype = evt.get("type", "unknown")
        counts[stype] = counts.get(stype, 0) + 1
    return counts

def _extract_network_destinations_orig(events: List[Dict[str, Any]]) -> set:
    dests = set()
    for evt in events:
        if evt.get("type") == "connect":
            dests.add(evt.get("target", ""))
    return dests

def _extract_file_accesses_orig(events: List[Dict[str, Any]]) -> set:
    files = set()
    for evt in events:
        if evt.get("type") in ("openat", "read", "write", "unlink"):
            target = evt.get("target", "")
            if target and not target.startswith("/proc/") and not target.startswith("/dev/"):
                files.add(target)
    return files

def original_summarize(events: List[Dict[str, Any]]):
    counts = _count_syscall_types_orig(events)
    net = _extract_network_destinations_orig(events)
    files = _extract_file_accesses_orig(events)
    return counts, net, files

# --- New Implementation ---
from monitor.diff import _summarize_events

def generate_synthetic_events(count: int) -> List[Dict[str, Any]]:
    events = []
    syscall_types = ["openat", "read", "write", "connect", "execve", "unlink", "mmap"]
    for i in range(count):
        stype = syscall_types[i % len(syscall_types)]
        event = {
            "type": stype,
            "pid": "1234",
            "target": f"/tmp/file_{i % 1000}" if stype != "connect" else f"1.1.1.{i%255}"
        }
        events.append(event)
    return events

def run_bench(count: int):
    print(f"\n--- Comparing {count:,} events ---")
    events = generate_synthetic_events(count)

    # Baseline
    start = time.perf_counter()
    for _ in range(10):
        _ = original_summarize(events)
    duration_orig = (time.perf_counter() - start) / 10

    # Optimized
    start = time.perf_counter()
    for _ in range(10):
        _ = _summarize_events(events)
    duration_opt = (time.perf_counter() - start) / 10

    improvement = (duration_orig - duration_opt) / duration_orig * 100
    print(f"Original:  {duration_orig:.4f}s")
    print(f"Optimized: {duration_opt:.4f}s")
    print(f"Speedup:   {improvement:.2f}%")

if __name__ == "__main__":
    for c in [10000, 100000, 500000]:
        run_bench(c)
