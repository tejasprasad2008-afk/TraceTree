import time
import tracemalloc
from typing import List, Dict, Any
from monitor.diff import diff_analysis

def generate_synthetic_events(count: int) -> List[Dict[str, Any]]:
    events = []
    syscall_types = ["openat", "read", "write", "connect", "execve", "unlink", "mmap"]
    for i in range(count):
        stype = syscall_types[i % len(syscall_types)]
        event = {
            "type": stype,
            "pid": "1234",
            "timestamp": "12:00:00.000000",
        }
        if stype == "connect":
            event["target"] = f"192.168.1.{i % 255}"
        elif stype in ("openat", "read", "write", "unlink"):
            event["target"] = f"/tmp/file_{i % 1000}"
        elif stype == "execve":
            event["target"] = "/usr/bin/ls"

        events.append(event)
    return events

def run_benchmark(event_count: int):
    print(f"\n--- Benchmarking with {event_count:,} events ---")

    events_a = generate_synthetic_events(event_count)
    events_b = generate_synthetic_events(event_count)

    # Add some differences
    events_b.append({"type": "connect", "target": "8.8.8.8", "pid": "1234"})
    events_b.append({"type": "openat", "target": "/etc/shadow", "pid": "1234"})

    result_a = {"parsed_data": {"events": events_a}, "graph_data": {"stats": {}}}
    result_b = {"parsed_data": {"events": events_b}, "graph_data": {"stats": {}}}

    tracemalloc.start()
    start_time = time.perf_counter()

    # Run diff_analysis multiple times for better measurement if event_count is small
    iterations = 10 if event_count < 100000 else 1
    for _ in range(iterations):
        _ = diff_analysis(result_a, result_b)

    end_time = time.perf_counter()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    avg_duration = (end_time - start_time) / iterations
    print(f"Average Execution Time: {avg_duration:.4f} seconds")
    print(f"Peak Memory Usage: {peak / 1024 / 1024:.2f} MB")

if __name__ == "__main__":
    for count in [10000, 100000, 500000]:
        run_benchmark(count)
