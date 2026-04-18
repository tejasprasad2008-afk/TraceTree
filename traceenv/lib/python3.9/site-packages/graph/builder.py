import networkx as nx
from typing import Dict, Any, List, Optional

# Time window (milliseconds) for creating temporal edges between events
_TEMPORAL_WINDOW_MS = 5000.0


def build_cascade_graph(
    parsed_data: Dict[str, Any],
    signature_matches: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Builds a NetworkX directed graph from the parsed strace events.

    Node types: process, network, file
    Edges carry syscall labels and severity weights.
    Nodes/edges that match a behavioral signature are tagged with
    ``signature_tags`` (a set of signature names).
    Consecutive events from the same PID within a time window get
    ``temporal`` edges with ``time_delta_ms``.

    Args:
        parsed_data: Output of ``monitor.parser.parse_strace_log()``.
        signature_matches: Optional list of matched signature dicts
            from ``monitor.signatures.match_signatures()``.  When provided,
            nodes and edges referenced by matched events are tagged.

    Returns:
        A dictionary with Cytoscape-format nodes/edges, graph stats,
        and the raw NetworkX DiGraph.
    """
    G = nx.DiGraph()
    processes = parsed_data.get("processes", {})
    parent_map = parsed_data.get("parent_map", {})
    events = parsed_data.get("events", [])

    # Build a lookup: event index → list of signature names that matched it
    sig_tags_by_event: Dict[int, set] = {}
    if signature_matches:
        for match in signature_matches:
            sig_name = match["name"]
            for evt in match.get("matched_events", []):
                # Find the event index in the original events list
                try:
                    idx = events.index(evt)
                except ValueError:
                    continue
                sig_tags_by_event.setdefault(idx, set()).add(sig_name)

    # 1. Map all processes first
    for pid, proc in processes.items():
        label = proc.get("command", f"PID:{pid}")
        G.add_node(pid, label=label, type="process", severity=0.0, signature_tags=[])

    # 2. Attach Process-to-Process fork/clone lineage
    for child_pid, parent_pid in parent_map.items():
        if parent_pid in G and child_pid in G:
            G.add_edge(parent_pid, child_pid, label="clone", severity=1.0, signature_tags=[])

    # 3. Inject syscall target nodes with severity weights and signature tags
    for evt_idx, event in enumerate(events):
        pid = event["pid"]
        target = event["target"]
        evt_type = event["type"]
        severity = event.get("severity", 0.0)
        tags = sorted(sig_tags_by_event.get(evt_idx, set()))

        if pid not in G:
            G.add_node(pid, label=f"PID:{pid}", type="process", severity=0.0, signature_tags=[])

        if evt_type == "connect":
            node_id = f"net_{target}"
            details = event.get("details", {})
            category = details.get("category", "unknown") if isinstance(details, dict) else "unknown"
            risk = details.get("risk_score", 0.0) if isinstance(details, dict) else 0.0
            G.add_node(
                node_id,
                label=target,
                type="network",
                severity=risk,
                destination_category=category,
                signature_tags=tags,
            )
            G.add_edge(pid, node_id, label="connect", severity=risk, signature_tags=tags)

        elif evt_type == "openat":
            node_id = f"file_{target}"
            sensitive = event.get("details", {}).get("sensitive", False) if isinstance(event.get("details"), dict) else False
            G.add_node(
                node_id,
                label=target,
                type="file",
                severity=8.0 if sensitive else 0.5,
                signature_tags=tags,
            )
            G.add_edge(pid, node_id, label="openat", severity=8.0 if sensitive else 0.5, signature_tags=tags)

        elif evt_type in ("sendto", "socket"):
            node_id = f"sock_{target}"
            G.add_node(node_id, label=target, type="network", severity=severity, signature_tags=tags)
            G.add_edge(pid, node_id, label=evt_type, severity=severity, signature_tags=tags)

        elif evt_type in ("execve", "dup2", "mmap", "mprotect", "chmod",
                          "unlink", "unlinkat", "read", "write",
                          "getaddrinfo", "getuid", "geteuid", "getcwd",
                          "pipe", "pipe2", "clone", "fork", "vfork"):
            node_id = f"{evt_type}_{pid}_{target[:40]}"
            G.add_node(node_id, label=target, type=evt_type, severity=severity, signature_tags=tags)
            G.add_edge(pid, node_id, label=evt_type, severity=severity, signature_tags=tags)

    # 4. Add temporal edges between consecutive events from the same PID
    #    within the time window.
    pid_events: Dict[str, List[Dict[str, Any]]] = {}
    for evt in events:
        pid_events.setdefault(evt["pid"], []).append(evt)

    temporal_edge_count = 0
    for pid, pevents in pid_events.items():
        # Sort by sequence_id for correct temporal order
        pevents_sorted = sorted(pevents, key=lambda e: e.get("sequence_id", 0))
        for i in range(len(pevents_sorted) - 1):
            e_a = pevents_sorted[i]
            e_b = pevents_sorted[i + 1]
            time_a = e_a.get("relative_ms", 0.0)
            time_b = e_b.get("relative_ms", 0.0)
            delta = time_b - time_a
            if delta > 0 and delta <= _TEMPORAL_WINDOW_MS:
                node_a_id = f"{e_a['type']}_{e_a['pid']}_{e_a['target'][:40]}"
                node_b_id = f"{e_b['type']}_{e_b['pid']}_{e_b['target'][:40]}"
                if node_a_id in G and node_b_id in G:
                    G.add_edge(
                        node_a_id, node_b_id,
                        label="temporal",
                        severity=0.0,
                        temporal=True,
                        time_delta_ms=round(delta, 2),
                        signature_tags=[],
                    )
                    temporal_edge_count += 1

    # Convert to Cytoscape format
    cyto_nodes = [
        {
            "data": {
                "id": str(n),
                "label": d.get("label", n),
                "type": d.get("type", "unknown"),
                "severity": d.get("severity", 0.0),
                "signature_tags": d.get("signature_tags", []),
            }
        }
        for n, d in G.nodes(data=True)
    ]
    cyto_edges = [
        {
            "data": {
                "source": str(u),
                "target": str(v),
                "label": d.get("label", ""),
                "severity": d.get("severity", 0.0),
                "signature_tags": d.get("signature_tags", []),
                "temporal": d.get("temporal", False),
                "time_delta_ms": d.get("time_delta_ms", 0.0),
            }
        }
        for u, v, d in G.edges(data=True)
    ]

    # Graph stats — extended with severity, destination, signature, and temporal info
    net_nodes = [d for _, d in G.nodes(data=True) if d.get("type") == "network"]
    file_nodes = [d for _, d in G.nodes(data=True) if d.get("type") == "file"]

    graph_stats = {
        "node_count": G.number_of_nodes(),
        "edge_count": G.number_of_edges(),
        "network_conn_count": len(net_nodes),
        "file_read_count": len(file_nodes),
        "total_severity": round(sum(d.get("severity", 0.0) for _, _, d in G.edges(data=True)), 2),
        "max_severity": round(max((d.get("severity", 0.0) for _, _, d in G.edges(data=True)), default=0.0), 2),
        "suspicious_network_count": sum(
            1 for d in net_nodes if d.get("destination_category") == "suspicious"
        ),
        "sensitive_file_count": sum(
            1 for d in file_nodes if d.get("severity", 0) >= 8.0
        ),
        "signature_match_count": len(signature_matches) if signature_matches else 0,
        "temporal_edge_count": temporal_edge_count,
    }

    return {
        "nodes": cyto_nodes,
        "edges": cyto_edges,
        "stats": graph_stats,
        "raw_graph": G,
    }
