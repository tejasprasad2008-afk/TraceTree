import networkx as nx
from typing import Dict, Any

def build_cascade_graph(parsed_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Builds a NetworkX directed graph from the parsed strace events.
    Returns a dictionary formatted mapping of the processes and behavioral metrics.
    """
    G = nx.DiGraph()
    processes = parsed_data.get("processes", {})
    parent_map = parsed_data.get("parent_map", {})
    events = parsed_data.get("events", [])
    
    # 1. Map all processes first
    for pid, proc in processes.items():
        label = proc.get("command", f"PID:{pid}")
        G.add_node(pid, label=label, type="process")
        
    # 2. Attach Process-to-Process fork/clone lineage
    for child_pid, parent_pid in parent_map.items():
        if parent_pid in G and child_pid in G:
            G.add_edge(parent_pid, child_pid, label="clone")

    # 3. Inject syscall target nodes recursively
    for event in events:
        pid = event["pid"]
        target = event["target"]
        evt_type = event["type"]
        
        # Ensure process node exists just in case it escaped standard init
        if pid not in G:
            G.add_node(pid, label=f"PID:{pid}", type="process")
            
        if evt_type == "connect":
            node_id = f"net_{target}"
            G.add_node(node_id, label=target, type="network")
            G.add_edge(pid, node_id, label="connect")
            
        elif evt_type == "openat":
            node_id = f"file_{target}"
            G.add_node(node_id, label=target, type="file")
            G.add_edge(pid, node_id, label="openat")
            
        elif evt_type in ("sendto", "socket"):
            node_id = f"sock_{target}"
            G.add_node(node_id, label=target, type="network")
            G.add_edge(pid, node_id, label=evt_type)

    # Convert structural graph mappings
    cyto_nodes = [{"data": {"id": str(n), "label": d.get("label", n), "type": d.get("type", "unknown")}} for n, d in G.nodes(data=True)]
    cyto_edges = [{"data": {"source": str(u), "target": str(v), "label": d.get("label", "")}} for u, v, d in G.edges(data=True)]

    # Compute internal structural constants for the ML isolation forest layer
    graph_stats = {
        "node_count": G.number_of_nodes(),
        "edge_count": G.number_of_edges(),
        "network_conn_count": sum(1 for n, d in G.nodes(data=True) if d.get("type") == "network"),
        "file_read_count": sum(1 for n, d in G.nodes(data=True) if d.get("type") == "file"),
    }
    
    return {
        "nodes": cyto_nodes,
        "edges": cyto_edges,
        "stats": graph_stats,
        "raw_graph": G
    }
