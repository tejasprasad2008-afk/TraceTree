# Graph-Based Analysis

<cite>
**Referenced Files in This Document**
- [builder.py](file://TraceTree/graph/builder.py)
- [parser.py](file://TraceTree/monitor/parser.py)
- [signatures.py](file://TraceTree/monitor/signatures.py)
- [timeline.py](file://TraceTree/monitor/timeline.py)
- [detector.py](file://TraceTree/ml/detector.py)
- [trainer.py](file://TraceTree/ml/trainer.py)
- [features.py](file://TraceTree/mcp/features.py)
- [client.py](file://TraceTree/mcp/client.py)
- [sandbox.py](file://TraceTree/sandbox/sandbox.py)
- [main.py](file://TraceTree/api/main.py)
- [cli.py](file://TraceTree/cli.py)
- [signatures.json](file://TraceTree/data/signatures.json)
</cite>

## Table of Contents
1. [Introduction](#introduction)
2. [Project Structure](#project-structure)
3. [Core Components](#core-components)
4. [Architecture Overview](#architecture-overview)
5. [Detailed Component Analysis](#detailed-component-analysis)
6. [Dependency Analysis](#dependency-analysis)
7. [Performance Considerations](#performance-considerations)
8. [Troubleshooting Guide](#troubleshooting-guide)
9. [Conclusion](#conclusion)
10. [Appendices](#appendices)

## Introduction
This document explains TraceTree’s graph-based analysis system that constructs NetworkX graphs from syscall traces and detects behavioral anomalies. It focuses on:
- How the graph builder creates nodes for processes, files, and network connections with temporal edge weighting and signature propagation
- How the graph captures process lineage, file access dependencies, and network communication patterns
- How traversal and aggregation algorithms support signature detection, anomaly scoring, and temporal pattern recognition
- How graph features integrate with machine learning models to improve detection performance and interpretability

## Project Structure
The graph analysis pipeline spans several modules:
- Sandbox execution and syscall capture
- Event parsing and classification
- Behavioral signature matching
- Temporal pattern detection
- Graph construction and statistics
- Machine learning anomaly detection and model orchestration
- MCP-specific feature extraction and classification
- API and CLI entrypoints

```mermaid
graph TB
subgraph "Execution"
SB["sandbox.py<br/>Docker sandbox + strace"]
end
subgraph "Parsing & Classification"
PR["parser.py<br/>parse_strace_log()"]
SG["signatures.py<br/>load_signatures(), match_signatures()"]
TL["timeline.py<br/>detect_temporal_patterns()"]
end
subgraph "Graph Construction"
GB["builder.py<br/>build_cascade_graph()"]
end
subgraph "ML & Features"
ML["detector.py<br/>detect_anomaly(), map_features()"]
TR["trainer.py<br/>train_model()"]
FE["features.py<br/>extract_mcp_features()"]
end
subgraph "Integration"
CL["cli.py<br/>perform_analysis()"]
AP["api/main.py<br/>FastAPI endpoints"]
MC["client.py<br/>MCP client"]
end
SB --> PR --> SG --> GB
PR --> TL --> GB
GB --> ML
TR --> ML
CL --> SB
CL --> PR
CL --> SG
CL --> TL
CL --> GB
CL --> ML
AP --> CL
MC --> PR
MC --> FE
```

**Diagram sources**
- [sandbox.py:175-335](file://TraceTree/sandbox/sandbox.py#L175-L335)
- [parser.py:340-679](file://TraceTree/monitor/parser.py#L340-L679)
- [signatures.py:57-115](file://TraceTree/monitor/signatures.py#L57-L115)
- [timeline.py:298-331](file://TraceTree/monitor/timeline.py#L298-L331)
- [builder.py:8-195](file://TraceTree/graph/builder.py#L8-L195)
- [detector.py:29-299](file://TraceTree/ml/detector.py#L29-L299)
- [trainer.py:15-99](file://TraceTree/ml/trainer.py#L15-L99)
- [features.py:32-206](file://TraceTree/mcp/features.py#L32-L206)
- [cli.py:181-259](file://TraceTree/cli.py#L181-L259)
- [api/main.py:78-128](file://TraceTree/api/main.py#L78-L128)
- [client.py:18-195](file://TraceTree/mcp/client.py#L18-L195)

**Section sources**
- [cli.py:181-259](file://TraceTree/cli.py#L181-L259)
- [sandbox.py:175-335](file://TraceTree/sandbox/sandbox.py#L175-L335)
- [parser.py:340-679](file://TraceTree/monitor/parser.py#L340-L679)
- [signatures.py:57-115](file://TraceTree/monitor/signatures.py#L57-L115)
- [timeline.py:298-331](file://TraceTree/monitor/timeline.py#L298-L331)
- [builder.py:8-195](file://TraceTree/graph/builder.py#L8-L195)
- [detector.py:29-299](file://TraceTree/ml/detector.py#L29-L299)
- [trainer.py:15-99](file://TraceTree/ml/trainer.py#L15-L99)
- [features.py:32-206](file://TraceTree/mcp/features.py#L32-L206)
- [api/main.py:78-128](file://TraceTree/api/main.py#L78-L128)
- [client.py:18-195](file://TraceTree/mcp/client.py#L18-L195)

## Core Components
- Sandbox execution: Runs the target in a controlled environment and captures syscalls with strace.
- Parser: Reassembles multi-line strace entries, classifies destinations, flags suspicious events, and computes severity scores.
- Signature matcher: Loads behavioral patterns and matches them against parsed events.
- Temporal analyzer: Detects time-based patterns such as credential theft, rapid enumeration, and reverse shells.
- Graph builder: Creates a NetworkX directed graph with process, file, and network nodes; attaches severity and signature tags; adds temporal edges.
- ML detector: Aggregates graph and parsed features into a numeric vector and applies a supervised or fallback model with severity boosting.
- Trainer: Trains a Random Forest model on sandboxed packages and syncs it to cloud storage.
- MCP features: Extracts tool-call-centric features from MCP server traces for rule-based classification.
- CLI/API: Orchestrates the pipeline and exposes endpoints for analysis and graph visualization.

**Section sources**
- [sandbox.py:175-335](file://TraceTree/sandbox/sandbox.py#L175-L335)
- [parser.py:340-679](file://TraceTree/monitor/parser.py#L340-L679)
- [signatures.py:57-115](file://TraceTree/monitor/signatures.py#L57-L115)
- [timeline.py:298-331](file://TraceTree/monitor/timeline.py#L298-L331)
- [builder.py:8-195](file://TraceTree/graph/builder.py#L8-L195)
- [detector.py:29-299](file://TraceTree/ml/detector.py#L29-L299)
- [trainer.py:15-99](file://TraceTree/ml/trainer.py#L15-L99)
- [features.py:32-206](file://TraceTree/mcp/features.py#L32-L206)
- [cli.py:181-259](file://TraceTree/cli.py#L181-L259)
- [api/main.py:78-128](file://TraceTree/api/main.py#L78-L128)

## Architecture Overview
The system follows a staged pipeline:
1. Sandbox execution produces a strace log.
2. Parser converts logs into structured events with severity and classification.
3. Signature matcher enriches events with behavioral tags.
4. Temporal analyzer detects time-based patterns.
5. Graph builder constructs a NetworkX graph with nodes and weighted edges.
6. ML detector consumes graph and parsed features to produce anomaly verdicts.
7. CLI and API expose results and graph visualizations.

```mermaid
sequenceDiagram
participant User as "User"
participant CLI as "cli.py"
participant SB as "sandbox.py"
participant PR as "parser.py"
participant SG as "signatures.py"
participant TL as "timeline.py"
participant GB as "builder.py"
participant ML as "detector.py"
User->>CLI : cascade-analyze <target>
CLI->>SB : run_sandbox(target)
SB-->>CLI : strace.log path
CLI->>PR : parse_strace_log(log_path)
PR-->>CLI : parsed_data
CLI->>SG : load_signatures() + match_signatures(parsed_data)
SG-->>CLI : signature_matches
CLI->>TL : detect_temporal_patterns(parsed_data)
TL-->>CLI : temporal_patterns
CLI->>GB : build_cascade_graph(parsed_data, signature_matches)
GB-->>CLI : graph_data
CLI->>ML : detect_anomaly(graph_data, parsed_data)
ML-->>CLI : is_malicious, confidence
CLI-->>User : verdict + graph + patterns
```

**Diagram sources**
- [cli.py:181-259](file://TraceTree/cli.py#L181-L259)
- [sandbox.py:175-335](file://TraceTree/sandbox/sandbox.py#L175-L335)
- [parser.py:340-679](file://TraceTree/monitor/parser.py#L340-L679)
- [signatures.py:86-115](file://TraceTree/monitor/signatures.py#L86-L115)
- [timeline.py:298-331](file://TraceTree/monitor/timeline.py#L298-L331)
- [builder.py:8-195](file://TraceTree/graph/builder.py#L8-L195)
- [detector.py:235-299](file://TraceTree/ml/detector.py#L235-L299)

## Detailed Component Analysis

### Graph Builder: Node Creation, Temporal Edges, and Signature Propagation
The graph builder constructs a NetworkX directed graph from parsed syscall events:
- Node types: process, network, file, and syscall-specific auxiliary nodes
- Severity weights propagate from events to nodes and edges
- Signature tags propagate from matched events to nodes and edges
- Temporal edges connect consecutive events from the same PID within a fixed time window

Key behaviors:
- Process nodes are created from parsed processes and linked via fork/clone lineage
- Network nodes are created for connect/sendto/socket events with destination categories and risk scores
- File nodes are created for openat/read/write/unlink with sensitivity flags
- Auxiliary nodes encode syscall semantics (e.g., execve, dup2, mmap)
- Temporal edges are added between events sorted by sequence_id within the time window

```mermaid
flowchart TD
Start(["build_cascade_graph(parsed_data, signature_matches)"]) --> Init["Initialize DiGraph G"]
Init --> Tags["Map signature_matches to event indices<br/>and collect signature tags"]
Tags --> Proc["Create process nodes from parsed_data.processes"]
Proc --> Lineage["Add clone edges from parent_map"]
Lineage --> Targets["Iterate events and create target nodes:<br/>connect→network, openat→file,<br/>sendto/socket→network,<br/>execve/dup2/mmap/etc→auxiliary"]
Targets --> Severity["Assign severity from event details"]
Severity --> TagsAttach["Attach signature_tags to nodes and edges"]
TagsAttach --> Sort["Group events by PID and sort by sequence_id"]
Sort --> Temporal["Add temporal edges for adjacent events<br/>within time window"]
Temporal --> Stats["Compute graph stats and convert to Cytoscape format"]
Stats --> End(["Return nodes, edges, stats, raw_graph"])
```

**Diagram sources**
- [builder.py:8-195](file://TraceTree/graph/builder.py#L8-L195)

**Section sources**
- [builder.py:8-195](file://TraceTree/graph/builder.py#L8-L195)

### Parser: Severity Classification and Destination Intelligence
The parser reassembles multi-line strace entries and classifies destinations and file paths:
- Severity weights are assigned per syscall type
- Destinations are categorized as safe registry, known benign, suspicious, or unknown with risk scores
- Sensitive file patterns trigger elevated severity
- Chains like clone→execve→openat sensitive file are flagged as credential theft

```mermaid
flowchart TD
PStart(["parse_strace_log(log_path)"]) --> Reassemble["Reassemble multi-line entries"]
Reassemble --> Iterate["Iterate lines and parse syscall"]
Iterate --> Timestamps["Parse timestamps and compute relative_ms"]
Timestamps --> History["Track per-PID history for chaining"]
Iterate --> Syscall{"Syscall type?"}
Syscall --> |clone/fork/vfork| Parent["Record parent-child and add to events"]
Syscall --> |execve| Exec["Classify binary as benign/non-benign<br/>adjust severity"]
Syscall --> |connect| Conn["Extract IP/port, classify destination<br/>compute risk score"]
Syscall --> |openat/read/write/unlink/chmod| File["Check sensitive/benign paths<br/>adjust severity"]
Syscall --> |mmap/mprotect| Mem["Check PROT_EXEC flags<br/>flag suspicious mappings"]
Syscall --> |sendto/socket| Net["Flag AF_INET sockets"]
Syscall --> |dup2| Dup["Check recent connect → flag reverse shell"]
Syscall --> |getaddrinfo/getuid/geteuid/getcwd| Recon["Flag reconnaissance patterns"]
Syscall --> |pipe/pipe2| IPC["Flag IPC channels"]
Parent --> Update["Update total severity and history"]
Exec --> Update
Conn --> Update
File --> Update
Mem --> Update
Net --> Update
Dup --> Update
Recon --> Update
IPC --> Update
Update --> PEnd(["Return processes, parent_map, events, flags, destinations, totals"])
```

**Diagram sources**
- [parser.py:340-679](file://TraceTree/monitor/parser.py#L340-L679)

**Section sources**
- [parser.py:340-679](file://TraceTree/monitor/parser.py#L340-L679)

### Signature Matching Engine
The signature engine loads behavioral patterns and matches them against parsed events:
- Supports unordered and ordered (sequence) matching
- Conditions include external connections, shell binaries, sensitive files, protocol ports, and memory protections
- Evidence and matched events are collected for each signature

```mermaid
flowchart TD
SStart(["match_signatures(parsed_data, signatures)"]) --> Load["Load signatures from JSON"]
Load --> Iterate["For each signature: _match_single_signature()"]
Iterate --> Unordered{"Has sequence?"}
Unordered --> |No| UnorderedMatch["_match_unordered()<br/>Check syscalls present<br/>Check file/network patterns"]
Unordered --> |Yes| SeqMatch["_match_sequence()<br/>Ordered steps with conditions"]
UnorderedMatch --> Result["Build result with evidence and matched_events"]
SeqMatch --> Result
Result --> SEnd(["Sorted matches by severity"])
```

**Diagram sources**
- [signatures.py:86-115](file://TraceTree/monitor/signatures.py#L86-L115)
- [signatures.py:123-236](file://TraceTree/monitor/signatures.py#L123-L236)
- [signatures.py:244-343](file://TraceTree/monitor/signatures.py#L244-L343)
- [signatures.json:1-246](file://TraceTree/data/signatures.json#L1-L246)

**Section sources**
- [signatures.py:86-115](file://TraceTree/monitor/signatures.py#L86-L115)
- [signatures.py:123-236](file://TraceTree/monitor/signatures.py#L123-L236)
- [signatures.py:244-343](file://TraceTree/monitor/signatures.py#L244-L343)
- [signatures.json:1-246](file://TraceTree/data/signatures.json#L1-L246)

### Temporal Pattern Detection
The temporal analyzer detects time-based behavioral patterns:
- Credential theft: sensitive file read followed by external connection within a window
- Rapid file enumeration: many openat/read within a short time
- Burst process spawn: multiple forks/clones/execve within a short time
- Delayed payload: long gap then suspicious burst
- Connect-then-shell: external connect followed by shell exec within a window

```mermaid
flowchart TD
TStart(["detect_temporal_patterns(parsed_data)"]) --> Sort["Sort events by sequence_id"]
Sort --> Check1["Check credential_scan_then_exfil()"]
Sort --> Check2["Check rapid_file_enumeration()"]
Sort --> Check3["Check burst_process_spawn()"]
Sort --> Check4["Check delayed_payload()"]
Sort --> Check5["Check connect_then_shell()"]
Check1 --> Merge["Collect all matches"]
Check2 --> Merge
Check3 --> Merge
Check4 --> Merge
Check5 --> Merge
Merge --> TEnd(["Sorted by severity, then start time"])
```

**Diagram sources**
- [timeline.py:298-331](file://TraceTree/monitor/timeline.py#L298-L331)
- [timeline.py:100-131](file://TraceTree/monitor/timeline.py#L100-L131)
- [timeline.py:134-169](file://TraceTree/monitor/timeline.py#L134-L169)
- [timeline.py:172-206](file://TraceTree/monitor/timeline.py#L172-L206)
- [timeline.py:209-250](file://TraceTree/monitor/timeline.py#L209-L250)
- [timeline.py:253-281](file://TraceTree/monitor/timeline.py#L253-L281)

**Section sources**
- [timeline.py:298-331](file://TraceTree/monitor/timeline.py#L298-L331)
- [timeline.py:100-131](file://TraceTree/monitor/timeline.py#L100-L131)
- [timeline.py:134-169](file://TraceTree/monitor/timeline.py#L134-L169)
- [timeline.py:172-206](file://TraceTree/monitor/timeline.py#L172-L206)
- [timeline.py:209-250](file://TraceTree/monitor/timeline.py#L209-L250)
- [timeline.py:253-281](file://TraceTree/monitor/timeline.py#L253-L281)

### Machine Learning Detector and Feature Extraction
The ML detector:
- Converts graph and parsed data into a numeric feature vector
- Applies a supervised Random Forest or fallback Isolation Forest
- Boosts confidence using severity thresholds and temporal pattern counts

```mermaid
flowchart TD
FStart(["map_features(graph_data, parsed_data)"]) --> Extract["Extract node_count, edge_count,<br/>network_conn_count, file_read_count,<br/>execve_count, total_severity,<br/>suspicious_network_count,<br/>sensitive_file_count, max_severity,<br/>temporal_pattern_count"]
Extract --> FEnd(["Feature vector"])
DStart(["detect_anomaly(graph_data, parsed_data)"]) --> LoadModel["get_ml_model()"]
LoadModel --> Vector["map_features()"]
Vector --> Predict{"Model type?"}
Predict --> |RandomForest| RF["predict + predict_proba"]
Predict --> |IsolationForest| IF["predict + decision_function"]
RF --> Boost["_severity_adjusted_confidence()"]
IF --> Boost
Boost --> DEnd(["Return is_malicious, confidence"])
```

**Diagram sources**
- [detector.py:29-68](file://TraceTree/ml/detector.py#L29-L68)
- [detector.py:108-146](file://TraceTree/ml/detector.py#L108-L146)
- [detector.py:180-232](file://TraceTree/ml/detector.py#L180-L232)
- [detector.py:235-299](file://TraceTree/ml/detector.py#L235-L299)

**Section sources**
- [detector.py:29-68](file://TraceTree/ml/detector.py#L29-L68)
- [detector.py:108-146](file://TraceTree/ml/detector.py#L108-L146)
- [detector.py:180-232](file://TraceTree/ml/detector.py#L180-L232)
- [detector.py:235-299](file://TraceTree/ml/detector.py#L235-L299)

### MCP-Specific Features and Classification
The MCP analyzer:
- Parses strace logs with MCP-specific parsing
- Extracts features grouped by tool-call activity
- Compares observed behavior to known server baselines
- Classifies threats and computes risk scores

```mermaid
flowchart TD
MCPStart(["extract_mcp_features(log_path, call_log, adversarial_log, server_type)"]) --> Parse["Parse strace log"]
Parse --> Timeline["Attribute events to tool calls"]
Timeline --> Classify["Classify network destinations and file accesses"]
Classify --> Aggregate["Aggregate counts and flags"]
Aggregate --> Baseline["Compare to known baseline"]
Baseline --> MCPEnd(["Return MCP features"])
```

**Diagram sources**
- [features.py:32-206](file://TraceTree/mcp/features.py#L32-L206)
- [features.py:209-238](file://TraceTree/mcp/features.py#L209-L238)
- [features.py:429-472](file://TraceTree/mcp/features.py#L429-L472)

**Section sources**
- [features.py:32-206](file://TraceTree/mcp/features.py#L32-L206)
- [features.py:209-238](file://TraceTree/mcp/features.py#L209-L238)
- [features.py:429-472](file://TraceTree/mcp/features.py#L429-L472)

### Sandbox Execution and Pipeline Orchestration
The sandbox executes the target in a controlled environment and captures syscalls:
- Pipelines support pip, npm, DMG, and EXE targets
- strace is configured to capture full process trees with timestamps
- Wine noise filtering is applied for EXE analysis

```mermaid
flowchart TD
SStart(["run_sandbox(target, target_type)"]) --> Image["Ensure sandbox image exists"]
Image --> Prepare["Prepare volumes and command"]
Prepare --> Run["Run container with strace -t -f -e trace=all"]
Run --> Wait["Wait for completion or timeout"]
Wait --> Fetch["Fetch strace.log from container"]
Fetch --> Post["Filter wine noise (EXE)"]
Post --> SEnd(["Return log path"])
```

**Diagram sources**
- [sandbox.py:175-335](file://TraceTree/sandbox/sandbox.py#L175-L335)
- [sandbox.py:338-375](file://TraceTree/sandbox/sandbox.py#L338-L375)

**Section sources**
- [sandbox.py:175-335](file://TraceTree/sandbox/sandbox.py#L175-L335)
- [sandbox.py:338-375](file://TraceTree/sandbox/sandbox.py#L338-L375)

### API and CLI Integration
The CLI orchestrates the full pipeline and renders results, including:
- Cascade graph visualization
- Flagged behaviors and matched signatures
- Temporal patterns
- Final verdict and confidence

The API provides endpoints for asynchronous analysis and graph visualization.

```mermaid
sequenceDiagram
participant CLI as "cli.py"
participant SB as "sandbox.py"
participant PR as "parser.py"
participant SG as "signatures.py"
participant TL as "timeline.py"
participant GB as "builder.py"
participant ML as "detector.py"
participant API as "api/main.py"
CLI->>SB : run_sandbox()
SB-->>CLI : log_path
CLI->>PR : parse_strace_log()
PR-->>CLI : parsed_data
CLI->>SG : match_signatures()
SG-->>CLI : signature_matches
CLI->>TL : detect_temporal_patterns()
TL-->>CLI : temporal_patterns
CLI->>GB : build_cascade_graph()
GB-->>CLI : graph_data
CLI->>ML : detect_anomaly()
ML-->>CLI : verdict + confidence
CLI-->>CLI : render UI and tree
API-->>CLI : graph endpoint returns nodes/edges
```

**Diagram sources**
- [cli.py:181-259](file://TraceTree/cli.py#L181-L259)
- [api/main.py:78-128](file://TraceTree/api/main.py#L78-L128)

**Section sources**
- [cli.py:181-259](file://TraceTree/cli.py#L181-L259)
- [api/main.py:78-128](file://TraceTree/api/main.py#L78-L128)

## Dependency Analysis
The graph builder depends on:
- Parsed events and parent_map from the parser
- Signature matches to propagate tags
- Timestamps to create temporal edges

The ML detector depends on:
- Graph stats and parsed stats (including temporal pattern counts)
- A trained model (Random Forest or Isolation Forest)

```mermaid
graph LR
PR["parser.py"] --> GB["builder.py"]
SG["signatures.py"] --> GB
TL["timeline.py"] --> ML["detector.py"]
GB --> ML
TR["trainer.py"] --> ML
FE["features.py"] --> ML
```

**Diagram sources**
- [builder.py:8-195](file://TraceTree/graph/builder.py#L8-L195)
- [parser.py:340-679](file://TraceTree/monitor/parser.py#L340-L679)
- [signatures.py:86-115](file://TraceTree/monitor/signatures.py#L86-L115)
- [timeline.py:298-331](file://TraceTree/monitor/timeline.py#L298-L331)
- [detector.py:235-299](file://TraceTree/ml/detector.py#L235-L299)
- [trainer.py:15-99](file://TraceTree/ml/trainer.py#L15-L99)
- [features.py:32-206](file://TraceTree/mcp/features.py#L32-L206)

**Section sources**
- [builder.py:8-195](file://TraceTree/graph/builder.py#L8-L195)
- [parser.py:340-679](file://TraceTree/monitor/parser.py#L340-L679)
- [signatures.py:86-115](file://TraceTree/monitor/signatures.py#L86-L115)
- [timeline.py:298-331](file://TraceTree/monitor/timeline.py#L298-L331)
- [detector.py:235-299](file://TraceTree/ml/detector.py#L235-L299)
- [trainer.py:15-99](file://TraceTree/ml/trainer.py#L15-L99)
- [features.py:32-206](file://TraceTree/mcp/features.py#L32-L206)

## Performance Considerations
- Graph construction scales with the number of events and nodes; grouping by PID and sorting by sequence_id ensures efficient temporal edge creation.
- Signature matching and temporal pattern detection iterate over events; keeping event lists sorted reduces redundant checks.
- ML inference uses a compact feature vector; caching models avoids repeated I/O.
- Docker sandbox timeouts prevent hangs; wine noise filtering reduces irrelevant syscall volume for EXE targets.

[No sources needed since this section provides general guidance]

## Troubleshooting Guide
Common issues and resolutions:
- Docker not installed or not running: The CLI checks Docker and exits with guidance.
- Sandbox fails to produce a log: The pipeline validates log size and content; empty or error messages indicate issues with the target or environment.
- Model loading failures: The detector falls back to an Isolation Forest baseline and attempts to download a model from cloud storage.
- Signature matching or temporal analysis exceptions: The CLI continues with partial results and logs warnings.

**Section sources**
- [cli.py:73-109](file://TraceTree/cli.py#L73-L109)
- [sandbox.py:310-335](file://TraceTree/sandbox/sandbox.py#L310-L335)
- [detector.py:108-146](file://TraceTree/ml/detector.py#L108-L146)
- [cli.py:218-235](file://TraceTree/cli.py#L218-L235)

## Conclusion
TraceTree’s graph-based analysis system transforms syscall traces into actionable insights by constructing NetworkX graphs enriched with severity, signature tags, and temporal edges. The combination of behavioral signatures, temporal pattern detection, and ML anomaly scoring yields robust detection capabilities with interpretable security insights. Integration with MCP-specific features and rule-based classification further strengthens the system’s ability to assess diverse threat surfaces.

[No sources needed since this section summarizes without analyzing specific files]

## Appendices

### Example Graph Structures for Attack Scenarios
Below are conceptual graph structures representing attack patterns. These illustrate how the graph builder encodes process lineage, file access dependencies, and network communication.

- Privilege escalation chain (conceptual)
  - Nodes: process nodes for the initial process and child processes
  - Edges: clone/clone-like edges forming a lineage; execve edges to escalate privileges
  - Temporal edges: connect successive events within the time window
  - Signature tags: propagated from matched escalation patterns

- Data exfiltration pipeline (conceptual)
  - Nodes: sensitive file nodes and external network nodes
  - Edges: openat/read to sensitive files; connect to external hosts
  - Temporal edges: rapid file enumeration followed by external connection
  - Signature tags: propagated from credential theft or typosquat exfil patterns

[No sources needed since this section provides conceptual diagrams]