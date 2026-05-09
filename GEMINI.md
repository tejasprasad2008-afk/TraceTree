# TraceTree (cascade-analyzer) - Project Context & Instructions

This project, **TraceTree** (internally `cascade-analyzer`), is a runtime behavioral analysis tool designed to detect supply chain attacks and Remote Code Execution (RCE) vulnerabilities. It specializes in analyzing Python packages, npm modules, DMG images, Windows EXE files, and Model Context Protocol (MCP) servers.

## Project Overview

TraceTree executes suspicious targets in isolated Docker sandboxes, monitors their system calls using `strace`, and classifies their behavior through a multi-layered analysis pipeline:

1.  **Sandbox Execution:** Targets are run in a Linux-based Docker container (`sandbox/Dockerfile`). Network access is dropped (`ip link set eth0 down`) before execution to block exfiltration while logging the attempts.
2.  **Syscall Tracing:** `strace -t -f` is used to capture timestamped system calls and child processes.
3.  **Parsing:** The `monitor/parser.py` module uses regex to reassemble multi-line strace logs into structured events, categorizing 24+ syscall types.
4.  **Signature Matching:** Events are matched against behavioral signatures defined in `data/signatures.json` and `monitor/mcp_signatures.py`.
5.  **Temporal Analysis:** `monitor/timeline.py` detects time-based patterns (e.g., sensitive read followed by network connect).
6.  **Graph Construction:** `graph/builder.py` creates a NetworkX directed graph of processes, files, and network nodes.
7.  **ML Detection:** `ml/detector.py` extracts a 10-feature vector from the graph and parsed data, using a `RandomForestClassifier` (if trained) or an `IsolationForest` (fallback) to provide a final security verdict.
8.  **MCP Security:** Specialized modules in `mcp/` and `monitor/` handle Model Context Protocol server analysis, including adversarial tool probing and RCE detection based on the OX Security April 2026 disclosure.

## Key Technologies

-   **Language:** Python 3.9+
-   **Sandboxing:** Docker
-   **Analysis:** NetworkX (Graphing), scikit-learn (ML), strace (Tracing), YARA (Static matching)
-   **CLI:** Typer (Commands), Rich (UI/Formatting)
-   **API:** FastAPI (currently a stub in `api/main.py`)

## Directory Structure

-   `cli.py`: Main CLI entry point.
-   `sandbox/`: Docker container lifecycle and target execution.
-   `monitor/`: Strace parsing, signatures, temporal analysis, YARA scanning, and reporting.
-   `graph/`: NetworkX graph builder.
-   `ml/`: Machine learning models and feature extraction.
-   `mcp/`: MCP-specific client simulation and security analysis.
-   `watcher/`: Background session guardian for repository monitoring.
-   `mascot/`: ASCII spider mascot for terminal feedback.
-   `hooks/`: Git hooks for automatic analysis after `git clone`.
-   `data/`: Configuration for signatures and YARA rules.
-   `tests/`: Test suite (Pytest).

## Development Commands

### Building and Running

```bash
# Install in development mode
pip install -e .

# Main analysis command
cascade-analyze <target>

# MCP server analysis
cascade-analyze mcp --path <path_to_server>

# Background repository watcher
cascade-watch <repo_path>

# Quick scan of a specific file
cascade-check <file_path>

# Update ML models from GCS
cascade-update

# Train the ML model locally
cascade-train
```

### Testing

```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/mcp/
pytest tests/monitor/
```

## Development Conventions

-   **Testing:** New features MUST include tests in the `tests/` directory. Use mocks for Docker calls to avoid requiring a running Docker daemon for unit tests.
-   **CLI Output:** Use the `rich` library for all terminal output to maintain the project's visual style. The `SpiderMascot` should be used for progress/status feedback.
-   **Imports:** Adhere to the order: standard library -> third-party packages -> local project modules.
-   **Architecture:** Keep analysis modules decoupled. Feature extraction for ML should be centralized in `ml/detector.py`.
-   **Legacy Code:** The `TraceTree/` directory at the root is a duplicate/legacy structure. **Always use the root-level modules** (`monitor/`, `sandbox/`, etc.).
-   **Configuration:** API keys (like `MALWAREBAZAAR_AUTH_KEY`) should be handled via environment variables.

## Important Notes

-   **Docker Dependency:** Most core functionality requires a running Docker daemon.
-   **Platform Limitations:** `strace` is Linux-specific. On macOS/Windows, it runs inside the Docker Linux VM. DMG and EXE analysis are "best-effort" translations in a Linux environment.
-   **Data Sensitivity:** The sandbox drops network access by default. Use `--allow-network` only if explicitly required for the target to function.
-   **API Status:** The FastAPI backend in `api/` is currently a stub and does not reflect real-time analysis results from the CLI pipeline.
