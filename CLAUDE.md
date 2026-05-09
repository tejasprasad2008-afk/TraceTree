# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TraceTree (cascade-analyzer) is a runtime behavioral analysis tool that detects supply chain attacks in Python packages, npm modules, DMG images, and Windows EXE files. It executes targets in isolated Docker sandboxes, monitors syscalls via strace, and classifies behavior using ML anomaly detection, rule-based signatures, and temporal pattern analysis.

## Build and Install

```bash
# Install in development mode
pip install -e .

# The following CLI commands become available:
# cascade-analyze, cascade-train, cascade-update, cascade-watch, cascade-check, cascade-install-hook
```

Requires Python 3.9+ and Docker (must be running).

## Running Tests

Tests are in `tests/` directory with minimal coverage currently. Use pytest:

```bash
pytest tests/
# Run a single test file
pytest tests/mcp/test_payload_generator.py
pytest tests/monitor/test_mcp_rce_detection.py
```

When adding tests, mirror the package structure in `tests/` and mock Docker calls for unit testing.

## Architecture

### Analysis Pipeline

```
target → Docker sandbox (network dropped) → strace -t -f → parser → signatures + timeline → graph → ML → verdict
```

### Core Modules

- **`cli.py`** — Typer CLI entry point. Orchestrates analysis pipeline with Rich progress bars and formatted output. All subcommands registered here.

- **`sandbox/`** — Docker container lifecycle. Builds `cascade-sandbox:latest` from `sandbox/Dockerfile` (python:3.11-slim + strace, wine64, p7zip-full, Node.js). Drops network (`ip link set eth0 down`) before execution. Supports pip, npm, DMG, and EXE targets.

- **`monitor/`** — Core analysis modules:
  - `parser.py` — Regex-based strace log parser. Handles multi-line output, `[pid]` and bare-pid formats. Extracts 24 syscall types across 5 categories. Assigns severity weights (0–9) per event.
  - `signatures.py` — Behavioral signature matcher. Loads 8 patterns from `data/signatures.json`. Supports ordered and unordered matching.
  - `timeline.py` — Temporal pattern analyzer. Detects 5 time-based patterns from timestamped events.
  - `yara.py` — YARA rule scanning for MCP RCE detection.
  - `mcp_signatures.py` / `mcp_report.py` — MCP-specific signature matching and reporting.
  - `sarif.py` — SARIF format output generation.
  - `diff.py` — Execution diff analysis.
  - `ngrams.py` — N-gram analysis for behavioral patterns.

- **`graph/`** — NetworkX directed graph construction (`builder.py`). Creates process/file/network nodes with temporal edges.

- **`ml/`** — Anomaly detection (`detector.py`). Extracts 10-feature vectors. Uses RandomForestClassifier if trained model exists (`ml/model.pkl`), falls back to IsolationForest with hardcoded baselines. Training pipeline in `trainer.py`.

- **`mcp/`** — MCP server security analysis:
  - `sandbox.py` — Docker sandbox for MCP servers
  - `client.py` — JSON-RPC 2.0 client with tool discovery and adversarial payload probes
  - `features.py` — MCP-specific feature extraction
  - `classifier.py` — Rule-based threat classification (6 threat types)
  - `report.py` — Report generation (Rich console + JSON)
  - `payload_generator.py` — Generates adversarial test payloads

- **`watcher/`** — Session guardian (`session.py`). Background daemon that scans for package manifests and runs sandbox analysis.

- **`hooks/`** — Shell hook system. Wraps `git` command to auto-launch `cascade-watch` after `git clone`.

- **`api/`** — FastAPI backend (`main.py`). Currently a stub returning hardcoded data.

- **`mascot/`** — ASCII spider mascot for terminal UI feedback.

- **`traceenv/`** — Virtual environment management for sandboxed execution.

### Data Files

- `data/signatures.json` — 8 behavioral signatures (reverse_shell, container_escape, credential_theft, etc.)
- `data/mcp_rce_signatures.yara` — YARA rules for MCP RCE detection
- `data/clean_packages.txt` / `data/malicious_packages.txt` — Training data lists
- `ml/model.pkl` — Trained RandomForest model (~54MB, gitignored in practice)

## Key Patterns

- **CLI**: Typer for commands, Rich for terminal formatting, progress indicators for long operations
- **API**: FastAPI with Pydantic models, background tasks for long operations
- **Sandbox**: Docker container lifecycle management with network restriction and resource cleanup
- **Imports order**: stdlib → third-party → local (see AGENTS.md for full style guide)

## Important Notes

- Docker must be running for any sandbox functionality
- The `TraceTree/` directory at root is a duplicate/legacy structure — work with root-level modules
- `config.json` contains API keys (NVIDIA_API_KEY) — do not commit actual secrets
- First `cascade-update` downloads ML model from GCS (~100MB)
- DMG analysis runs Linux containers, so macOS-specific behavior won't execute
- EXE analysis uses wine64 — Windows syscalls translate to Linux syscalls via Wine
- No train/test split in current training pipeline — accuracy metrics not reported
