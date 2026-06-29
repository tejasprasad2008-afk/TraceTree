# AI Mesh Initialization & Robustness Verification Architecture

This document describes the architectural enhancements introduced to resolve the silent "Default-to-Malicious" failure state when TraceTree defaults to a hardcoded "MALICIOUS" verdict.

---

## 1. Architectural Changes

We have modified the interaction pipeline between the Python orchestration layer and the local Ollama API to guarantee high visibility, connection health tracking, and robust error management.

### 1.1 Connection Health Checks & Exception Management
* **Location:** `orchestrator/ai_mesh.py` (`AIMeshOrchestrator` class)
* **Connectivity Verification (`check_connection_health`):** Designed a routine that performs a HEAD or GET ping request directly to `http://localhost:11434/api/tags`.
* **Explicit Exceptions:** Defined two new exceptions to distinguish connection failures from model parsing/hallucination failures:
  - `AIConnectionRefusedError`: Raised when the Ollama port/server is offline.
  - `AIBadResponseError`: Raised when the local LLM returns invalid JSON or non-200 HTTP status.
* **Triage Pipeline Integration:** Integrated this check inside the main `cascade-analyze` command lifecycle (`cli.py`). Before executing sandboxed analysis with AI, the CLI runs this pre-flight test. If the check fails, the CLI outputs a beautiful `CONNECTION_ERROR` block and exits cleanly with status code `1` instead of defaulting to a hardcoded `MALICIOUS` verdict.

### 1.2 JSON Schema Enforcement
* **Location:** `orchestrator/ai_mesh.py`
* **Mechanism:** Ensured that request headers strictly declare `"format": "json"`. This is combined with the JSON body payload format option to instruct the Qwen 2.5 Coder 7B model to output pure, parseable JSON payloads, bypassing conversational preamble.

### 1.3 Debug Trace & Verbose Logging
* **Location:** `cli.py` & `orchestrator/ai_mesh.py`
* **Options Added:** Added `--ai` (triage mode) and `--dry-run` (verbose logging mode) to the `cascade-analyze analyze` CLI subcommand.
* **Traces:** In dry-run mode, the AI Mesh Orchestrator prints:
  - The raw JSON payload/prompt sent to Ollama.
  - The HTTP status code returned.
  - The raw HTTP response body text before parsing attempts.

### 1.4 ML Graceful Fallback
* **Location:** `ml/detector.py`
* **Mechanism:** Updated the pickle unpickling try-except block to check if `model.pkl` is empty (0 bytes) or if it throws an `EOFError` upon reading. Rather than printing an alarming stack trace to stdout, it silently and gracefully falls back to training the zero-shot baseline `IsolationForest` model.

---

## 2. Diagnostic Tools

We have delivered three standalone, executable diagnostic scripts to help inspect and debug the connection pipeline in terminal environments:

### 2.1 Direct Port Visibility Check
* **Script:** `verify_ollama_connectivity.py`
* **Command:** `./verify_ollama_connectivity.py`
* **Description:** Tests the raw TCP socket visibility to port 11434 and requests `/api/tags` to list all loaded/pulled local model tags.

### 2.2 Latency and CPU/GPU Responsiveness Test
* **Script:** `test_ollama_roundtrip.py`
* **Command:** `./test_ollama_roundtrip.py`
* **Description:** Sends a short prompt to `qwen2.5-coder:7b` to calculate prompt execution and latency round-trip time. It checks if the performance resides within the safe 15-second MCP or 60-second analysis timeout thresholds.

### 2.3 End-to-End Triage Simulation
* **Script:** `simulate_benign_triage.py`
* **Command:** `./simulate_benign_triage.py`
* **Description:** Feeds a simulated benign package telemetry vector directly into the `AIMeshOrchestrator` false-positive jury leg and checks if the system reaches a `"FALSE_POSITIVE"` (benign) verdict.
