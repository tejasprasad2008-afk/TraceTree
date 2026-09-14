# TraceTree Technical Reference Guide

This document serves as a reference for the unique architectural choices, feature engineering, and data strategies implemented in the TraceTree project.

## 1. Hybrid Detection Engine
Unlike traditional scanners that look only at code (static analysis), TraceTree uses a **Hybrid Pipeline**:
*   **Signatures (Rule-Based):** 8 standard and 10+ MCP-specific signatures (e.g., `reverse_shell`, `ui_injection`). These are "hard rules" that flag immediate red flags.
*   **Temporal Analysis (Time-Based):** Detects *sequences* of events, like a file read followed by a network connection within 5 seconds.
*   **Machine Learning (Behavioral):** A RandomForest model that looks at the "big picture" of the execution graph.

## 2. Feature Engineering (The 10 "Sensors")
The ML model doesn't "read" code; it looks at these 10 specific numeric features extracted from a sandbox run:
1.  **Node Count:** Total entities (processes/files/IPs) involved.
2.  **Edge Count:** Total interactions between entities.
3.  **Network Count:** Distinct remote servers contacted.
4.  **File Read Count:** Distinct files accessed.
5.  **Execve Count:** Number of new programs launched.
6.  **Total Severity:** Sum of weights (0-10) assigned to every syscall.
7.  **Suspicious Network Count:** Connections to cloud metadata, private IPs, or known C2 ports.
8.  **Sensitive File Count:** Accesses to `.env`, `/etc/shadow`, `.ssh`, etc.
9.  **Max Severity:** The highest single risk score found in the run.
10. **Temporal Pattern Count:** Number of time-based suspicious chains detected.

## 3. Custom Training Methodology
*   **Model:** RandomForestClassifier (100 trees).
*   **Parallelism:** We use `ThreadPoolExecutor` to run 4 sandboxes at once during training, which speeds up feature extraction by ~350%.
*   **Direct Mode:** A custom "Docker-less" mode implemented specifically for cloud environments (Azure ML) where nested virtualization is restricted.
*   **Confidence Boosting:** The final score is not just the ML probability; it is manually boosted by the presence of hard signatures and temporal patterns.

## 4. Data Sources
The 841-package dataset was compiled from:
*   **Malicious:** MalwareBazaar (automated ingestion script), research on known PyPI typosquatting attacks, and the **OX Security April 2026 Disclosure** (specifically for MCP RCE patterns).
*   **Clean:** Top 500 downloaded packages from PyPI and npm, used to establish "benign baselines" (e.g., how `requests` or `lodash` normally behaves).

## 5. Model Portability
The model is serialized into `ml/model.pkl`. 
*   **Portability:** This file is all a user needs to run a scan. 
*   **Update Mechanism:** `cascade-update` pulls the latest `.pkl` from Google Cloud Storage, allowing users to stay protected against new threats without updating the entire software.
