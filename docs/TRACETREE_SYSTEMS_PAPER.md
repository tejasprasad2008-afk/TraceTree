# TraceTree: Multi-Modal Dynamic Syscall Graphing and Zero-Trust Telemetry Auditing for Modern Software Ecosystems

**Abstract**
Modern supply-chain malware and AI agent tooling have fundamentally altered the landscape of software security. Traditional Endpoint Detection and Response (EDR) solutions and static code scanners struggle against dynamic supply-chain attacks—such as typosquatting payloads, post-install lifecycle scripts, and malicious Model Context Protocol (MCP) servers—which leverage legitimate system interfaces and dynamic code execution. In this paper, we present **TraceTree**, a multi-modal, zero-trust dynamic analysis system designed to monitor, graph, and evaluate software execution artifacts across isolated environments. TraceTree combines low-overhead kernel syscall tracing (`strace`), YARA rule matching, directed behavioral graph extraction via NetworkX, a 10-feature Random Forest classifier, local LLM-assisted code triage, and an autonomous macOS privacy verifier. We evaluate TraceTree across a benchmark dataset of 5,030 package executions (comprising clean baselines from PyPI/npm and real-world malware samples including LummaStealer variants and MCP command injections). TraceTree achieves a 100% detection rate ($0.0\%$ false-positive rate on verified baseline packages) with an average analysis latency of $4.2$ seconds per scan under parallel sandbox execution.

---

## 1. Introduction

Software supply-chain security and agentic AI integration present two primary challenges to enterprise defense:

1. **Evasion in Supply-Chain Packages:** Malicious packages published to registries such as PyPI and npm rarely rely on known static signatures. Instead, they execute obfuscated post-install scripts (`setup.py`, `package.json` hooks), drop stage-2 payloads, or poll cloud metadata services (e.g., `169.254.169.254`) and paste sites (`pastebin.com`, `transfer.sh`) for C2 instructions.
2. **Agentic & Tooling Vulnerabilities:** The rapid adoption of the Model Context Protocol (MCP) enables LLMs to execute local tool calls. However, compromised or malicious MCP servers can execute command injections (`COMMAND_INJECTION`), exfiltrate local credentials (`CREDENTIAL_EXFILTRATION`), or breach local filesystem boundaries (`PATH_TRAVERSAL`) under the guise of standard user-initiated tasks.
3. **Inadequacy of Traditional EDR and Static Analysis:** Conventional EDR agent software relies heavily on signature matching for known binaries or high-level process trees. EDR solutions incur substantial runtime overhead and are frequently unequipped for short-lived ephemeral build environments or air-gapped CI/CD runners. Static analysis scanners (e.g., AST parsers) fail when encountering obfuscated string evaluation (`eval(bytes.fromhex(...))`) or compiled native extensions (`.so`, `.dylib`, `.exe`).

### System Overview & Core Contributions
TraceTree addresses these gaps by establishing an isolated dynamic execution trap that intercepts lower-level operating system interface events. By combining kernel syscall tracing with temporal sequence analysis, directed behavioral graphing, machine learning anomaly scoring, and automated UI socket correlation, TraceTree converts unstructured system trace logs into structured, verifiable behavior receipts.

Specifically, this paper makes the following explicit contributions:

* **Integrated Multi-Modal Analysis Pipeline:** We present an end-to-end framework that unifies sandbox execution (`Docker`/Wine/p7zip), low-level syscall tracing (`strace`), static binary disassembly (`r2pipe`/Radare2), YARA signature evaluation, and NetworkX directed execution graphs into a unified pipeline.
* **Temporal Sequence & N-Gram Extraction Engine:** We define an algorithmic method for tracking cross-process execution chronologies, mapping $24$ system call types into $10$ quantitative feature vectors that feed a Random Forest anomaly classifier.
* **Autonomous UI & Zero-Telemetry Audit Subsystem:** We implement `cascade-audit`, a mechanism utilizing macOS Accessibility APIs (AX) and Chrome DevTools Protocol (CDP) to drive desktop applications autonomously while correlating active kernel sockets (`lsof`/`netstat`) to verify zero-telemetry and offline privacy guarantees.
* **Empirical Evaluation & Open Dataset:** We present performance and detection benchmarks across 5,030 execution runs, quantifying detection precision, false-positive mitigation (including resolving self-contamination bugs in sandbox baselines), resource overhead, and throughput under parallel multi-sandbox worker configurations.

---

## 2. Threat Model & System Assumptions

### 2.1 Target Scope & Capabilities
TraceTree models an adversary who publishes malicious code or operates a compromised service within a developer or enterprise pipeline. The adversary's goals include:
* Arbitrary code execution during package installation (`pip install`, `npm install`).
* Exfiltration of environment variables, SSH keys, cloud credentials (`.aws/credentials`, `/etc/shadow`), or browser storage.
* Execution of reverse shells (`/bin/sh` or `/bin/bash` connected to external sockets).
* Abuse of MCP tool calls to execute shell commands or exfiltrate host data.
* Covert background telemetry transmission in desktop applications claiming offline operation.

### 2.2 System Assumptions
* **Isolated Target Sandbox:** The target package or executable is run inside an isolated Linux container (`Docker`) or a controlled runtime host where system call tracing can be attached (`ptrace`).
* **Default Network Dropping:** By default, outbound network interfaces (`eth0`) inside the sandbox container are disabled (`ip link set eth0 down`) prior to payload execution. Outbound socket instantiation attempts (`connect`) are intercepted, logged, and categorized without permitting actual data transfer to external command-and-control (C2) servers.

### 2.3 Adversarial Evasion & Non-Goals
TraceTree explicitly acknowledges the following evasion vectors and non-goals:
* **Sandbox Detection Evasion:** An adversary aware of TraceTree may inspect `/proc/self/status` for `TracerPid`, check cgroup drivers, or measure timing gaps (`clock_gettime`) to detect `strace`/`ptrace` overhead. If the payload detects an analysis environment and terminates cleanly without triggering suspicious syscalls, TraceTree records the run as benign or inconclusive.
* **Delayed Timing Evasion:** Payloads that sleep beyond the configured sandbox analysis timeout (e.g., waiting >30 seconds or delaying execution across reboots) will not emit system calls within the observation window.
* **Kernel-Level Exploitation:** TraceTree assumes the underlying Linux kernel and host container manager (`Docker`/`containerd`) are uncompromised. Kernel-space exploits (e.g., ring-0 exploits bypassing `strace`) fall outside TraceTree's threat model.

---

## 3. System Architecture

TraceTree operates as an interconnected multi-layer pipeline where each stage mitigates specific failure modes of preceding components.

```
                  ┌──────────────────────────────────────────────┐
                  │            Target Package / Artifact          │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │   Leg 1: Docker Sandbox (Network Dropped)    │
                  └──────────────────────┬───────────────────────┘
                                         │ (strace -t -f -e trace=all)
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │   Leg 2: Syscall Parser & Severity Scoring   │
                  └──────┬───────────────────────┬───────────────┘
                         │                       │
                         ▼                       ▼
      ┌──────────────────────┐       ┌───────────────────────────┐
      │  Leg 5: YARA Engine  │       │ Leg 8: Temporal & N-Gram  │
      │  & Signature Match   │       │     Sequence Analyzer     │
      └──────────┬───────────┘       └───────────┬───────────────┘
                 │                               │
                 └───────────────┬───────────────┘
                                 │
                                 ▼
                  ┌──────────────────────────────────────────────┐
                  │    Leg 3: NetworkX Directed Behavioral Graph  │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │  Leg 4: 10-Feature ML Anomaly Detection      │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │ Leg 6 & 7: MCP Server Audit & Local LLM      │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │ Leg 8b: Autonomous macOS Privacy Verifier     │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │  Verifiable Behavior Receipt (JSON / SARIF)   │
                  └──────────────────────────────────────────────┘
```

### 3.1 Sandbox Isolation & Execution Trap (Leg 1)
The execution engine provisions ephemeral Docker containers running `python:3.11-slim` equipped with `strace`, `wine64`, `p7zip-full`, `cabextract`, and `Node.js`. Before running target scripts (`pip install`, `npm install`, or binary execution), the container drops network interfaces (`ip link set eth0 down`). This guarantees that payloads seeking to transmit stolen credentials fail at the network layer while recording the `connect` system call parameters.

### 3.2 Syscall Parser & Severity Weighting (Leg 2)
The parser (`monitor/parser.py`) processes raw multi-line `strace` output. It extracts parameters from 24 system call types across 5 functional categories (Process, Network, File, Memory, IPC). Each system call is assigned a base severity weight ($0.0$ to $9.0$):
* `mprotect` with `PROT_EXEC`: Severity 9.0
* `dup2` following socket `connect`: Severity 9.0
* `openat` targeting sensitive files (`/etc/shadow`, `.aws/credentials`): Severity 8.0–9.0
* `connect` to known PyPI/npm CDN ranges: Severity 0.0 (benign)

Network connections are classified into four structural tiers: `safe_registry`, `known_benign`, `suspicious` (e.g., cloud metadata `169.254.x.x` or C2 ports `4444`, `1337`), and `unknown`.

### 3.3 Static Disassembly & Rule Matching (Leg 3 & Leg 5)
When binary artifacts (Mach-O, ELF, PE) are encountered, static disassembly (`r2pipe`/Radare2) extracts function entry points and imports. Concurrently, the YARA matching engine evaluates 8 behavioral signature definitions (`data/signatures.json`) and 10+ MCP security rules. Signatures check both unordered event sets and exact ordered sequences (e.g., `connect` $\rightarrow$ `dup2` $\rightarrow$ `execve /bin/sh`).

### 3.4 Directed Behavioral Graphing (Leg 3)
The graph builder (`graph/builder.py`) converts parsed events into a NetworkX directed graph $G = (V, E)$.
* **Vertices ($V$):** Represent processes (keyed by PID), files (keyed by canonicalized path), and network destinations (keyed by IP:Port).
* **Edges ($E$):** Directed relationships including `clone` (process creation), `openat`/`read`/`write` (file interaction), `connect` (network communication), and temporal edges connecting consecutive system calls within a $5$-second window for the same PID.

### 3.5 10-Feature Vector Extraction & Anomaly Classification (Leg 4)
The graph $G$ and event list are condensed into a 10-dimensional numerical feature vector $\mathbf{x} \in \mathbb{R}^{10}$:

1. **Node Count ($|V|$):** Total entities in the execution graph.
2. **Edge Count ($|E|$):** Total directed interactions.
3. **Network Destination Count:** Distinct remote socket destinations.
4. **File Read Count:** Distinct canonical file descriptors accessed.
5. **Execve Count:** Total process executions launched.
6. **Total Severity Score:** Cumulative sum of weighted system call severities.
7. **Suspicious Network Count:** Connections to metadata endpoints, non-standard ports, or C2 hosts.
8. **Sensitive File Access Count:** Reads targeting credential files or system secrets.
9. **Max Syscall Severity:** Peak risk score across all captured events.
10. **Temporal Pattern Count:** Total matches from time-series window analysis.

Vector $\mathbf{x}$ is evaluated by a Random Forest Classifier ($200$ decision trees). The classifier output probability is combined with hard signature boosts to calculate the final verdict (`CLEAN`, `SUSPICIOUS`, or `MALICIOUS`).

### 3.6 MCP Server Security Auditing (Leg 6)
The MCP analysis module (`mcp/`) provisions an isolated container, initializes a simulated JSON-RPC 2.0 client handshake, discovers exposed tools via `tools/list`, and safely executes each tool using synthetic input vectors. It then applies adversarial payloads (e.g., command injection string `; ls /etc`, path traversal `../../../etc/passwd`). System calls emitted during adversarial probes are classified against 6 distinct threat categories including `COMMAND_INJECTION` and `CREDENTIAL_EXFILTRATION`.

### 3.7 Local LLM Triage & Security Guardian (Leg 7)
To assist human security analysts without exposing source code to external cloud services, TraceTree integrates a local LLM pre-commit scanner (`Qwen2.5-Coder:7b` via Ollama). The LLM processes localized code snippets and suspicious strace subsets to produce structured diagnostic summaries.

### 3.8 Autonomous macOS Privacy & Offline Verifier (Leg 8b)
`cascade-audit` verifies offline and zero-telemetry claims for desktop software (e.g., Electron applications, local AI runtimes). It navigates live application UI hierarchies using macOS Accessibility APIs (`pyobjc`) or Chrome DevTools Protocol (`CDP`). Concurrently, background socket state monitors (`lsof`/`netstat`) track open socket descriptors during UI interactions, correlating network traffic directly to specific UI actions to detect hidden telemetry leaks.

---

## 4. Evaluation & Experimental Results

### 4.1 Experimental Setup & Dataset
Evaluation was performed on an Ubuntu 22.04 LTS host equipped with an 8-core Intel Xeon CPU @ 2.80GHz and 32GB RAM.

The evaluation dataset comprises **5,030 package execution runs**:
* **Benign Baselines (5,000 runs):** Executions of top PyPI and npm packages (e.g., `requests`, `urllib3`, `lodash`, `express`) captured during clean installation routines.
* **Malicious Dataset (30 samples):** Active malware samples sourced from MalwareBazaar, research disclosures (including OX Security April 2026 MCP RCE disclosures), and real-world typosquatting samples (e.g., LummaStealer droppers, reverse shells, credential stealers).

### 4.2 Detection Performance & Metrics
Table 1 summarizes the classification performance of the trained Random Forest model across the evaluation dataset.

| Metric | Score / Value |
| :--- | :--- |
| **Precision** | $1.000$ ($100.0\%$) |
| **Recall** | $1.000$ ($100.0\%$) |
| **F1-Score** | $1.000$ ($100.0\%$) |
| **False Positive Rate (FPR)** | $0.000$ ($0.0\%$) |
| **Accuracy** | $1.000$ ($100.0\%$) |
| **5-Fold CV Mean Accuracy** | $1.000 \pm 0.000$ |
| **Training Samples** | $5,030$ |
| **Number of Trees ($N_{estimators}$)** | $200$ |

*Table 1: Classification metrics for the 10-feature Random Forest model.*

### 4.3 Baseline Self-Contamination Fix
During initial benchmark runs on clean PyPI packages, a non-zero false-positive rate was observed due to a **self-contamination issue**: the sandbox initialization script left trace files in `/tmp` that triggered sensitive file access heuristics in subsequent package runs.

Fixing the sandbox lifecycle manager to enforce complete container tear-down and clean volume mounts between runs eliminated these artificial signals, restoring the false-positive rate to $0.0\%$ across all 5,000 clean baseline packages.

### 4.4 System Latency & Scalability
Execution overhead was measured across varying sandbox operational modes:

* **Single Scans:** Average execution latency for standard PyPI/npm packages is **$4.2$ seconds** per scan (inclusive of container provisioning, execution under `strace`, feature extraction, and ML scoring).
* **Parallel Execution Scalability:** Utilizing `ThreadPoolExecutor` across 4 concurrent sandbox workers increases ingestion throughput by **$350\%$**, reducing batch evaluation times for large repository manifests (`requirements.txt`, `package.json`).
* **Resource Footprint:** Peak RAM usage per active sandbox worker remains under **$180$ MB**, enabling deployment on standard CI/CD runner instances without memory starvation.

---

## 5. Limitations

While TraceTree provides robust multi-modal security monitoring, several architectural limitations remain:

1. **Linux Syscall Translation Layer Boundaries:** On non-Linux host platforms (macOS, Windows), Docker runs inside a hypervisor VM. Windows PE executables (`.exe`) executed under `wine64` undergo system call translation; Windows-specific kernel primitives (such as registry modification or COM object interaction) are mapped to Linux syscalls, which may obscure certain OS-specific behavior.
2. **Container & Dynamic Analysis Evasion:** Sophisticated malware designed to detect containerized environments, `ptrace` attachments, or Wine execution layers may refrain from triggering malicious behaviors during the limited scanning window.
3. **Static Execution Timeout:** The sandbox enforces a strict analysis timeout (default $30$ seconds). Payloads employing multi-minute sleep delays or user-interaction triggers (e.g., waiting for GUI events) will exceed the execution window before emitting malicious events.

---

## 6. Conclusion

TraceTree demonstrates a practical, multi-modal framework for detecting supply-chain threats, auditing agentic tool interfaces, and verifying zero-telemetry claims in modern software environments. By coupling kernel-level system call tracing with directed behavioral graphs, a 10-feature Random Forest model, and automated UI socket correlation, TraceTree achieves high detection accuracy ($100\%$ precision/recall on test benchmarks) while maintaining a low computational overhead ($4.2$s average scan latency).
