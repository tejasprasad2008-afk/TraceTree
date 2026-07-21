# TraceTree

![TraceTree Banner](header%20banner.png)

![TraceTree Demo](tracetree%20ad.gif)

**TraceTree** (cascade-analyzer) is an autonomous security organism designed for the agentic era. It moves beyond simple scanning into a robust, hardened, and scalable detection ecosystem. Like its mascot, the spider, TraceTree weaves a comprehensive web of protection around your development workflow using its eight specialized "legs."

## Table of Contents
* [Repository Structure](#repository-structure)
* [Behavior receipt export](#behavior-receipt-export)
* [The 8 Legs of the TraceTree Spider](#the-8-legs-of-the-tracetree-spider)
* [How It Works](#how-it-works)
* [What It Detects](#what-it-detects)
  * [Behavioral Signatures](#behavioral-signatures-8-patterns)
  * [Temporal Patterns](#temporal-patterns-5-patterns)
* [Supported Targets](#supported-targets)
* [Quick Start (Skip to Installation)](#quick-start)
  * [Prerequisites](#prerequisites)
  * [Install](#install)
  * [Run an Analysis](#run-an-analysis)
* [CLI Reference](#cli-reference)
* [MCP Server Security Analysis](#mcp-server-security-analysis)
* [Architecture Overview](#architecture)
* [Limitations & Blind Spots](#limitations--blind-spots)

## Behavior receipt export

TraceTree can be used as a review gate before agents or humans trust a package install. See [Behavior receipt export](docs/behavior-receipt-export.md) for a small JSON/SARIF-friendly receipt shape that summarizes target hash, sandbox policy, observed behavior, artifact hashes, verdict, and privacy defaults without exposing raw syscall logs.


## Repository Structure

```
TraceTree/
├── api/                    # API stubs
├── codebase-analysis-docs/ # Architecture documents and knowledge guides
├── data/                   # Behavioral signatures, rules, and training datasets
├── docs/                   # Documentation assets
├── examples/               # Demo scripts and usage examples
├── frontend/               # Next.js/React web dashboard
├── graph/                  # NetworkX directed graph builder
├── hooks/                  # Git/Shell hooks for background monitoring
├── logs/                   # Execution trace logs and strace outputs
├── macapp/                 # Native macOS menu bar app
├── mascot/                 # Console ASCII spider mascot
├── mcp/                    # MCP server security testing module
├── ml/                     # Machine learning classification and anomaly detection
├── monitor/                # Core syscall parser, YARA matching, and timelines
├── orchestrator/           # TypeScript multi-agent coordination server
├── repocheckai/            # Repository analysis engine (TypeScript/Node)
├── samples/                # Malware and benign files for sandbox tests
├── sandbox/                # Docker container manager and strace sandbox
├── test_targets/           # Mock packages/servers for detection testing
├── tests/                  # Unit, integration, and system tests
├── watcher/                # File system change listener daemon
└── worker/                 # Background task execution worker
```

## The 8 Legs of the TraceTree Spider

1.  **Leg 1: Sandbox Isolation (The Trap)** — Executes targets in isolated Docker containers (or a high-performance `direct` mode) where threats are physically contained.
2.  **Leg 2: Syscall Parsing (The Nervous System)** — A high-precision engine that monitors every "vibration" (system call) a process makes to the OS.
3.  **Leg 3: Behavioral Graphing (The Web)** — Maps the "Cascade" of how processes, files, and network nodes interact using NetworkX directed graphs.
4.  **Leg 4: ML Anomaly Detection (The Intuition)** — A custom-trained Random Forest model (trained on a small, representative dataset of clean/malicious packages, plus optional live MalwareBazaar feeds) that predicts malicious intent with high confidence.
5.  **Leg 5: YARA Signature Matching (The Memory)** — An integrated library of known malware DNA and exploit patterns (Reverse Shells, Cryptominers, etc.).
6.  **Leg 6: MCP Security Protocol (The Agent Shield)** — Specialized protection for Model Context Protocol servers, defending the tools that AI agents use.
7.  **Leg 7: Security Guardian AI (The Proactive Web)** — A pre-commit "Smart Scanner" using local LLMs (Qwen-Coder) to catch leaks and injections before they hit your history.
8.  **Leg 8: Temporal & N-gram Analysis (The DNA Scan)** — Identifies threats by the *rhythm* and *sequence* of their actions across time.

## How It Works

```
target ──► Docker sandbox (network dropped) ──► strace -t -f
                                               │
                                               ▼
                                          strace log
                                               │
                              ┌────────────────┼────────────────┐
                              ▼                ▼                ▼
                        strace parser      signature       temporal
                        (parser.py)     matcher (sigs)    analyzer
                              │                │                │
                              └───────┬────────┴────────────────┘
                                      ▼
                              NetworkX graph
                              (builder.py)
                                      │
                                      ▼
                          ML anomaly detection
                          (RandomForest / IsolationForest)
                                      │
                                      ▼
                                 verdict
```

1. **Sandbox** — The target runs inside a Docker container. Network is dropped (`ip link set eth0 down`) before installation/execution begins, so any outbound connection attempts are logged but blocked.
2. **strace** — Every syscall is traced with `strace -t -f -e trace=all`. The `-t` flag adds timestamps for temporal analysis, `-f` follows child processes.
3. **Parser** (`monitor/parser.py`) — Regex-based parser that handles multi-line strace output and both `[pid]` and bare-pid formats. Extracts process creation, file access, network connections, and memory operations. Each syscall is assigned a severity weight (0–9) based on its security relevance.
4. **Signature matching** (`monitor/signatures.py`) — Matches the parsed event stream against 8 behavioral signature patterns defined in `data/signatures.json`. Each match produces evidence listing the specific events that triggered it.
5. **Temporal analysis** (`monitor/timeline.py`) — Detects 5 time-based behavioral patterns from the timestamped event stream (e.g., credential read followed by external connection within 5 seconds).
6. **Graph** (`graph/builder.py`) — Builds a NetworkX directed graph with process, file, and network nodes. Adds temporal edges between consecutive same-PID events within a 5-second window.
7. **ML** (`ml/detector.py`) — Extracts a 10-feature vector from the graph and parsed data. Uses a RandomForestClassifier if a trained model is available, falls back to an IsolationForest trained on 10 hardcoded clean-package baselines. Severity scores and temporal pattern counts boost the final confidence.

## What It Detects

### Behavioral Signatures (8 patterns)

Defined in `data/signatures.json`. Each has a severity (1–10), required syscalls, file patterns, network conditions, and an ordered sequence to match.

| Signature | Severity | What it catches |
|---|---|---|
| `reverse_shell` | 10 | External connect → dup2 → execve /bin/sh |
| `container_escape` | 10 | openat of /proc/1/, /sys/fs/cgroup, /var/run/docker.sock |
| `credential_theft` | 9 | openat of /etc/shadow, .ssh/, .aws/ → external connect |
| `typosquat_exfil` | 9 | Secret read (.env, .npmrc) → connect to pastebin/file.io/transfer.sh |
| `process_injection` | 9 | mprotect PROT_EXEC → execve of non-standard binary |
| `crypto_miner` | 8 | clone → clone → connect to mining pool port (3333, 4444, 14444, 45700) |
| `dns_tunneling` | 7 | getaddrinfo + sendto + socket on port 53/5353 |
| `persistence_cron` | 7 | openat of crontab path → write |

### Temporal Patterns (5 patterns)

Detected from timestamped strace output. Requires strace `-t` flag (enabled by default).

| Pattern | Severity | Trigger condition |
|---|---|---|
| `connect_then_shell` | 10 | External connect → execve /bin/sh within 3 seconds |
| `credential_scan_then_exfil` | 9 | Sensitive file read → external connect within 5 seconds |
| `delayed_payload` | 8 | >10s gap followed by burst of suspicious activity (dropper behavior) |
| `rapid_file_enumeration` | 7 | 10+ file opens within 1 second (scanning behavior) |
| `burst_process_spawn` | 7 | 5+ clone/execve within 2 seconds |

### Severity-Weighted Syscall Scoring

Each of 24 syscall types has a base severity weight. Examples:
- `mprotect` with `PROT_EXEC`: 9.0
- `dup2` after a `connect`: 9.0
- `execve` of unexpected binary: 7.0
- `connect` to cloud metadata (169.254.x.x): 8.0
- `connect` to PyPI/npm CDN: 0.0 (benign)
- `openat` of /usr/lib/python/*: 0.0 (benign)

The total severity score feeds into the ML confidence calculation.

### Network Destination Classification

Every `connect` syscall is classified into one of four categories:

| Category | Criteria | Risk score |
|---|---|---|
| `safe_registry` | IP matches known PyPI/npm/GitHub CDN ranges | 0.0 |
| `known_benign` | Standard web port (80/443) to unclassified host | 0.5 |
| `suspicious` | Cloud metadata (169.254.x.x), private IP from container, or suspicious port (4444, 1337, 31337, etc.) | 8.0–9.0 |
| `unknown` | Default | 3.0 |

## Supported Targets

| Target type | How it works | Notes |
|---|---|---|
| **PyPI packages** | `pip download` (with network), then `pip install --no-index` (without network) under strace | Most reliable. Network is dropped before install. |
| **npm packages** | `npm install` under strace, network dropped after dry-run | Requires Node.js in the sandbox image. |
| **DMG files** | Extracted with `7z` inside the container. Found scripts (.sh, .py, .command), .pkg installers, .app bundles, and bare Mach-O binaries are each executed under strace. | Requires p7zip-full in the sandbox image. DMG extraction may fail on encrypted or uncommon formats. Scripts are run in a Linux container, so macOS-specific behavior won't execute. |
| **EXE files** | Run under `wine64` with `strace -t -f` and a 30-second timeout. Wine initialization noise is filtered from the strace log. | Requires wine64 in the sandbox image. GUI apps that wait for user input will timeout. Wine's translation layer means syscalls are Linux syscalls, not native Windows — some Windows-specific behavior may not be visible. |

## Quick Start

### Prerequisites

- Python 3.9+
- Node.js 18+ and npm (required for the Workbench dashboard)
- Docker (required to run sandbox scans; the dashboard itself can open without it)

### Install

```bash
git clone --depth 1 https://github.com/tejasprasad2008-afk/TraceTree.git
cd TraceTree
pip install -e .
```

### First-run Workbench setup

```bash
# Opens the visual, step-by-step first-run wizard in your browser.
cascade-analyze setup
```

On a fresh clone, TraceTree installs the frontend and orchestrator dependencies, then opens the local Workbench. The first-run screen lets you choose **OpenAI**, Anthropic, or OpenRouter; paste an API key; accept or replace the provider base URL; and enter the model identifier you want to use. It saves the selection only to the ignored root `.env` file and asks you to restart the dashboard to load it.

No cloud key is required just to explore the Workbench: choose **Set up later** to start in local mock mode. You can return to the provider wizard by clearing the browser's TraceTree site data, or configure it from the terminal:

```bash
cascade-analyze dashboard
```

The built-in defaults are `https://api.openai.com/v1`, `https://api.anthropic.com`, and `https://openrouter.ai/api/v1`. Copy [.env.example](.env.example) to `.env` if you prefer to configure manually. Run `cascade-analyze dashboard --check` to validate Node, frontend/orchestrator dependencies, and Docker before launching.

### Run an Analysis

```bash
cascade-analyze --help
```

Output:

```
 ┌──────────────────────────────────────┐
 │ TraceTree Security Analyzer          │
 │ Target: requests                     │
 │ Analyzer Type: PIP                   │
 └──────────────────────────────────────┘
 ✔ Sandboxing requests (pip)...
 ✔ Parsing requests...
 ✔ Graphing requests...
 ✔ Detecting requests...

 ┌─ Cascade Graph: requests ────────────┐
 │ pip install requests                 │
 │  └─ pip (root)                       │
 │     └─ net_151.101.1.69:443 (connect)│
 │     └─ file_/usr/lib/python3.11/...  │
 └──────────────────────────────────────┘

 ┌─ Flagged Behaviors ──────────────────┐
 │ No suspicious footprints flagged.    │
 └──────────────────────────────────────┘

        ┌──────────┐
        │  CLEAN   │
        └──────────
        Confidence Score: 72.3%
```

For a malicious package (e.g., a known typosquat):

```
 ┌─ Behavioral Signatures Matched ──────┐
 │ 🔴 credential_theft (severity 9/10) │
 │   Step 1: openat /etc/shadow         │
 │   Step 2: connect 45.33.32.156:4444  │
 └──────────────────────────────────────┘

 ┌─ Temporal Execution Patterns ────────┐
 │ 🔴 connect_then_shell (severity 10/10)│
 │   Window: 1500-4200 ms — External... │
 └──────────────────────────────────────┘

        ┌───────────┐
        │ MALICIOUS │
        └───────────┘
        Confidence Score: 99.9%
        Signatures: credential_theft | Temporal: connect_then_shell
```

## CLI Reference

### `cascade-analyze <target>`

Analyze a single package, binary, or bulk file.

```bash
# PyPI package
cascade-analyze requests
cascade-analyze urllib33      # known typosquat

# npm package
cascade-analyze package.json

# DMG / EXE
cascade-analyze suspicious_app.dmg
cascade-analyze payload.exe

# Bulk analysis
cascade-analyze requirements.txt
cascade-analyze package.json

# Force target type
cascade-analyze ./some_file --type pip
cascade-analyze ./some_file --type npm
cascade-analyze ./some_file --type dmg
cascade-analyze ./some_file --type exe
```

**Subcommand: `cascade-analyze mcp`** — MCP server security analysis (see MCP section below).

**Subcommand: `cascade-analyze watch <repo>`** — Session guardian (see Session Guardian section).

**Subcommand: `cascade-analyze check <file>`** — Quick on-demand scan.

### `cascade-watch <repo>`

Standalone session guardian. Watches a directory for package manifests and runs background sandbox analysis.

```bash
cascade-watch ./my-project
cascade-watch ./my-project --check setup.py    # on-demand scan
cascade-watch https://github.com/user/repo.git  # URL accepted but not cloned
```

Displays a spider mascot in the terminal and polls status in a loop. Press Ctrl+C to stop. Only one watcher per directory is allowed (lockfile at `/tmp/tracetree_sessions/`).

### `cascade-check <file>`

Quick one-off analysis of a specific file. Starts a fresh sandbox run and returns a verdict.

```bash
cascade-check setup.py
cascade-check ./payload.exe
```

### `cascade-install-hook`

Installs a shell hook that runs `cascade-watch` automatically after every `git clone`.

```bash
cascade-install-hook
```

This appends a `source` line to `~/.bashrc` or `~/.zshrc`. The hook script lives at `~/.local/share/tracetree/hooks/shell_hook.sh`. After installation, every `git clone` will launch a background watcher and log to `/tmp/tracetree_<reponame>.log`.

### `cascade-train`

Interactive training pipeline. Prompts for a MalwareBazaar API key (optional — can be skipped to train on local datasets only), then:

1. Ingests samples from MalwareBazaar (if key provided)
2. Runs each through the sandbox pipeline
3. Trains a RandomForestClassifier on the extracted features
4. Saves to `ml/model.skops` and invalidates cache

```bash
export MALWAREBAZAAR_AUTH_KEY="your-key"
cascade-train
```

## MCP Server Security Analysis

The `cascade-analyze mcp` subcommand analyzes Model Context Protocol servers for malicious behavior. It runs the server in a sandboxed container, acts as a simulated MCP client to discover and invoke every tool, then classifies the resulting syscall trace.

```bash
# Analyze an npm MCP server
cascade-analyze mcp --npm @modelcontextprotocol/server-github

# Analyze a local MCP server project
cascade-analyze mcp --path ./my-mcp-server

# Allow network (for servers that legitimately need internet)
cascade-analyze mcp --npm @modelcontextprotocol/server-github --allow-network

# Force transport
cascade-analyze mcp --npm some-package --transport stdio
cascade-analyze mcp --npm some-package --transport http --port 3000

# JSON output
cascade-analyze mcp --npm some-package --output json
```

### What MCP analysis does

1. **Sandbox** — Server runs in Docker with network blocked by default. Traced with `strace -f`.
2. **Client simulation** — JSON-RPC 2.0 `initialize` handshake, `tools/list` discovery, safe invocation of every tool with synthetic arguments.
3. **Adversarial probes** — Each tool re-invoked with injection payloads (`; ls /etc`, `../../../etc/passwd`, `<script>alert(1)</script>`).
4. **Feature extraction** — MCP-specific features: per-tool network connections, shell invocations, sensitive file reads, behavior changes under adversarial input.
5. **Threat classification** — Rule-based classifier with 6 categories:

| Threat | Severity | Description |
|---|---|---|
| `COMMAND_INJECTION` | Critical | Shell spawned in response to tool arguments |
| `CREDENTIAL_EXFILTRATION` | Critical | Secret read followed by network connection |
| `COVERT_NETWORK_CALL` | High | Outbound connection during tool call to unexpected destination |
| `PATH_TRAVERSAL` | High | File reads outside working directory |
| `EXCESSIVE_PROCESS_SPAWNING` | Medium | Disproportionate child process count |
| `PROMPT_INJECTION_VECTOR` | High | Tool descriptions contain zero-width characters or injection language |

6. **Baseline comparison** — Compares syscall profiles against hardcoded baselines for 5 server types: `filesystem`, `github`, `postgres`, `fetch`, `shell`.

## Architecture

**`sandbox/`** — Docker container lifecycle management. Builds `cascade-sandbox:latest` from a Dockerfile based on `python:3.11-slim` with strace, wine64, p7zip-full, cabextract, Node.js, and npm. Drops the network interface (`ip link set eth0 down`) before target execution. Supports pip, npm, DMG, and EXE targets. Returns a strace log path or empty string on failure.

**`monitor/parser.py`** — Regex-based strace log parser. Handles multi-line syscall entries, both `[pid]` and bare-pid formats, and timestamped (`-t`) output. Tracks 24 syscall types across 5 categories (process, network, file, memory, IPC). Assigns per-event severity weights, classifies network destinations, and flags sensitive file accesses. Returns structured event data with timestamps and relative millisecond offsets.

**`monitor/signatures.py`** — Behavioral signature matcher. Loads 8 patterns from `data/signatures.json`. Supports both unordered matching (required syscalls + file/network patterns must be present) and ordered sequence matching (syscall-condition pairs must appear in order). Returns matched signatures with evidence listing the specific events that triggered each match.

**`monitor/timeline.py`** — Temporal pattern analyzer. Detects 5 time-based behavioral patterns from the ordered, timestamped event stream. Each pattern specifies a severity, a time window, and the triggering conditions. Returns matches sorted by severity descending. Only active when strace was run with `-t` (which is the default).

**`graph/builder.py`** — NetworkX directed graph construction. Creates nodes for processes, files, and network destinations. Adds edges for clone relationships, syscall targets, and temporal relationships (consecutive same-PID events within 5 seconds). Nodes and edges are tagged with signature matches and severity weights. Outputs Cytoscape-compatible JSON and internal stats.

**`ml/detector.py`** — Anomaly detection. Extracts a 10-feature vector (node count, edge count, network connections, file reads, execve count, total severity, suspicious networks, sensitive files, max severity, temporal pattern count). Uses RandomForestClassifier if a trained model is available locally or downloadable from GCS; falls back to IsolationForest trained on 10 hardcoded clean-package baselines. Severity scores and temporal pattern counts boost the final confidence independently of the ML prediction.

**`mcp/`** — MCP server analysis module. Six files: `sandbox.py` (Docker sandbox for MCP servers), `client.py` (JSON-RPC 2.0 client with tool discovery and adversarial probes), `features.py` (MCP-specific feature extraction with server type detection), `classifier.py` (rule-based threat classification), `report.py` (Rich console + JSON report generation).

**`watcher/session.py`** — Session guardian. `SessionWatcher` class runs in a background daemon thread. Discovers packages by scanning for `requirements.txt`, `package.json`, `setup.py`, and `pyproject.toml`. Runs each through the sandbox pipeline. Exposes status via `get_status()` and results via a `Queue`. Session locking via lockfile at `/tmp/tracetree_sessions/`.

**`mascot/spider.py`** — `SpiderMascot` class. ASCII spider with 5 states (`idle`, `success`, `warning`, `scanning`, `confused`). Used in the CLI for visual feedback during analysis.

**`hooks/`** — Shell hook system. `shell_hook.sh` wraps the `git` command to intercept `git clone` and start `cascade-watch` in the background. `install_hook.py` is a cross-platform installer that detects bash/zsh and appends the source line to the appropriate RC file.

**`cli.py`** — Typer CLI entry point. Registers all subcommands. Orchestrates the analysis pipeline with Rich progress bars and formatted output panels.

## Limitations & Blind Spots

- **ML model reliability** — The trained RandomForest model is only as good as its training data. The current model was trained on a small set of packages. For reliable detection, run `cascade-train` with a large, labeled dataset. The IsolationForest fallback is a heuristic baseline, not a production-quality model.
- **Network sandbox exclusion** — By default, the sandbox disables network access (`ip link set eth0 down`) before running/installing the package to prevent active data exfiltration during scanning. While secure, this means malware requiring network handshakes or C2 connections during installation may not execute its payload, or some legitimate installers that require internet connectivity will fail. To bypass this, pass the `--controlled-network` option to enable controlled/sinkhole network mode.
- **Container and strace evasion** — Advanced malware can detect it is running inside a Docker container (by checking cgroups, filesystem clues, etc.) or detect that its processes are under `strace`/`ptrace` monitoring (by calling `ptrace(PTRACE_TRACEME, ...)` or checking `TracerPid` in `/proc/self/status`). If evasion is triggered, the malware may terminate early or execute only benign actions, evading detection.
- **strace requires Linux** — The sandbox runs on Linux inside Docker. On macOS and Windows, Docker runs a Linux VM, which works, but native macOS or Windows syscalls cannot be traced. DMG scripts and EXE binaries are executed in a Linux environment, which limits their behavioral fidelity.
- **wine64 EXE analysis is best-effort** — Wine translates Windows syscalls to Linux syscalls. Some Windows-specific behavior (registry access, COM objects, Windows API calls) may not produce visible Linux-level syscalls. GUI applications that wait for user input will timeout after 30 seconds.
- **DMG analysis is limited** — DMG files are extracted with 7z, which may fail on encrypted or uncommon formats. Extracted scripts are run in a Linux container, so macOS-specific behavior (launchd, Keychain, etc.) will not execute.
- **API implementation** — `api/main.py` is wired to run the actual TraceTree analysis pipeline inside background tasks. It uses an in-memory database (`mock_db`) for job tracking, and requires the `TRACETREE_API_KEYS` environment variable to be set to start.
- **Session guardian does not clone repos** — `cascade-watch` accepts a URL argument but does not perform `git clone`. It watches the local directory or falls back to the current working directory.

## Contributing

Pull requests are welcome. Please keep new features decoupled from existing modules.

## License

MIT
