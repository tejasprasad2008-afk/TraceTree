# TraceTree
> Runtime behavioral analysis for Python packages, npm modules, DMG and EXE files — catching supply chain attacks that install-time scanners miss.

![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)

![Header Banner](header%20banner.png)

## How It Works
TraceTree executes suspicious packages inside an isolated Docker sandbox. Right after the initial download starts, it drops the container's network interface. This safely triggers and logs malicious outbound connection attempts without actually letting traffic escape.

A regex engine parses the `strace` output, tracks system calls (like `clone`, `execve`, `socket`, and `openat`), and builds a directed graph using `NetworkX`. Finally, a `RandomForestClassifier` trained on known malware evaluates the graph's topology to detect anomalous behavior.

## Installation
You need Python 3.9+ and Docker running on your machine.

```bash
git clone https://github.com/tejasprasad2008-afk/TraceTree.git
cd TraceTree

# Install the CLI tool in editable mode
pip install -e .
```

## Usage
The pipeline is controlled via a Typer CLI.

```bash
# Analyze a PyPI package
cascade-analyze requests

# Evaluate standard dependency files
cascade-analyze requirements.txt
cascade-analyze package.json

# Analyze compiled installers
cascade-analyze malicious_app.dmg
cascade-analyze payload.exe

# Watch a repo live (with spider mascot!)
cascade-watch ./my-project

# Quick-check a suspicious file
cascade-check setup.py

# Auto-start watcher on every git clone
cascade-install-hook
```

## Advanced Training & Dataset Ingestion
TraceTree features an **Online Training Pipeline** that can fetch live malware samples from [MalwareBazaar](https://malwarebazaar.abuse.ch/).

### Local Training
If you want to train the model locally using the datasets in `data/`:

```bash
# Start the interactive training pipeline
cascade-train
```

During `cascade-train`, you will be prompted for a MalwareBazaar Auth Key. If provided, the tool will:
1.  **Ingest:** Fetch the latest malicious Python samples from MalwareBazaar.
2.  **Sandbox:** Run them through the Docker pipeline to extract fresh behavioral footprints.
3.  **Train:** Re-calculate the Random Forest weights to include the new data.
4.  **Sync:** Automatically cache the new model locally.

### Model Synchronization
To fetch the latest pre-trained model directly from the global cloud storage:

```bash
# Force download the latest global model
cascade-update
```

## Who Is This For
- **Security Researchers:** Hunting undocumented supply chain behavior.
- **DevOps / DevSecOps:** Validating the runtime safety of injected dependencies.
- **Software Engineers:** Profiling the exact syscall requirements of applications.

## Architecture
The pipeline is split into 9 core modules:
1. **`/sandbox`**: Manages the Docker container lifecycle and actively restricts networking during testing.
2. **`/monitor`**: Parses the `strace` log to track execution paths and network attempts.
3. **`/graph`**: Uses `networkx` to translate parent/child process relationships into an edge graph.
4. **`/ml`**: Feeds the extracted graph features into a `RandomForestClassifier` for anomaly detection.
5. **`/mcp`**: MCP server security analysis — sandboxed execution, simulated client, threat classification.
6. **`/watcher`**: Session guardian — background repo watching with live status updates.
7. **`/mascot`**: ASCII spider mascot with animated states for terminal UI.
8. **`/hooks`**: Shell hook for auto-watching repos on `git clone`.
9. **`/cli`**: The Typer entrypoint that orchestrates the pipeline and renders the terminal UI.

![Banner](banner.png)

## MCP Server Security Analysis

> **Built in response to the April 2026 MCP security crisis.** The AgentSeal report and [CVE-2026-32211](https://cve.mitre.org/) exposed widespread vulnerabilities in Model Context Protocol servers — including command injection, credential exfiltration, and prompt injection vectors that bypass traditional static analysis. TraceTree's MCP analyzer executes servers in a sandboxed Docker container, acts as a simulated MCP client to invoke every discovered tool, and classifies the resulting syscall trace for malicious behavior.

### Usage

```bash
# Analyze an npm MCP server package
cascade-analyze mcp --npm @modelcontextprotocol/server-github

# Analyze a local MCP server project
cascade-analyze mcp --path ./my-mcp-server

# Allow network (for servers that legitimately need internet, like GitHub MCP)
cascade-analyze mcp --npm @modelcontextprotocol/server-github --allow-network

# Specify transport explicitly
cascade-analyze mcp --npm some-package --transport stdio
cascade-analyze mcp --npm some-package --transport http --port 3000

# Output as JSON for machine-readable consumption
cascade-analyze mcp --npm some-package --output json
```

### How MCP Analysis Works

1. **Sandbox** — The MCP server runs inside Docker with `strace -f` tracing the entire process tree. Network is blocked by default (`--network none`), and the server runs as a non-root user.
2. **Simulated Client** — TraceTree connects to the server (stdio or HTTP/SSE), performs the full JSON-RPC 2.0 `initialize` handshake, and calls `tools/list` to discover every tool the server exposes.
3. **Safe Invocation** — Each discovered tool is invoked with synthetic arguments (strings → `"test_value"`, numbers → `0`, booleans → `false`). No real credentials or destructive operations are used.
4. **Adversarial Probes** — Each tool is re-invoked with injection payloads (`; ls /etc`, `../../../etc/passwd`, `<script>alert(1)</script>`) to detect command injection, path traversal, and XSS vulnerabilities.
5. **Feature Extraction** — The strace log is parsed for MCP-specific features: network connections per tool call, shell invocations, sensitive file reads, and behavioral changes under adversarial input.
6. **Threat Classification** — A rule-based classifier evaluates the features against known baselines for common server types (filesystem, GitHub, Postgres, fetch, shell).

### Threat Categories

| Threat | Severity | Description |
|---|---|---|
| **COMMAND_INJECTION** | Critical | Shell (`/bin/sh`, `/bin/bash`) spawned in response to tool arguments, especially adversarial ones. |
| **CREDENTIAL_EXFILTRATION** | Critical | Reads `.env`, `~/.aws`, SSH keys, or other secrets, followed by a network connection. |
| **COVERT_NETWORK_CALL** | High | Outbound connection to an unexpected destination during a tool call — potential C2 or exfiltration. |
| **PATH_TRAVERSAL** | High | Reads files outside the working directory, especially sensitive system paths. |
| **EXCESSIVE_PROCESS_SPAWNING** | Medium | Disproportionate number of child processes relative to tool call count. |
| **PROMPT_INJECTION_VECTOR** | High | Tool descriptions contain zero-width characters (U+200B, U+200C, U+200D, U+FEFF), unusual unicode, or language patterns like "ignore previous instructions". |

### Known Server Baselines

TraceTree compares syscall profiles against hardcoded baselines for common legitimate MCP servers:

- **filesystem** — Only `openat`, `read`, `write`, `getdents` within specified directories. No network, no process spawning.
- **github** — Connects to `api.github.com` only. File reads for config/auth allowed. No process spawning.
- **postgres** — Connects to configured DB host only. No filesystem writes outside temp, no process spawning.
- **fetch/browser** — Connects to user-specified URLs only. No filesystem writes, no process spawning.
- **shell/execution** — Explicitly allowed to spawn processes. Flags spawning for non-shell tools.

## 🕷️ Session Guardian

TraceTree can now **watch your development session in real-time** — automatically analyzing packages as you clone, install, or modify them.

### Commands

| Command | Description |
|--------|-------------|
| `cascade-watch <repo>` | Start live monitoring of a repository. Shows spider mascot + real-time status. |
| `cascade-check <file>` | Quick one-off scan of a specific file or command. |
| `cascade-install-hook` | Install shell hook so `git clone` auto-starts `cascade-watch`. |

### Usage

```bash
# Watch a repo live (with spider mascot!)
cascade-watch ./my-project
cascade-watch https://github.com/someone/sus-repo.git

# On-demand deep scan while watching
cascade-watch ./my-project --check setup.py

# Quick-check a suspicious file (one-off)
cascade-check setup.py
cascade-check ./payload.exe

# Auto-start watcher on every git clone
cascade-install-hook
```

### Spider Mascot States

The terminal displays a cute furry spider with 4 eyes that reacts to analysis state:

| State | Behavior | When |
|---|---|---|
| `idle` | Blinking, watching calmly | Default — no analysis running |
| `scanning` | Legs moving toward target | On-demand check in progress |
| `success` | Relaxed pose | Analysis complete — clean verdict |
| `warning` | Eyes wide, alarmed | Analysis complete — malicious detected |
| `alert` | Tense, high-risk posture | Suspicious behavior spotted mid-analysis |

### Shell Hook (Auto-Watch on Clone)

After running `cascade-install-hook`, every `git clone` will automatically start `cascade-watch` in the background:

```bash
$ git clone https://github.com/someone/sus-repo.git
🕷️  TraceTree is now watching sus-repo
   (background session guardian started)
```

💡 Hook logs are written to `/tmp/tracetree_<reponame>.log`.

### Session Locking

Only one watcher per directory is allowed. If you try to watch an already-watched repo, it'll tell you to use `cascade-check` instead.

Lockfiles live in `/tmp/tracetree_sessions/`.

## Key Files

| File | Description |
|---|---|
| `cli.py` | Main CLI entrypoint; now includes `watch`, `check`, `install-hook` commands |
| `mascot/spider.py` | ASCII spider mascot with animated states |
| `watcher/session.py` | Background session guardian logic |
| `hooks/shell_hook.sh` | Bash/zsh wrapper for auto-watching clones |
| `hooks/install_hook.py` | Cross-platform hook installer |
| `sandbox/sandbox.py` | Docker sandbox manager with network restriction |
| `monitor/parser.py` | Strace log parser with syscall classification |
| `graph/builder.py` | NetworkX graph construction from parsed events |
| `ml/detector.py` | Anomaly detection logic; loads model or falls back to IsolationForest |
| `mcp/client.py` | Simulated MCP client with stdio/HTTP transport and adversarial probes |

## Important Notes

1. **Docker must be running** for any sandbox analysis to work. The CLI performs a preflight check.
2. **Session locking**: Only one `cascade-watch` instance per directory. Lockfiles stored in `/tmp/tracetree_sessions/`.
3. **Shell hook**: After `cascade-install-hook`, all `git clone` commands auto-launch `cascade-watch`. Logs at `/tmp/tracetree_<reponame>.log`.
4. **ML model file** (`ml/model.pkl`) is ~100MB and gitignored — not committed to the repo.
5. **`venv/` is machine-specific** — do not commit. Recreate with `pip install -e .` after pulling.

## Threat Model
In late 2024, the highly obfuscated **XZ Utils** backdoor bypassed standard static scanning. Advanced supply chain malware often hides malicious operations deep within legitimate-looking test code or delayed payload fetches. By analyzing the runtime execution graph, TraceTree bypasses code obfuscation entirely to see exactly what external files, commands, and sockets a package actually tries to open.

## Contributing
Pull requests are welcome. Please ensure new features remain decoupled across the existing architecture.

## License
MIT
