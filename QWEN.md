# TraceTree — Project Context

## Project Overview

**TraceTree** (published as `cascade-analyzer`) is a runtime behavioral analysis tool for detecting supply chain attacks in Python packages, npm modules, DMG images, and EXE installers. It executes suspicious packages inside an isolated Docker sandbox with network access restricted, monitors system calls via `strace`, builds a directed execution graph using NetworkX, and classifies behavior as clean or malicious using a scikit-learn `RandomForestClassifier`.

### Core Architecture (9 modules)

| Module | Purpose |
|---|---|
| `sandbox/` | Docker container lifecycle management; drops network during install; runs `strace` |
| `monitor/` | Regex-based strace parser; tracks clone, execve, openat, connect, sendto, socket syscalls |
| `graph/` | Builds a NetworkX directed graph of process/file/network relationships |
| `ml/` | Feature extraction + RandomForestClassifier anomaly detection; GCS model sync |
| `mcp/` | MCP server security analysis — sandboxed execution, simulated client, threat classification |
| `watcher/` | Session guardian — background repo watching with live status updates |
| `mascot/` | Cute spider mascot (`SpiderMascot`) for terminal UI across all commands |
| `hooks/` | Shell hook (`shell_hook.sh`) that auto-watches repos on `git clone` |
| `api/` | FastAPI HTTP server with REST endpoints (currently a stub — not wired to the pipeline) |

### CLI Entry Points

Six commands are registered via `pyproject.toml` / `setup.py`:

| Command | Entrypoint | Purpose |
|---|---|---|
| `cascade-analyze` | `cli:app` | Main analysis command (Typer app with subcommands: `analyze`, `mcp`, `watch`, `quick-check`, `install-hook`) |
| `cascade-watch` | `cli:watch_app` | Standalone session guardian — watches a repo in the background |
| `cascade-check` | `cli:check_cli` | Quick on-demand scan of a specific file or command |
| `cascade-install-hook` | `cli:install_hook_cli` | Installs the shell hook for auto-watching on `git clone` |
| `cascade-train` | `cli:train_cli` | Trains a new model from local data + optional MalwareBazaar ingestion |
| `cascade-update` | `cli:update_cli` | Downloads latest model from Google Cloud Storage |

## Building and Running

### Prerequisites
- Python 3.9+
- Docker (must be running for sandbox functionality)

### Install (development mode)
```bash
pip install -e .
```

### Build distribution
```bash
python setup.py sdist bdist_wheel
```

### Common Commands
```bash
# Analyze a PyPI package
cascade-analyze requests

# Analyze a dependency file
cascade-analyze requirements.txt
cascade-analyze package.json

# Analyze binary installers
cascade-analyze malicious_app.dmg
cascade-analyze payload.exe

# Analyze an MCP server
cascade-analyze mcp --npm @modelcontextprotocol/server-github

# Watch a repository in real-time (session guardian)
cascade-watch ./my-repo
cascade-watch https://github.com/user/suspicious-repo.git
cascade-watch ./my-repo --check setup.py    # on-demand scan

# Quick on-demand check of a specific file
cascade-check ./payload.exe
cascade-check setup.py

# Install the shell hook (auto-watch on git clone)
cascade-install-hook

# Fetch latest pre-trained model from GCS
cascade-update

# Train a new model locally
cascade-train
```

### Data Ingestion (MalwareBazaar)
```bash
# Set auth key (optional — without it only local data is used)
export MALWAREBAZAAR_AUTH_KEY="your-key-here"

# Run ingestion script directly
python ingest_malwarebazaar.py
```

## Session Guardian

The **Session Guardian** (`watcher/` module) watches a repository directory and runs background sandbox analysis on detected packages.

### How It Works

1. **`cascade-watch <repo>`** starts a `SessionWatcher` in a background daemon thread
2. The watcher discovers packages by scanning for `requirements.txt`, `package.json`, `setup.py`, and `pyproject.toml`
3. Each discovered package is run through the sandbox → strace → graph → ML pipeline
4. A spider mascot (`SpiderMascot`) is displayed in `idle` state at the top of the terminal
5. Live status updates show the current phase (`cloning` → `sandboxing` → `analyzing` → `done`), threat count, and confidence
6. Press **Ctrl+C** to stop; a final verdict panel is shown with the spider in `success` (clean) or `warning` (malicious) state

### Key Classes

| Class | File | Purpose |
|---|---|---|
| `SessionWatcher` | `watcher/session.py` | Background watcher with `start()`, `get_status()`, `check_path()`, `stop()`, `wait()` |
| `SpiderMascot` | `mascot/spider.py` | Cute 4-eyed ASCII spider with states: `idle`, `success`, `warning`, `scanning`, `confused` |

### Spider Mascot States

| State | ASCII Art | When Used |
|---|---|---|
| `idle` | ` / \(oo)/ \ ` / `//\(-.-)/\\` | Default — blinking, watching |
| `scanning` | ` / \(?_?)/ \ ` | On-demand check in progress |
| `success` | ` /|\(OvO)/|\ ` | Analysis complete — clean |
| `warning` | ` ///\(ʘᴥ)/\\ ` | Analysis complete — malicious |
| `confused` | ` / \(?_?)/ \ ` | Unknown/invalid state |

### Shell Hook

The **shell hook** (`hooks/shell_hook.sh`) wraps the `git` command so that after every successful `git clone`, TraceTree automatically starts watching the cloned directory in the background.

```bash
# Install the hook
cascade-install-hook

# Or manually
source ~/.local/share/tracetree/hooks/shell_hook.sh

# Now every git clone auto-starts cascade-watch
git clone https://github.com/user/suspicious-repo.git
# 🕷️  TraceTree is now watching /path/to/suspicious-repo
```

The hook:
- Only intercepts `git clone` — all other git commands pass through unchanged
- Uses `nohup` to detach the watcher process
- Logs output to `/tmp/tracetree_<reponame>.log`
- Is idempotent — won't double-wrap if sourced multiple times

### Session Locking

Multiple watchers for the same directory are prevented via a lockfile at `/tmp/tracetree_sessions/<md5-hash>.pid`. Stale locks are auto-cleaned.

## Key Files

| File | Description |
|---|---|
| `cli.py` | Main CLI entrypoint; orchestrates the full sandbox → parse → graph → ML pipeline; defines `watch`, `quick-check`, `install-hook` commands and standalone entry-point wrappers |
| `pyproject.toml` | Modern build config; defines dependencies and console script entry points |
| `setup.py` | Legacy build config (still used); mirrors pyproject.toml |
| `ingest_malwarebazaar.py` | Fetches live malware samples from MalwareBazaar API for training |
| `data/clean_packages.txt` | List of known-clean packages for training |
| `data/malicious_packages.txt` | List of known-malicious packages for training |
| `ml/detector.py` | Anomaly detection logic; loads model or falls back to IsolationForest |
| `ml/trainer.py` | Model training loop over clean + malicious package lists |
| `sandbox/sandbox.py` | Docker sandbox manager with network restriction |
| `monitor/parser.py` | Strace log parser with syscall classification |
| `graph/builder.py` | NetworkX graph construction from parsed events |
| `mcp/client.py` | Simulated MCP client with stdio/HTTP transport, tool discovery, adversarial probes |
| `mcp/sandbox.py` | MCP-specific Docker sandbox with strace -f, network toggle, read-only mount |
| `mcp/features.py` | MCP-specific feature extraction with server type detection and 5 baselines |
| `mcp/classifier.py` | Rule-based threat classification (6 categories: COMMAND_INJECTION, CREDENTIAL_EXFILTRATION, etc.) |
| `mcp/report.py` | Rich console + JSON report generation |
| `watcher/session.py` | Session guardian with background thread, status polling, on-demand checks |
| `mascot/spider.py` | SpiderMascot class with 5 animation states |
| `hooks/shell_hook.sh` | Bash/zsh wrapper for auto-watching on git clone |
| `hooks/install_hook.py` | Cross-platform Python installer for the shell hook |
| `api/main.py` | FastAPI server (stub — not connected to real pipeline) |

## Development Conventions

### Code Style
- Follow PEP 8; max line length 88 (Black-compatible)
- Type hints on all function signatures
- Naming: `snake_case` for modules/functions, `PascalCase` for classes, `UPPER_SNAKE_CASE` for constants
- Docstrings with Args/Returns/Raises sections

### Import Order
1. Standard library
2. Third-party (typer, docker, rich, networkx, sklearn, fastapi)
3. Local modules (from .sandbox, from .monitor, etc.)

### Error Handling
- Try/except around Docker calls, network requests, and ML operations
- Graceful fallbacks (e.g., IsolationForest when no trained model exists)
- Rich console panels for user-facing errors

### Testing
- No formal test framework is set up
- Manual testing is the primary verification method
- When adding tests, use pytest in a `tests/` directory

## Important Notes

1. **`TraceTree/` subdirectory is a duplicate** — a leftover from a prior `pip install -e .` or build. The authoritative source modules are at the root level. Safe to delete.
2. **ML model file (`ml/model.pkl`) is ~100MB and gitignored** — not committed to the repo. First run downloads it from GCS or uses the IsolationForest fallback.
3. **`data/ingested_training_data.csv` is generated, not committed** — produced by `ingest_malwarebazaar.py`.
4. **`venv/` is machine-specific** — do not commit. Recreate with `pip install -e .` after pulling.
5. **API server (`api/main.py`) is a stub** — the background analysis task is not wired to the real pipeline. The CLI is the functional entry point.
6. **Docker must be running** for any sandbox analysis to work. The CLI performs a preflight check.
7. **Session lockfiles** live in `/tmp/tracetree_sessions/` — stale locks are auto-cleaned on next acquisition.
8. **Shell hook logs** go to `/tmp/tracetree_<reponame>.log` when triggered by `git clone`.

## Dependencies

```
typer>=0.9.0          # CLI framework
rich>=13.4.0          # Terminal UI formatting
networkx>=3.0         # Graph construction
scikit-learn>=1.3.0   # ML (RandomForest, IsolationForest)
fastapi>=0.100.0      # HTTP API
uvicorn>=0.23.0       # ASGI server
docker>=7.0.0         # Docker SDK for Python
google-cloud-storage>=2.10.0  # GCS model storage
requests>=2.25.1      # HTTP client (MCP + data ingestion)
```
