# TraceTree — Project Context

## Project Overview

**TraceTree** (published as `cascade-analyzer`) is a runtime behavioral analysis tool for detecting supply chain attacks in Python packages, npm modules, DMG images, and EXE installers. It executes suspicious packages inside an isolated Docker sandbox with network access restricted, monitors system calls via `strace`, builds a directed execution graph using NetworkX, and classifies behavior as clean or malicious using a scikit-learn `RandomForestClassifier`.

### Core Architecture (5 modules)

| Module | Purpose |
|---|---|
| `sandbox/` | Docker container lifecycle management; drops network during install; runs `strace` |
| `monitor/` | Regex-based strace parser; tracks clone, execve, openat, connect, sendto, socket syscalls |
| `graph/` | Builds a NetworkX directed graph of process/file/network relationships |
| `ml/` | Feature extraction + RandomForestClassifier anomaly detection; GCS model sync |
| `api/` | FastAPI HTTP server with REST endpoints (currently a stub — not wired to the pipeline) |

### CLI Entry Points

Three commands are registered via `pyproject.toml` / `setup.py`:

- `cascade-analyze` → `cli:app` — main analysis command (Typer app)
- `cascade-train` → `cli:train_cli` — trains a new model from local data + optional MalwareBazaar ingestion
- `cascade-update` → `cli:update_cli` — downloads latest model from Google Cloud Storage

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

## Key Files

| File | Description |
|---|---|
| `cli.py` | Main CLI entrypoint; orchestrates the full sandbox → parse → graph → ML pipeline |
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
```
