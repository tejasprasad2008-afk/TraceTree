# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Python (cascade-analyzer)
```bash
pip install -e .           # install in editable mode
pytest                     # run all tests
pytest tests/unit/         # run unit tests only
pytest tests/monitor/      # run monitor tests
pytest -m "not integration" # skip tests requiring Docker/external services
```

### Full monorepo
```bash
make install   # install Python deps + orchestrator + frontend npm packages
make dev       # start orchestrator (Node) + frontend (Next.js) concurrently in dev mode
make build     # build orchestrator TypeScript → dist/ + frontend Next.js
make start     # start both in production mode
make clean     # remove build artifacts and node_modules
```

### Orchestrator (Node.js / TypeScript)
```bash
cd orchestrator && npm run dev    # run with tsx (no build needed)
cd orchestrator && npm run build  # compile TypeScript → dist/
cd orchestrator && npm test       # vitest
cd orchestrator && npm run lint   # eslint
```

### Frontend (Next.js)
```bash
cd frontend && npm run dev    # dev server
cd frontend && npm run build  # production build
```

### CLI entry points (after `pip install -e .`)
```bash
cascade-analyze <target>            # analyze a package/binary
cascade-analyze mcp --npm <pkg>     # analyze an MCP server
cascade-watch <repo>                # session guardian
cascade-check <file>                # quick one-off scan
cascade-train                       # train ML model
cascade-update                      # pull latest model from GCS
cascade-install-hook                # install git-clone shell hook
cascade-dashboard                   # launch dashboard CLI
```

## Architecture

TraceTree is a **monorepo** with three runtime layers:

```
TraceTree/
├── Python detection engine  (pip-installable, cli.py entry point)
├── orchestrator/            (Node.js/TypeScript, Fastify WebSocket server)
└── frontend/                (Next.js dashboard)
```

### Detection pipeline (Python)

`cli.py` → `sandbox/` → `monitor/` → `graph/` → `ml/` → verdict

1. **`sandbox/`** — Builds and manages a `cascade-sandbox:latest` Docker container (python:3.11-slim + strace + wine64 + Node.js). Drops network before execution, returns an strace log path.
2. **`monitor/parser.py`** — Regex strace parser; handles multi-line entries, `[pid]` and bare-pid formats, timestamped (`-t`) output. Produces structured events with per-event severity weights (0–9) and network destination classification.
3. **`monitor/signatures.py`** — Loads 8 behavioral signatures from `data/signatures.json`. Supports unordered and ordered sequence matching. Returns matched signatures with evidence.
4. **`monitor/timeline.py`** — Detects 5 temporal patterns from timestamped events (e.g., credential read → network connect within 5s). Only active when strace ran with `-t` (default).
5. **`graph/builder.py`** — Builds a NetworkX directed graph (process/file/network nodes, temporal edges within 5s windows). Outputs Cytoscape-compatible JSON.
6. **`ml/detector.py`** — Extracts a 10-feature vector, runs RandomForestClassifier (`ml/model.pkl`) or falls back to IsolationForest. Severity/temporal counts boost final confidence independently of ML output.
7. **`mcp/`** — Six-module MCP server analyzer: `sandbox.py`, `client.py` (JSON-RPC 2.0 + adversarial probes), `features.py`, `classifier.py` (6 threat categories), `report.py`.
8. **`watcher/session.py`** — Background daemon; discovers manifests (`requirements.txt`, `package.json`, `setup.py`, `pyproject.toml`), feeds each through the sandbox pipeline.
9. **`orchestrator/ai_mesh.py`** — AI False Positive Jury using a local Ollama instance (`qwen2.5-coder:7b`). Compresses deterministic outputs into JSON prompts. `OLLAMA_HOST` env var defaults to `http://localhost:11434`.

### Orchestrator (Node.js)

`orchestrator/src/server.ts` — Fastify server with WebSocket (`@fastify/websocket`) and CORS. Modules in `src/`: `cli/`, `engine/`, `llm/`, `mcp/`, `planner/`, `store/`, `types/`, `utils/`. Uses `better-sqlite3` (`orchestrator/tracetree.db`) for local persistence.

### Frontend (Next.js)

`frontend/src/` — Next.js dashboard. **Note:** this Next.js version has breaking changes from training-data defaults; read `node_modules/next/dist/docs/` before writing routing or API code.

### macOS menu bar app

`macos_app.py` — `rumps`-based system tray app using AppKit/objc for the file picker. Uses AppleScript (not Tkinter) for GUI interactions to avoid macOS GUI thread crashes.

## Key data files

| File | Purpose |
|------|---------|
| `data/signatures.json` | 8 behavioral signature patterns (severity, syscalls, sequences) |
| `ml/model.pkl` | Serialized RandomForestClassifier (updated via `cascade-update`) |
| `orchestrator/tracetree.db` | SQLite database for orchestrator state |

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama API endpoint for AI mesh |
| `MALWAREBAZAAR_AUTH_KEY` | — | Required for `cascade-train` with external samples |

## Known limitations

- `api/main.py` is a stub — returns hardcoded data, not wired to the real pipeline.
- The ML model was trained on 841 packages; the IsolationForest fallback is a heuristic baseline.
- strace requires Linux; on macOS/Windows, analysis runs inside Docker's Linux VM. DMG/EXE behavioral fidelity is limited.
- `cascade-watch` accepts a URL argument but does **not** clone the repo — it watches the local directory.
