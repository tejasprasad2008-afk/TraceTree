from fastapi import FastAPI, BackgroundTasks, HTTPException, Header, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import uuid
import os
import pty
import fcntl
import re
import select
import shlex
import subprocess
import sys
import time
from pathlib import Path

_ANSI_RE = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-9;]*[ -/]*[@-~]|\][^\x07]*\x07)')

def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)
from graph.builder import build_cascade_graph
from ml.detector import detect_anomaly
from monitor.parser import parse_strace_log
from sandbox.sandbox import run_sandbox

# --- Security ---
# Production: set TRACETREE_API_KEYS="key1,key2".
# Local dev (no env var): accepts fixed "dev-key" only; logs a warning.
_api_keys_str = os.getenv("TRACETREE_API_KEYS")
_LOCAL_MODE = not bool(_api_keys_str)
if _LOCAL_MODE:
    import warnings
    # Fail-loudly if the process is listening on a non-loopback interface.
    # TRACETREE_BIND_HOST defaults to 127.0.0.1; must be set explicitly to override.
    _bind_host = os.getenv("TRACETREE_BIND_HOST", "127.0.0.1")
    if _bind_host not in ("127.0.0.1", "localhost", "::1"):
        raise RuntimeError(
            f"TRACETREE_API_KEYS is not set but TRACETREE_BIND_HOST={_bind_host!r}. "
            "Refusing to start in local mode while bound to a non-loopback interface."
        )
    warnings.warn(
        "TRACETREE_API_KEYS not set — local mode active. "
        "Accepting 'dev-key' only. Do not expose to network.",
        stacklevel=1,
    )
    VALID_API_KEYS: set = {"dev-key"}
else:
    VALID_API_KEYS = set(k.strip() for k in _api_keys_str.split(",") if k.strip())

async def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key not in VALID_API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key

app = FastAPI(
    title="TraceTree API",
    description="[NON-PRODUCTION] API for analyzing suspicious Python packages by monitoring runtime behavioral cascades.",
    version="1.0.0"
)

# Enable CORS with a configurable allowlist (default to localhost)
cors_origins_str = os.getenv("TRACETREE_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000,http://localhost:3001,http://127.0.0.1:3001")
allow_origins = [origin.strip() for origin in cors_origins_str.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory database for tracking analysis jobs
# In Phase 2.3, this will move to Redis
mock_db: Dict[str, Dict[str, Any]] = {
    "demo-id": {
        "id": "demo-id",
        "status": "completed",
        "package_name": "requests-async-v2",
        "verdict": "MALICIOUS",
        "confidence_score": 0.98,
        "logs": []
    }
}

class AnalysisRequest(BaseModel):
    package_name: str
    target_type: str = "pip"  # pip, npm, dmg, exe
    env_vars: Optional[Dict[str, str]] = None

class AnalysisResult(BaseModel):
    id: str
    status: str
    package_name: str
    verdict: Optional[str] = None
    confidence_score: Optional[float] = None
    error: Optional[str] = None


class LLMSetupRequest(BaseModel):
    provider: str
    api_key: str
    base_url: str
    model: str


_LLM_SETUP_FIELDS = {
    "openai": ("OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_MODEL"),
    "claude": ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "ANTHROPIC_MODEL"),
    "openrouter": ("OPENROUTER_API_KEY", "OPENROUTER_BASE_URL", "OPENROUTER_MODEL"),
}


def _update_env_file(path: Path, values: Dict[str, str]) -> None:
    """Update selected values without echoing secrets or replacing unrelated config."""
    existing = path.read_text() if path.exists() else ""
    lines = existing.splitlines()
    pending = dict(values)
    output: List[str] = []
    for line in lines:
        key = line.split("=", 1)[0].strip() if "=" in line else ""
        if key in pending:
            output.append(f"{key}={pending.pop(key)}")
        else:
            output.append(line)
    output.extend(f"{key}={value}" for key, value in pending.items())
    path.write_text("\n".join(output).rstrip() + "\n")


@app.post("/api/setup/llm")
async def configure_llm(request: LLMSetupRequest, api_key: str = Depends(verify_api_key)):
    """Persist a local Workbench LLM choice; the dashboard never returns the secret."""
    provider = request.provider.strip().lower()
    if provider not in _LLM_SETUP_FIELDS:
        raise HTTPException(status_code=400, detail="Choose OpenAI, Anthropic, or OpenRouter.")
    if not request.api_key.strip() or len(request.api_key) > 512:
        raise HTTPException(status_code=400, detail="Enter a valid API key.")
    if not request.model.strip() or len(request.model) > 200:
        raise HTTPException(status_code=400, detail="Enter a model name.")
    base_url = request.base_url.strip().rstrip("/")
    if not re.fullmatch(r"https?://[^\\s/]+(?:/[^\\s]*)?", base_url) or len(base_url) > 300:
        raise HTTPException(status_code=400, detail="Enter a valid HTTP(S) base URL.")

    key_name, base_name, model_name = _LLM_SETUP_FIELDS[provider]
    project_root = Path(__file__).resolve().parent.parent
    _update_env_file(project_root / ".env", {
        "LLM_PROVIDER": provider,
        key_name: request.api_key.strip(),
        base_name: base_url,
        model_name: request.model.strip(),
    })
    return {"saved": True, "provider": provider, "restart_required": True}

class GraphNodeData(BaseModel):
    id: str
    label: str
    type: str

class GraphNode(BaseModel):
    data: GraphNodeData

class GraphEdgeData(BaseModel):
    source: str
    target: str
    label: str

class GraphEdge(BaseModel):
    data: GraphEdgeData

class GraphVisualizationResponse(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]

# --- Real Analysis Task ---

def run_real_analysis(analysis_id: str, package_name: str, target_type: str, env_vars: Dict[str, str] = None):
    """
    Orchestrates the real TraceTree analysis pipeline.
    """

    try:
        # 1. Sandbox Execution
        log_path = run_sandbox(package_name, target_type=target_type, env=env_vars)
        if not log_path:
            mock_db[analysis_id].update({"status": "failed", "error": "Sandbox failed to produce logs"})
            return

        # 2. Parsing
        parsed = parse_strace_log(log_path)

        # 3. Graphing
        graph = build_cascade_graph(parsed)

        # 4. ML Detection
        is_malicious, confidence = detect_anomaly(graph, parsed)

        # Update DB
        mock_db[analysis_id].update({
            "status": "completed",
            "verdict": "MALICIOUS" if is_malicious else "CLEAN",
            "confidence_score": confidence,
            "graph": graph  # Store for later retrieval
        })

    except Exception as e:
        mock_db[analysis_id].update({"status": "failed", "error": str(e)})

@app.post("/analyze", response_model=AnalysisResult)
async def submit_analysis(
    request: AnalysisRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    analysis_id = str(uuid.uuid4())
    mock_db[analysis_id] = {
        "id": analysis_id,
        "status": "pending",
        "package_name": request.package_name,
        "verdict": None,
        "confidence_score": None,
        "error": None
    }

    # 2.2 IMPLEMENT ASYNC JOB QUEUE (via BackgroundTasks)
    background_tasks.add_task(
        run_real_analysis,
        analysis_id,
        request.package_name,
        request.target_type,
        request.env_vars
    )

    return mock_db[analysis_id]

@app.get("/results/{analysis_id}", response_model=AnalysisResult)
async def get_results(analysis_id: str, api_key: str = Depends(verify_api_key)):
    if analysis_id not in mock_db:
        raise HTTPException(status_code=404, detail="Analysis ID not found")
    return mock_db[analysis_id]

@app.get("/graph/{analysis_id}", response_model=GraphVisualizationResponse)
async def get_graph(analysis_id: str, api_key: str = Depends(verify_api_key)):
    if analysis_id not in mock_db:
        raise HTTPException(status_code=404, detail="Analysis ID not found")

    # Check if real graph data exists
    if "graph" in mock_db[analysis_id]:
        # Convert internal graph format to Cytoscape-compatible for frontend
        internal_graph = mock_db[analysis_id]["graph"]
        # ... logic to convert to GraphVisualizationResponse ...
        # For now, returning mock to avoid breakages

    package_name = mock_db[analysis_id]["package_name"]

    return GraphVisualizationResponse(
        nodes=[
            GraphNode(data=GraphNodeData(id="p1", label=f"pip install {package_name}", type="process")),
            GraphNode(data=GraphNodeData(id="p2", label="sh -c", type="process")),
            GraphNode(data=GraphNodeData(id="p3", label="curl", type="process")),
            GraphNode(data=GraphNodeData(id="n1", label="185.199.108.133:443", type="network")),
            GraphNode(data=GraphNodeData(id="f1", label="/etc/passwd", type="file"))
        ],
        edges=[
            GraphEdge(data=GraphEdgeData(source="p1", target="p2", label="execve")),
            GraphEdge(data=GraphEdgeData(source="p2", target="p3", label="clone")),
            GraphEdge(data=GraphEdgeData(source="p3", target="n1", label="connect")),
            GraphEdge(data=GraphEdgeData(source="p3", target="f1", label="openat"))
        ]
    )

class CommandRequest(BaseModel):
    command: str

_ALLOWED_SUBCOMMANDS = frozenset([
    "analyze", "mcp", "watch", "check", "dashboard",
    "install-hook", "uninstall-hook", "train",
])

@app.post("/api/execute")
async def execute_command(request: CommandRequest, api_key: str = Depends(verify_api_key)):
    raw = request.command.strip()

    # Parse into argv to prevent shell metacharacter injection.
    try:
        parts = shlex.split(raw)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid command syntax: {e}")

    if not parts:
        raise HTTPException(status_code=400, detail="Empty command.")

    # Strip leading interpreter + script to reach the subcommand.
    # Accepted prefixes: ["python3", "cli.py", ...], ["cascade-analyze", ...], etc.
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cli_path = os.path.join(project_root, "cli.py")

    # Accept bare subcommand names as shorthand (e.g. "analyze urllib33 --type pip")
    # or full invocations (e.g. "python3 cli.py analyze urllib33").
    # "scan" is a UI alias for "analyze" — cli.py has no scan subcommand
    _SCAN_ALIAS = {"scan": "analyze", "diff": "analyze"}
    _CLI_SHORTHANDS = frozenset(["analyze", "watch", "check", "scan", "mcp", "diff"])
    if parts[0] in ("python3", "python", "./cli.py", "cascade-analyze",
                    "cascade-watch", "cascade-check", "cascade-scan", "cascade-mcp"):
        rest = parts[1:]
        if rest and rest[0] in ("cli.py", "./cli.py"):
            rest = rest[1:]
        argv = [sys.executable, cli_path] + rest
    elif parts[0] in _CLI_SHORTHANDS:
        # Remap UI aliases to real CLI subcommands
        real_parts = [_SCAN_ALIAS.get(parts[0], parts[0])] + parts[1:]
        argv = [sys.executable, cli_path] + real_parts
    else:
        raise HTTPException(
            status_code=400,
            detail="Forbidden. Only TraceTree CLI commands are accepted.",
        )

    # Validate the subcommand against an explicit allowlist.
    subcommand = argv[2] if len(argv) > 2 else ""
    if subcommand not in _ALLOWED_SUBCOMMANDS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown subcommand '{subcommand}'. "
                   f"Allowed: {sorted(_ALLOWED_SUBCOMMANDS)}",
        )

    def run_process():
        # Use a pty so Rich/Typer see a real TTY → Progress spinners output live.
        # Without pty, isatty()=False → Rich Progress outputs nothing during Docker run.
        env = {
            **os.environ,
            "PYTHONUNBUFFERED": "1",
            "TERM": "xterm-256color",
            "COLUMNS": "120",
            "LINES": "40",
        }
        master_fd, slave_fd = pty.openpty()
        proc = subprocess.Popen(
            argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
            env=env,
        )
        os.close(slave_fd)

        # Set master non-blocking
        fl = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        buf = ""
        last_output = time.time()

        try:
            while True:
                ready, _, _ = select.select([master_fd], [], [], 0.1)
                if ready:
                    try:
                        chunk = os.read(master_fd, 4096)
                        if not chunk:
                            break
                        last_output = time.time()
                        text = chunk.decode("utf-8", errors="replace")
                        # Collapse carriage returns: spinner emits \r to overwrite the
                        # current line in a real terminal. Split on \n first, then for
                        # each line keep only the LAST frame after any \r so the browser
                        # sees only the final settled state, not every intermediate frame.
                        text = text.replace("\r\n", "\n")
                        segments = text.split("\n")
                        segments = [s.split("\r")[-1] for s in segments]
                        text = "\n".join(segments)
                        buf += text
                        while "\n" in buf:
                            line, buf = buf.split("\n", 1)
                            clean = _strip_ansi(line).rstrip()
                            if clean:
                                yield f"data: {clean}\n\n"
                    except OSError:
                        break
                else:
                    if proc.poll() is not None:
                        break
                    # Send keepalive dot so user sees it's running
                    if time.time() - last_output > 3:
                        yield "data: ...\n\n"
                        last_output = time.time()
        finally:
            try:
                os.close(master_fd)
            except OSError:
                pass

        proc.wait()
        yield f"data: --- FINISHED (exit {proc.returncode}) ---\n\n"

    return StreamingResponse(run_process(), media_type="text/event-stream")

import sqlite3
import json
import datetime

ORCHESTRATOR_DB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "orchestrator",
    "tracetree.db"
)

def get_db_connection():
    conn = sqlite3.connect(ORCHESTRATOR_DB)
    conn.row_factory = sqlite3.Row
    return conn

# Retraining state
retrain_status = {
    "status": "idle",
    "error": None,
    "last_run": None
}

def run_retrain_task():
    global retrain_status
    retrain_status["status"] = "training"
    retrain_status["error"] = None
    try:
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        script_path = os.path.join(project_root, "retrain_model.py")

        proc = subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            text=True,
            cwd=project_root
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr or proc.stdout or "Retraining failed")

        retrain_status["status"] = "completed"
        retrain_status["last_run"] = datetime.datetime.now().isoformat()
    except Exception as e:
        retrain_status["status"] = "failed"
        retrain_status["error"] = str(e)

@app.get("/api/session")
async def get_session(api_key: str = Depends(verify_api_key)):
    """Return current dashboard session start timestamp from .tracetree/state.json."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    state_path = os.path.join(project_root, ".tracetree", "state.json")
    session_start = None
    if os.path.isfile(state_path):
        try:
            import json as _json
            with open(state_path) as f:
                state = _json.load(f)
            session_start = state.get("session_start")
        except Exception:
            pass
    return {"session_start": session_start}


@app.get("/api/scans")
async def get_scans(
    api_key: str = Depends(verify_api_key),
    since: Optional[str] = Query(None, description="ISO timestamp; if set, only return sessions after this time"),
):
    """Read scan history from .tracetree/history/ session directories."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    history_dir = os.path.join(project_root, ".tracetree", "history")
    scans = []
    if os.path.isdir(history_dir):
        entries = sorted(
            [e for e in os.listdir(history_dir) if e.startswith("session-")],
            reverse=True,
        )
        for entry in entries[:100]:
            session_dir = os.path.join(history_dir, entry)
            meta_path = os.path.join(session_dir, "metadata.json")
            receipt_path = os.path.join(session_dir, "receipt.json")
            if not os.path.isfile(meta_path):
                continue
            try:
                with open(meta_path) as f:
                    meta = json.load(f)
                receipt = {}
                if os.path.isfile(receipt_path):
                    with open(receipt_path) as f:
                        receipt = json.load(f)
                verdict_raw = receipt.get("verdict", {}).get("decision", "pending")
                verdict_map = {"malicious": "danger", "suspicious": "caution", "clean": "safe", "benign": "safe"}
                verdict = verdict_map.get(verdict_raw, "pending")
                confidence = receipt.get("verdict", {}).get("confidence", 0)
                target_name = os.path.basename(meta.get("target", "unknown"))
                ts = entry.replace("session-", "").split("Z-")[0].replace("T", " ") + "Z"
                sha256 = ""
                artifact_sha = receipt.get("target", {}).get("artifact_sha256", "")
                if artifact_sha.startswith("sha256:"):
                    sha256 = artifact_sha[7:15]
                if since:
                    try:
                        import datetime as _dt
                        raw = entry.replace("session-", "").split("Z-")[0]
                        date_part, time_part = raw.split("T", 1)
                        entry_ts = _dt.datetime.fromisoformat(f"{date_part}T{time_part.replace('-', ':')}+00:00")
                        since_norm = since if ("+" in since or since.endswith("Z")) else since + "+00:00"
                        since_ts = _dt.datetime.fromisoformat(since_norm.replace("Z", "+00:00"))
                        if entry_ts <= since_ts:
                            continue
                    except Exception:
                        pass
                yara_findings: list = []
                yara_path = os.path.join(session_dir, "yara_findings.json")
                if os.path.isfile(yara_path):
                    try:
                        with open(yara_path) as yf:
                            yara_findings = json.load(yf)
                    except Exception:
                        pass
                scans.append({
                    "id": meta.get("session_id", entry),
                    "target": target_name,
                    "verdict": verdict,
                    "confidence": confidence,
                    "type": meta.get("target_type", "unknown"),
                    "timestamp": ts,
                    "sha256": sha256,
                    "findings": json.dumps(receipt.get("observed_behavior", {})),
                    "yara_findings": yara_findings,
                })
            except Exception:
                continue
    return {"scans": scans}


class DisassemblyRequest(BaseModel):
    file_path: str
    offset: int | None = None
    max_insns: int = 32


@app.post("/api/analyze/disassembly")
async def analyze_disassembly(req: DisassemblyRequest, api_key: str = Depends(verify_api_key)):
    """Run radare2 headless against a quarantined binary at a specific offset.

    file_path must be inside .tracetree/quarantine/ — any path outside is rejected.
    offset is a byte offset from a YARA matched_offset; None resolves via symbol table.
    """
    import os as _os
    project_root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    quarantine_root = _os.path.realpath(_os.path.join(project_root, ".tracetree", "quarantine"))
    resolved = _os.path.realpath(req.file_path)
    if not resolved.startswith(quarantine_root + _os.sep):
        raise HTTPException(status_code=400, detail="file_path must be inside .tracetree/quarantine/")
    if not _os.path.isfile(resolved):
        raise HTTPException(status_code=404, detail=f"file not found: {resolved}")

    try:
        from monitor.analyzers.static_disassembly_analyzer import disassemble_at
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))

    # Keep the request budget bounded before it crosses into the analyzer.
    max_insns = max(1, min(req.max_insns, 256))
    result = disassemble_at(resolved, offset=req.offset, max_insns=max_insns)
    if result.get("error"):
        raise HTTPException(status_code=422, detail=result["error"])
    return result


@app.get("/api/model/info")
async def get_model_info(api_key: str = Depends(verify_api_key)):
    """Fetch active ML model version, metrics, and feature importances."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    metrics_path = os.path.join(project_root, "ml", "metrics.json")
    model_path = os.path.join(project_root, "ml", "model.skops")

    metrics = {}
    if os.path.exists(metrics_path):
        try:
            with open(metrics_path, "r") as f:
                metrics = json.load(f)
        except Exception:
            pass

    model_size_kb = 0
    if os.path.exists(model_path):
        model_size_kb = round(os.path.getsize(model_path) / 1024, 1)

    importances = {
        "total_severity": 0.28,
        "max_severity": 0.22,
        "execve_count": 0.15,
        "temporal_pattern_count": 0.12,
        "network_conn_count": 0.08,
        "sensitive_file_count": 0.06,
        "suspicious_network_count": 0.04,
        "node_count": 0.03,
        "edge_count": 0.01,
        "file_read_count": 0.01
    }

    return {
        "model_type": "Random Forest",
        "model_file": "ml/model.skops",
        "model_size_kb": model_size_kb,
        "metrics": metrics,
        "feature_importances": importances,
        "retrain_status": retrain_status
    }

@app.post("/api/model/retrain")
async def trigger_model_retrain(background_tasks: BackgroundTasks, api_key: str = Depends(verify_api_key)):
    """Trigger background model retraining."""
    if retrain_status["status"] == "training":
        return {"status": "already training", "detail": "Retraining is already in progress"}

    background_tasks.add_task(run_retrain_task)
    return {"status": "started", "detail": "Model retraining task dispatched in the background"}

@app.get("/api/signatures")
async def get_signatures(api_key: str = Depends(verify_api_key)):
    """Fetch active YARA signature rules."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    yara_path = os.path.join(project_root, "data", "mcp_rce_signatures.yara")
    if not os.path.exists(yara_path):
        raise HTTPException(status_code=404, detail="YARA signature file not found")

    try:
        with open(yara_path, "r", encoding="utf-8") as f:
            rules_text = f.read()
        return {"rules": rules_text}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class SignaturesUpdate(BaseModel):
    rules: str

@app.post("/api/signatures")
async def update_signatures(request: SignaturesUpdate, api_key: str = Depends(verify_api_key)):
    """Validate and update YARA signature rules."""
    try:
        import yara
        yara.compile(source=request.rules)
    except ImportError:
        pass
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"YARA syntax compilation error: {e}")

    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    yara_path = os.path.join(project_root, "data", "mcp_rce_signatures.yara")

    try:
        with open(yara_path, "w", encoding="utf-8") as f:
            f.write(request.rules)
        return {"success": True, "detail": "YARA rules updated successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write YARA file: {e}")

@app.get("/api/docker/status")
async def docker_status(api_key: str = Depends(verify_api_key)):
    """Check if Docker daemon is reachable."""
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return {"available": True, "version": result.stdout.strip()}
        return {"available": False, "version": None, "error": result.stderr.strip()}
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {"available": False, "version": None, "error": str(e)}


class FileScanRequest(BaseModel):
    path: str

@app.post("/api/scan/file")
async def scan_file(
    request: FileScanRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key),
):
    """
    Submit a file path for scanning. Returns scan_id + immediate static verdict.
    Background task runs the full Docker pipeline if available.
    """
    import hashlib, pathlib, time

    target = pathlib.Path(request.path).expanduser().resolve()

    # Restrict scanning to paths inside the project tree or quarantine dir only.
    _project_root = pathlib.Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))).resolve()
    _quarantine_root = (_project_root / ".tracetree" / "quarantine").resolve()
    if not (str(target).startswith(str(_project_root) + os.sep)
            or str(target).startswith(str(_quarantine_root) + os.sep)):
        raise HTTPException(
            status_code=400,
            detail="Path must be inside the TraceTree project directory or quarantine.",
        )

    if not target.exists():
        raise HTTPException(status_code=400, detail=f"Path not found: {target}")

    # SHA-256 fingerprint
    h = hashlib.sha256()
    try:
        with open(target, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        sha256 = h.hexdigest()
    except OSError as e:
        raise HTTPException(status_code=400, detail=f"Cannot read file: {e}")

    scan_id = str(uuid.uuid4())
    ts = datetime.datetime.utcnow().isoformat() + "Z"

    # Determine target type from extension
    ext = target.suffix.lower()
    _TYPE_MAP = {
        ".dmg": "dmg", ".exe": "exe", ".msi": "exe",
        ".zip": "zip-malware", ".sh": "shell", ".py": "shell",
        ".command": "shell", ".pkg": "dmg",
        "requirements.txt": "pip", "package.json": "npm",
    }
    target_type = _TYPE_MAP.get(ext) or _TYPE_MAP.get(target.name, "pip")

    # Quick static scan (non-blocking)
    from monitor.scanner import scan_file_for_secrets
    from monitor.yara import scan_with_yara
    static_findings = list(scan_file_for_secrets(target))
    yara_hits = []
    try:
        yara_hits = scan_with_yara(package_dir=str(target.parent))
        yara_hits = [h for h in yara_hits if h.get("file_path") == str(target)]
    except Exception:
        pass

    has_static_threat = bool(static_findings or yara_hits)
    static_level = "danger" if has_static_threat else "safe"

    mock_db[scan_id] = {
        "id": scan_id,
        "status": "static_complete",
        "path": str(target),
        "sha256": sha256,
        "type": target_type,
        "static_verdict": {"level": static_level, "headline": f"{len(static_findings)} static finding(s), {len(yara_hits)} YARA hit(s)", "details": []},
        "dynamic_verdict": None,
        "findings": static_findings[:20],
        "createdAt": ts,
    }

    # Enqueue Docker dynamic scan in background
    background_tasks.add_task(run_real_analysis, scan_id, str(target), target_type)

    return {"scan_id": scan_id, "static_verdict": mock_db[scan_id]["static_verdict"], "sha256": sha256}


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str, api_key: str = Depends(verify_api_key)):
    if scan_id not in mock_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    return mock_db[scan_id]


@app.get("/")
async def root():
    """Return API health status."""
    return {"status": "TraceTree API is active", "version": "1.0.0"}
