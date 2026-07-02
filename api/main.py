from fastapi import FastAPI, BackgroundTasks, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import uuid
import os
import shlex
import subprocess
import sys

# --- Security ---
# Load API keys from environment variable for production
_api_keys_str = os.getenv("TRACETREE_API_KEYS")
if not _api_keys_str:
    # In a real production environment, we should never fall back to hardcoded keys.
    # We raise an error here to prevent the API from starting in an unauthenticated or misconfigured state.
    raise RuntimeError("TRACETREE_API_KEYS environment variable is not set.")

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
cors_origins_str = os.getenv("TRACETREE_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
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
    from sandbox.sandbox import run_sandbox
    from monitor.parser import parse_strace_log
    from graph.builder import build_cascade_graph
    from ml.detector import detect_anomaly
    
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
    "analyze", "scan", "mcp", "diff", "scan-guardian", "install-hook",
    "uninstall-hook", "train", "check", "dashboard",
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

    if parts[0] in ("python3", "python", "./cli.py", "cascade-analyze"):
        # Normalise to [sys.executable, cli_path, subcommand, ...]
        rest = parts[1:]
        if rest and rest[0] in ("cli.py", "./cli.py"):
            rest = rest[1:]
        argv = [sys.executable, cli_path] + rest
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
        env = {**os.environ, "PYTHONUNBUFFERED": "1"}
        proc = subprocess.Popen(
            argv,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
        )

        for line in iter(proc.stdout.readline, ""):
            yield f"data: {line}\n\n"

        proc.stdout.close()
        proc.wait()
        yield f"data: \n--- PROCESS FINISHED WITH CODE {proc.returncode} ---\n\n"

    return StreamingResponse(run_process(), media_type="text/event-stream")

@app.get("/")
async def root():
    """Return API health status."""
    return {"status": "TraceTree API is active", "version": "1.0.0"}
