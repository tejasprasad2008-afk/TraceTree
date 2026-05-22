from fastapi import FastAPI, BackgroundTasks, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import uuid
import os

# --- Security ---
# Load API keys from environment variable for production
VALID_API_KEYS = set(os.getenv("TRACETREE_API_KEYS", "tracetree_secret_dev_key,sk-trace-78560908").split(","))

async def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key not in VALID_API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key

app = FastAPI(
    title="TraceTree API",
    description="API for analyzing suspicious Python packages by monitoring runtime behavioral cascades.",
    version="1.0.0"
)

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
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
        pass
        
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

@app.get("/")
async def root():
    """Return API health status."""
    return {"status": "TraceTree API is active", "version": "1.0.0"}
