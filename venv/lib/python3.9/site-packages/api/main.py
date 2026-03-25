from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import uuid
import os

app = FastAPI(
    title="Cascading Behavioral Propagation Analyzer",
    description="API for analyzing suspicious Python packages by monitoring runtime behavioral cascades.",
    version="1.0.0"
)

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory mock database for tracking analysis jobs
mock_db: Dict[str, Dict[str, Any]] = {
    "demo-id": {
        "id": "demo-id",
        "status": "completed",
        "package_name": "requests-async-v2",
        "verdict": "MALICIOUS",
        "confidence_score": 0.98
    }
}

class AnalysisRequest(BaseModel):
    package_name: str
    pypi_url: Optional[str] = None

class AnalysisResult(BaseModel):
    id: str
    status: str
    package_name: str
    verdict: Optional[str] = None
    confidence_score: Optional[float] = None

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

def mock_analysis_task(analysis_id: str, package_name: str):
    """
    Mock background task that simulates the full pipeline:
    1. Docker Sandbox Execution
    2. Strace Monitoring
    3. NetworkX Graph Building
    4. ML Anomaly Detection (scikit-learn)
    """
    pass

@app.post("/analyze", response_model=AnalysisResult)
async def submit_analysis(request: AnalysisRequest, background_tasks: BackgroundTasks):
    analysis_id = str(uuid.uuid4())
    mock_db[analysis_id] = {
        "id": analysis_id,
        "status": "pending",
        "package_name": request.package_name,
        "verdict": None,
        "confidence_score": None
    }
    background_tasks.add_task(mock_analysis_task, analysis_id, request.package_name)
    return mock_db[analysis_id]

@app.get("/results/{analysis_id}", response_model=AnalysisResult)
async def get_results(analysis_id: str):
    if analysis_id not in mock_db:
        raise HTTPException(status_code=404, detail="Analysis ID not found")
    return mock_db[analysis_id]

@app.get("/graph/{analysis_id}", response_model=GraphVisualizationResponse)
async def get_graph(analysis_id: str):
    if analysis_id not in mock_db:
        raise HTTPException(status_code=404, detail="Analysis ID not found")
        
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
    """Redirect root access to the dashboard."""
    return RedirectResponse(url="/app/")

# Mount the frontend directory to serve static UI files under /app path
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(frontend_path):
    app.mount("/app", StaticFiles(directory=frontend_path, html=True), name="frontend")
