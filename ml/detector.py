import os
import pickle
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from typing import Dict, Any, Tuple
from google.cloud import storage

from rich.console import Console

console = Console()

# Global model cache to avoid repeated disk I/O and unpickling
_MODEL_CACHE = None

def clear_model_cache():
    """Invalidates the in-memory model cache."""
    global _MODEL_CACHE
    _MODEL_CACHE = None

# Pre-trained baseline characteristics of completely benign normal pip installations
CLEAN_BASELINES = [
    [5, 4, 0, 15, 1],   [10, 9, 0, 30, 2],
    [8, 7, 0, 25, 2],   [15, 14, 0, 50, 3],
    [6, 5, 0, 20, 1],   [20, 19, 0, 80, 4],
    [12, 11, 0, 40, 2], [7, 6, 0, 22, 1],
    [9, 8, 0, 35, 2],   [14, 13, 0, 45, 3]
]

def map_features(graph_data: Dict[str, Any], parsed_data: Dict[str, Any]) -> list:
    stats = graph_data.get("stats", {})
    execve_count = sum(1 for evt in parsed_data.get("events", []) if evt["type"] == "execve")
    
    return [
        stats.get("node_count", 0),
        stats.get("edge_count", 0),
        stats.get("network_conn_count", 0),
        stats.get("file_read_count", 0),
        execve_count
    ]

def train_baseline_model() -> IsolationForest:
    model = IsolationForest(
        n_estimators=100, 
        contamination=0.01,
        random_state=42
    )
    X = np.array(CLEAN_BASELINES)
    model.fit(X)
    return model

def get_ml_model():
    """Lazily loads the Supervised Random Forest if available locally or in GCS."""
    global _MODEL_CACHE
    if _MODEL_CACHE is not None:
        return _MODEL_CACHE

    model_path = Path(__file__).parent / "model.pkl"
    
    if not model_path.exists():
        console.print("[dim]Local model.pkl not found. Hooking anonymous Google Cloud fetch from 'cascade-analyzer-models'...[/]")
        try:
            client = storage.Client.create_anonymous_client()
            bucket = client.bucket("cascade-analyzer-models")
            blob = bucket.blob("model.pkl")
            model_path.parent.mkdir(exist_ok=True)
            blob.download_to_filename(str(model_path))
            console.print("[bold green]✔ Automatically synced robust parameters from GCS model cache.[/]")
        except Exception as e:
            console.print(f"[bold yellow]⚠ Transparent GCS Download Skipped:[/] {e}")
            console.print("[dim italic]Routing detection cleanly backward onto internal explicit IsolationForest zero-shot mapping...[/]")
            _MODEL_CACHE = train_baseline_model()
            return _MODEL_CACHE
            
    try:
        with open(model_path, 'rb') as f:
            _MODEL_CACHE = pickle.load(f)
            return _MODEL_CACHE
    except Exception as e:
        console.print(f"[bold red]Failed cleanly evaluating local model.pkl structure:[/] {e}")
        _MODEL_CACHE = train_baseline_model()
        return _MODEL_CACHE

def update_model_from_gcs():
    """Forces direct synchronization replacing identically explicit local model cache structures globally."""
    model_path = Path(__file__).parent / "model.pkl"
    try:
        console.print("[cyan]Actively routing targeted requests updating explicit model.pkl natively from upstream GCS storage...[/]")
        client = storage.Client.create_anonymous_client()
        bucket = client.bucket("cascade-analyzer-models")
        blob = bucket.blob("model.pkl")
        model_path.parent.mkdir(exist_ok=True)
        blob.download_to_filename(str(model_path))
        clear_model_cache()
        console.print("[bold green]✔ Supervised RF Model identically synchronized actively from Google Cloud successfully.[/]")
    except Exception as e:
        console.print(f"[bold red]Aggressive GCS Fetch Failed:[/] {e}")

def detect_anomaly(graph_data: Dict[str, Any], parsed_data: Dict[str, Any]) -> Tuple[bool, float]:
    model = get_ml_model()
    target_features = map_features(graph_data, parsed_data)
    X_target = np.array([target_features])
    
    if isinstance(model, RandomForestClassifier):
        prediction = model.predict(X_target)[0]
        # RF model training uses 1 natively mapping strictly malicious parameters
        is_malicious = bool(prediction == 1)
        proba = model.predict_proba(X_target)[0]
        confidence = max(proba) * 100
        
    else:
        # Fallback Isolation Forest Model Mapping
        prediction = model.predict(X_target)[0]
        is_malicious = (prediction == -1)
        raw_score = model.decision_function(X_target)[0]
        if is_malicious:
            confidence = min(99.9, max(50.0, 50.0 + abs(raw_score) * 200))
        else:
            confidence = max(0.0, 50.0 - (raw_score * 200))
            
    return is_malicious, round(confidence, 1)
