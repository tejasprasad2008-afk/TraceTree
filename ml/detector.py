import pickle
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from typing import Dict, Any, Tuple

from rich.console import Console

console = Console()

import hashlib
import json

# Global model cache to avoid repeated disk I/O and unpickling
_MODEL_CACHE = None
_PREDICTION_CACHE = {}


def clear_model_cache():
    """Invalidates the in-memory model and prediction caches."""
    global _MODEL_CACHE, _PREDICTION_CACHE
    _MODEL_CACHE = None
    _PREDICTION_CACHE = {}


# --------------------------------------------------------------------------- #
#  Feature extraction
#  Maps graph stats + parsed events into a numeric vector for the ML model.
#  Updated to include severity-weighted features and destination intelligence.
# --------------------------------------------------------------------------- #

def map_features(graph_data: Dict[str, Any], parsed_data: Dict[str, Any]) -> list:
    """
    Extract a numeric feature vector from the graph and parsed data.

    Features (in order):
      0. node_count              — total nodes in the execution graph
      1. edge_count              — total edges
      2. network_conn_count       — number of distinct network nodes
      3. file_read_count          — number of distinct file nodes
      4. execve_count             — number of execve syscalls
      5. total_severity           — sum of all edge severity weights
      6. suspicious_network_count — connections to suspicious destinations
      7. sensitive_file_count     — accesses to sensitive files (/etc/shadow, etc.)
      8. max_severity             — highest single-edge severity
      9. temporal_pattern_count   — number of detected temporal patterns (0 if no timestamps)
    """
    stats = graph_data.get("stats", {})
    # Temporal patterns may be in either graph stats or parsed data stats
    # (cli.py injects them into parsed_data["stats"])
    temporal_count = stats.get("temporal_pattern_count", 0)
    parsed_stats = parsed_data.get("stats", {})
    if temporal_count == 0 and "temporal_pattern_count" in parsed_stats:
        temporal_count = parsed_stats["temporal_pattern_count"]

    execve_count = sum(
        1 for evt in parsed_data.get("events", []) if evt.get("type") == "execve"
    )

    return [
        stats.get("node_count", 0),
        stats.get("edge_count", 0),
        stats.get("network_conn_count", 0),
        stats.get("file_read_count", 0),
        execve_count,
        stats.get("total_severity", 0.0),
        stats.get("suspicious_network_count", 0),
        stats.get("sensitive_file_count", 0),
        stats.get("max_severity", 0.0),
        temporal_count,
    ]


# --------------------------------------------------------------------------- #
#  Baseline model (IsolationForest fallback)
#  Updated baselines reflect the expanded 9-feature vector.
#  These represent normal pip install profiles measured empirically.
# --------------------------------------------------------------------------- #

CLEAN_BASELINES = [
    # node_count, edge_count, net_conn, file_reads, execve, total_sev, susp_net, sens_file, max_sev, temporal_patterns
    [12,  10, 0, 35, 1, 1.5,  0, 0, 1.0, 0],   # simple pure-python package
    [25,  22, 0, 80, 2, 3.0,  0, 0, 2.0, 0],   # package with native extension build
    [18,  15, 0, 55, 2, 2.0,  0, 0, 1.5, 0],   # medium-sized pure-python
    [40,  38, 0, 150, 3, 5.0, 0, 0, 2.5, 0],   # heavy package (e.g. numpy with build)
    [10,  8,  0, 25, 1, 0.5,  0, 0, 0.5, 0],   # tiny no-dependency package
    [30,  28, 0, 100, 3, 4.0, 0, 0, 2.0, 0],   # large pure-python (e.g. requests)
    [15,  13, 0, 45, 2, 1.5,  0, 0, 1.0, 0],   # medium package
    [8,   6,  0, 18, 1, 0.5,  0, 0, 0.5, 0],   # minimal utility
    [20,  18, 0, 65, 2, 2.5,  0, 0, 1.5, 0],   # medium-large pure-python
    [35,  32, 0, 120, 3, 4.5, 0, 0, 2.0, 0],   # large package with scripts
]


def train_baseline_model() -> IsolationForest:
    """Train an IsolationForest on the clean baselines (zero-shot fallback)."""
    model = IsolationForest(
        n_estimators=100,
        contamination=0.01,
        random_state=42,
    )
    X = np.array(CLEAN_BASELINES)
    model.fit(X)
    return model


# --------------------------------------------------------------------------- #
#  Model loading
# --------------------------------------------------------------------------- #

def get_ml_model(version: str = None):
    """
    Lazily loads the Supervised RandomForest if available locally or from GCS.
    Falls back to an IsolationForest trained on hardcoded clean baselines.
    
    Args:
        version: Optional version string (e.g., "v1.0", "v2.0-rc1").
                 If None, uses the latest/default version.
    """
    global _MODEL_CACHE
    if _MODEL_CACHE is not None:
        return _MODEL_CACHE

    # Try versioning system first
    if version:
        from ml.models.versioning import ModelVersionManager
        manager = ModelVersionManager()
        version_path = manager.get_version(version)
        if version_path and version_path.exists():
            try:
                with open(version_path, "rb") as f:
                    _MODEL_CACHE = pickle.load(f)
                    console.print(f"[dim]Loaded model version {version}[/]")
                    return _MODEL_CACHE
            except Exception as e:
                console.print(f"[bold yellow]Failed to load version {version}: {e}[/]")
    
    # Fall back to legacy path or GCS
    model_path = Path(__file__).parent / "model.pkl"

    if not model_path.exists():
        console.print(
            "[dim]Local model.pkl not found. Attempting anonymous GCS fetch "
            "from 'cascade-analyzer-models'...[/]"
        )
        try:
            import urllib.request
            url = "https://storage.googleapis.com/cascade-analyzer-models/model.pkl"
            model_path.parent.mkdir(exist_ok=True)
            urllib.request.urlretrieve(url, str(model_path))
            console.print("[bold green]✔ Synced model from GCS.[/]")
        except Exception as e:
            console.print(f"[bold yellow]⚠ GCS download skipped:[/] {e}")
            console.print(
                "[dim italic]Falling back to IsolationForest zero-shot detection.[/]"
            )
            _MODEL_CACHE = train_baseline_model()
            return _MODEL_CACHE

    try:
        if model_path.exists() and model_path.stat().st_size == 0:
            # 0-byte file is expected to trigger fallback cleanly
            _MODEL_CACHE = train_baseline_model()
            return _MODEL_CACHE
        with open(model_path, "rb") as f:
            _MODEL_CACHE = pickle.load(f)
            return _MODEL_CACHE
    except (EOFError, pickle.UnpicklingError):
        # Graceful fallback without alarming the user
        _MODEL_CACHE = train_baseline_model()
        return _MODEL_CACHE
    except Exception as e:
        console.print(f"[bold red]Local model load failed:[/] {e}")
        _MODEL_CACHE = train_baseline_model()
        return _MODEL_CACHE


def update_model_from_gcs():
    """Force-download the latest model from GCS, replacing the local cache."""
    model_path = Path(__file__).parent / "model.pkl"
    try:
        console.print("[cyan]Fetching latest model from GCS...[/]")
        import urllib.request
        url = "https://storage.googleapis.com/cascade-analyzer-models/model.pkl"
        model_path.parent.mkdir(exist_ok=True)
        urllib.request.urlretrieve(url, str(model_path))
        clear_model_cache()
        console.print("[bold green]✔ Model updated from GCS.[/]")
    except Exception as e:
        console.print(f"[bold red]GCS fetch failed:[/] {e}")


# --------------------------------------------------------------------------- #
#  Anomaly detection
#  Combines ML model prediction with syscall severity scoring.
# --------------------------------------------------------------------------- #

# Thresholds for the severity-boost system.
# If the raw severity score exceeds these, the anomaly confidence is boosted
# regardless of what the ML model says.
_SEVERITY_BOOST_THRESHOLDS = {
    "critical": 30.0,   # total_severity >= 30 → always flag as malicious
    "high": 15.0,       # total_severity >= 15 → boost confidence by +30%
    "medium": 5.0,      # total_severity >= 5 → boost confidence by +10%
}


def _severity_adjusted_confidence(
    is_malicious: bool,
    ml_confidence: float,
    total_severity: float,
    sensitive_file_count: int,
    suspicious_network_count: int,
    temporal_pattern_count: int = 0,
) -> Tuple[bool, float]:
    """
    Adjust the ML model's verdict using syscall severity and temporal evidence.

    The ML model's prediction is the primary signal.  Severity scoring and
    temporal pattern detection act as **boosters**, not replacements:
      - If total_severity >= critical threshold → override to malicious, conf ~95%
      - If total_severity >= high threshold → boost confidence by +30%
      - If total_severity >= medium threshold → boost confidence by +10%
      - Each temporal pattern adds +15% confidence (they are strong signals)
      - Individual sensitive file or suspicious network accesses add +5% each.

    Returns:
        (is_malicious_adjusted, confidence_adjusted)
    """
    confidence = ml_confidence

    # Critical severity override
    if total_severity >= _SEVERITY_BOOST_THRESHOLDS["critical"]:
        return True, min(99.0, max(confidence, 90.0) + 5.0)

    # High severity boost
    if total_severity >= _SEVERITY_BOOST_THRESHOLDS["high"]:
        confidence = min(99.0, confidence + 30.0)
        if confidence > 60.0 and not is_malicious:
            # ML said clean but evidence is strong — flip the verdict
            is_malicious = True

    # Medium severity boost
    elif total_severity >= _SEVERITY_BOOST_THRESHOLDS["medium"]:
        confidence = min(99.0, confidence + 10.0)

    # Temporal patterns are strong signals — each adds +15%
    confidence += temporal_pattern_count * 15.0
    if temporal_pattern_count >= 2 and not is_malicious:
        # Multiple temporal patterns → very suspicious, flip verdict
        is_malicious = True

    # Individual evidence items
    confidence += sensitive_file_count * 5.0
    confidence += suspicious_network_count * 5.0

    # Cap
    confidence = min(99.9, confidence)

    return is_malicious, round(confidence, 1)


def detect_anomaly(
    graph_data: Dict[str, Any], parsed_data: Dict[str, Any]
) -> Tuple[bool, float]:
    """
    Detect whether the analyzed package exhibits malicious behavior.

    Combines the ML model's prediction with syscall severity scoring
    for a boosted confidence score.

    Backward compatibility: if the loaded model was trained on fewer
    features (e.g. 5), only the first N features are passed to it.
    The extra features are used exclusively for the severity boost.

    Returns:
        (is_malicious, confidence) where confidence is 0.0-99.9%.
    """
    target_features = map_features(graph_data, parsed_data)

    # 2.9 MODEL CACHING - check if we have a cached prediction for these features
    feature_hash = hashlib.sha256(json.dumps(target_features).encode()).hexdigest()
    if feature_hash in _PREDICTION_CACHE:
        return _PREDICTION_CACHE[feature_hash]

    model = get_ml_model()

    # Determine how many features the model was trained on
    if isinstance(model, RandomForestClassifier):
        n_model_features = model.n_features_in_
    else:
        # IsolationForest — assume it matches our current vector
        n_model_features = len(target_features)

    # Truncate to what the model expects (backward compat with old 5-feature models)
    X_target = np.array([target_features[:n_model_features]])

    # --- ML model prediction ---
    if isinstance(model, RandomForestClassifier):
        prediction = model.predict(X_target)[0]
        is_malicious = bool(prediction == 1)
        proba = model.predict_proba(X_target)[0]
        ml_confidence = max(proba) * 100
    else:
        # IsolationForest fallback — may need full vector
        X_iso = np.array([target_features])
        if X_iso.shape[1] != model.n_features_in_:
            X_iso = np.array([target_features[:model.n_features_in_]])
        prediction = model.predict(X_iso)[0]
        is_malicious = bool(prediction == -1)
        raw_score = model.decision_function(X_iso)[0]
        if is_malicious:
            ml_confidence = min(99.9, max(50.0, 50.0 + abs(raw_score) * 200))
        else:
            ml_confidence = max(0.0, 50.0 - (raw_score * 200))

    # --- Severity + Temporal adjustment ---
    stats = graph_data.get("stats", {})
    total_severity = stats.get("total_severity", 0.0)
    sensitive_files = stats.get("sensitive_file_count", 0)
    suspicious_nets = stats.get("suspicious_network_count", 0)
    temporal_patterns = stats.get("temporal_pattern_count", 0)

    is_malicious, confidence = _severity_adjusted_confidence(
        is_malicious,
        ml_confidence,
        total_severity,
        sensitive_files,
        suspicious_nets,
        temporal_patterns,
    )

    result = (is_malicious, confidence)
    _PREDICTION_CACHE[feature_hash] = result
    
    return result
