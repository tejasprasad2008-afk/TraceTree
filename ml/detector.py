import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from typing import Dict, Any, List, Optional, Tuple

from rich.console import Console

console = Console()

import hashlib
import json
from ml.models.versioning import ModelVersionManager
from zipfile import ZipFile
import skops.io as sio

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

def safe_load_model(filepath: Path):
    """
    Safely load a model file using skops.io.
    Inspects type information in the schema first and rejects any forbidden types.
    """
    
    # 1. First run skops untrusted types check
    try:
        untrusted = sio.get_untrusted_types(file=filepath)
    except Exception as e:
        raise ValueError(f"Invalid model file format or structural check failed: {e}")
        
    if untrusted:
        raise ValueError(f"Security error: Untrusted types found in model file: {untrusted}")
        
    # 2. Strict allowlist verification of all module and class names
    allowed_modules = {
        "builtins",
        "numpy",
        "numpy.core.multiarray",
        "sklearn.ensemble._forest",
        "sklearn.ensemble._iforest",
        "sklearn.tree._classes",
        "sklearn.tree._tree",
        "sklearn.ensemble",
        "sklearn.tree",
    }
    allowed_classes = {
        "dict", "list", "str", "tuple", "float", "int", "bool",
        "ndarray", "dtype", "int64", "float64", "int32", "float32",
        "RandomForestClassifier", "IsolationForest",
        "DecisionTreeClassifier", "ExtraTreeRegressor", "Tree",
    }
    
    try:
        with ZipFile(filepath, "r") as zip_file:
            schema = json.loads(zip_file.read("schema.json"))
    except Exception as e:
        raise ValueError(f"Could not read model schema: {e}")
        
    def walk(node):
        if isinstance(node, dict):
            if "__class__" in node:
                module = node.get("__module__", "")
                name = node.get("__class__", "")
                if module and module not in allowed_modules:
                    raise ValueError(f"Security error: Forbidden module {module} in model file")
                if name and name not in allowed_classes:
                    raise ValueError(f"Security error: Forbidden class {name} in model file")
            for val in node.values():
                walk(val)
        elif isinstance(node, list):
            for item in node:
                walk(item)
                
    walk(schema)
    
    # Standard skops load
    return sio.load(filepath)


def get_ml_model(version: str = None):
    """
    Lazily loads the Supervised RandomForest if available locally.
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
        manager = ModelVersionManager()
        version_path = manager.get_version(version)
        if version_path and version_path.exists():
            if version_path.suffix == ".pkl":
                console.print(f"[bold yellow]Warning: Legacy model file {version_path.name} cannot be loaded safely. Please retrain to produce a .skops file.[/]")
            else:
                try:
                    _MODEL_CACHE = safe_load_model(version_path)
                    console.print(f"[dim]Loaded model version {version}[/]")
                    return _MODEL_CACHE
                except Exception as e:
                    console.print(f"[bold yellow]Failed to load version {version}: {e}[/]")
    
    # Check if a legacy model.pkl exists
    legacy_model_path = Path(__file__).parent / "model.pkl"
    if legacy_model_path.exists() and legacy_model_path.stat().st_size > 0:
        console.print("[bold yellow]Warning: Legacy model.pkl exists but cannot be loaded safely. Please retrain the model with `cascade-train` to produce model.skops.[/]")

    model_path = Path(__file__).parent / "model.skops"

    try:
        if not model_path.exists() or model_path.stat().st_size == 0:
            _MODEL_CACHE = _auto_train_or_baseline(model_path)
            return _MODEL_CACHE
        _MODEL_CACHE = safe_load_model(model_path)
        return _MODEL_CACHE
    except Exception as e:
        console.print(f"[bold red]Local model load failed:[/] {e}")
        _MODEL_CACHE = _auto_train_or_baseline(model_path)
        return _MODEL_CACHE


def _auto_train_or_baseline(model_path: Path):
    """
    Try to train RandomForest from the local feature CSV before giving up
    and falling back to IsolationForest.
    """
    csv_path = model_path.parent.parent / "data" / "ingested_training_data.csv"
    if csv_path.exists() and csv_path.stat().st_size > 0:
        console.print("[dim]Auto-training RandomForest from local feature CSV...[/]")
        try:
            from ml.trainer import train_model
            train_model()
            if model_path.exists() and model_path.stat().st_size > 0:
                model = safe_load_model(model_path)
                console.print("[bold green]✔ Auto-trained RandomForest model ready.[/]")
                return model
        except Exception as e:
            console.print(f"[bold yellow]⚠ Auto-train failed:[/] {e}")

    console.print("[dim italic]Falling back to IsolationForest zero-shot detection.[/]")
    return train_baseline_model()


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


class AnomalyVerdict(tuple):
    """
    Custom return type for detect_anomaly.
    Acts as a 2-tuple (is_malicious, risk_score) for backward compatibility,
    but exposes additional fields for detailed reports.
    """
    def __new__(cls, is_malicious: bool, risk_score: float, ml_probability: Optional[float], reasons: List[str]):
        return super().__new__(cls, (is_malicious, risk_score))

    def __init__(self, is_malicious: bool, risk_score: float, ml_probability: Optional[float], reasons: List[str]):
        self.is_malicious = is_malicious
        self.risk_score = risk_score
        self.ml_probability = ml_probability
        self.reasons = reasons


def _severity_adjusted_confidence(
    is_malicious: bool,
    ml_confidence: float,
    total_severity: float,
    sensitive_file_count: int,
    suspicious_network_count: int,
    temporal_pattern_count: int = 0,
) -> Tuple[bool, float, List[str]]:
    """
    Adjust the ML model's verdict using syscall severity, signature, and temporal evidence.

    Scoring Rules:
      1. Base score is the initial ML confidence/probability (0-100).
      2. If total_severity >= 30.0 (Critical): Override to malicious (is_malicious = True),
         and sets the risk score to min(99.0, max(confidence, 90.0) + 5.0).
      3. If total_severity >= 15.0 (High): Boosts risk score by +30.0. Flips verdict to
         malicious if the adjusted score exceeds 60.0.
      4. If total_severity >= 5.0 (Medium): Boosts risk score by +10.0.
      5. Each matched temporal pattern adds +15.0 to the risk score. If there are 2 or
         more temporal patterns, the verdict is overridden to malicious.
      6. Each sensitive file access adds +5.0 to the risk score.
      7. Each suspicious network connection adds +5.0 to the risk score.
      8. The final risk score is capped at 99.9.

    Returns:
        (is_malicious_adjusted, risk_score, reasons)
    """
    confidence = ml_confidence
    reasons = []

    # Critical severity override
    if total_severity >= _SEVERITY_BOOST_THRESHOLDS["critical"]:
        new_conf = min(99.0, max(confidence, 90.0) + 5.0)
        reasons.append(f"Critical syscall severity override (total severity {total_severity:.1f} >= 30.0)")
        return True, new_conf, reasons

    # High severity boost
    if total_severity >= _SEVERITY_BOOST_THRESHOLDS["high"]:
        confidence = min(99.0, confidence + 30.0)
        reasons.append(f"High syscall severity boost (+30.0 risk, total severity {total_severity:.1f} >= 15.0)")
        if confidence > 60.0 and not is_malicious:
            is_malicious = True
            reasons.append("Verdict flipped to malicious due to high syscall severity and supporting evidence")

    # Medium severity boost
    elif total_severity >= _SEVERITY_BOOST_THRESHOLDS["medium"]:
        confidence = min(99.0, confidence + 10.0)
        reasons.append(f"Medium syscall severity boost (+10.0 risk, total severity {total_severity:.1f} >= 5.0)")

    # Temporal patterns are strong signals — each adds +15%
    if temporal_pattern_count > 0:
        confidence += temporal_pattern_count * 15.0
        reasons.append(f"Temporal patterns matched: {temporal_pattern_count} (+{temporal_pattern_count * 15.0} risk)")
        if temporal_pattern_count >= 2 and not is_malicious:
            is_malicious = True
            reasons.append("Verdict flipped to malicious due to multiple suspicious temporal patterns")

    # Individual evidence items
    if sensitive_file_count > 0:
        confidence += sensitive_file_count * 5.0
        reasons.append(f"Sensitive file accesses: {sensitive_file_count} (+{sensitive_file_count * 5.0} risk)")
    if suspicious_network_count > 0:
        confidence += suspicious_network_count * 5.0
        reasons.append(f"Suspicious network connections: {suspicious_network_count} (+{suspicious_network_count * 5.0} risk)")

    # Cap
    confidence = min(99.9, confidence)

    return is_malicious, round(confidence, 1), reasons


def detect_anomaly(
    graph_data: Dict[str, Any], parsed_data: Dict[str, Any]
) -> AnomalyVerdict:
    """
    Detect whether the analyzed package exhibits malicious behavior.

    Combines the ML model's prediction with syscall severity scoring.

    Returns:
        AnomalyVerdict containing:
          - is_malicious (bool)
          - risk_score (float, 0-100)
          - ml_probability (float, 0-100 or None)
          - reasons (List[str])
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
        ml_probability = float(proba[1] * 100)
        ml_confidence = max(proba) * 100
    else:
        # IsolationForest fallback — may need full vector
        X_iso = np.array([target_features])
        if X_iso.shape[1] != model.n_features_in_:
            X_iso = np.array([target_features[:model.n_features_in_]])
        prediction = model.predict(X_iso)[0]
        is_malicious = bool(prediction == -1)
        raw_score = model.decision_function(X_iso)[0]
        ml_probability = None
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

    is_malicious, risk_score, reasons = _severity_adjusted_confidence(
        is_malicious,
        ml_confidence,
        total_severity,
        sensitive_files,
        suspicious_nets,
        temporal_patterns,
    )

    result = AnomalyVerdict(is_malicious, risk_score, ml_probability, reasons)
    _PREDICTION_CACHE[feature_hash] = result
    
    return result
