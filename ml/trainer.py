import csv
import os
import skops.io as sio
from pathlib import Path
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.console import Console
from sklearn.ensemble import RandomForestClassifier

_FEATURE_COLUMNS = [
    "node_count", "edge_count", "network_conn_count",
    "file_read_count", "execve_count", "total_severity",
    "suspicious_network_count", "sensitive_file_count", "max_severity",
    "temporal_pattern_count",
]

def load_dataset(filepath: str) -> list:
    if not Path(filepath).exists():
        return []
    with open(filepath, 'r') as f:
        return [line.strip() for line in f if line.strip()]


def _load_features_from_csv(csv_path: Path):
    """Load X, y from existing ingested_training_data.csv. Returns ([], []) if unusable."""
    if not csv_path.exists() or csv_path.stat().st_size == 0:
        return [], []
    X, y = [], []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        cols = reader.fieldnames or []
        if not all(c in cols for c in _FEATURE_COLUMNS) or "is_malicious" not in cols:
            return [], []
        for row in reader:
            try:
                features = [float(row.get(c, 0) or 0) for c in _FEATURE_COLUMNS]
                label = int(row.get("is_malicious", 0))
                X.append(features)
                y.append(label)
            except (ValueError, TypeError):
                continue
    return X, y


def train_model(skip_gcs: bool = False):
    console = Console()

    base_dir = Path(__file__).parent.parent
    csv_path = base_dir / "data" / "ingested_training_data.csv"

    # Use existing feature CSV to avoid re-running sandbox from scratch every call
    X, y = _load_features_from_csv(csv_path)
    if X:
        console.print(f"[cyan]Loaded {len(X)} samples from {csv_path.name}. Skipping sandbox re-run.[/]")
        from ml.detector import clear_model_cache  # noqa: F401
    else:
        # Fallback to labeled_fixtures.csv
        fixtures_path = base_dir / "data" / "labeled_fixtures.csv"
        X, y = _load_features_from_csv(fixtures_path)
        if X:
            console.print(f"[cyan]Loaded {len(X)} samples from committed labeled fixtures ({fixtures_path.name}). Skipping sandbox run.[/]")
            from ml.detector import clear_model_cache  # noqa: F401
        else:
            console.print("[cyan]No usable CSV or fixtures found — running sandbox on package lists...[/]")
            malicious_pkgs = load_dataset(base_dir / "data" / "malicious_packages_expanded.txt")
            clean_pkgs = load_dataset(base_dir / "data" / "clean_packages_expanded.txt")

            if not malicious_pkgs or not clean_pkgs:
                console.print("[bold red]Error:[/] Dataset files missing in data/ directory.")
                return

            from sandbox.sandbox import run_sandbox
            from monitor.parser import parse_strace_log
            from graph.builder import build_cascade_graph
            from ml.detector import map_features, clear_model_cache
            from concurrent.futures import ThreadPoolExecutor, as_completed

            all_packages = [(pkg, 1) for pkg in malicious_pkgs] + [(pkg, 0) for pkg in clean_pkgs]

            def process_package(pkg, label):
                try:
                    log_path = run_sandbox(pkg)
                    if not log_path:
                        return None
                    parsed = parse_strace_log(log_path)
                    graph = build_cascade_graph(parsed)
                    features = map_features(graph, parsed)
                    return features, label
                except Exception as e:
                    console.print(f"\n[red]Failed to extract features for {pkg}: {e}[/]")
                    return None

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task(
                    f"[cyan]Training model in parallel across {len(all_packages)} packages...",
                    total=len(all_packages)
                )
                max_workers = int(os.environ.get("TRACETREE_TRAIN_WORKERS", 4))
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = {executor.submit(process_package, pkg, label): pkg for pkg, label in all_packages}
                    for future in as_completed(futures):
                        result = future.result()
                        if result:
                            features, label = result
                            X.append(features)
                            y.append(label)
                        progress.advance(task)

    if not X:
        console.print("[bold red]Failed to extract meaningful features from any sandbox execution.[/]")
        return
        
    console.print("[green]Optimizing RandomForestClassifier weights...[/]")
    # Phase 1: Add class_weight='balanced' to handle severely imbalanced dataset
    # (32 clean vs 33 malicious packages is nearly 50/50 but model will generalize better)
    model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
    model.fit(X, y)
    
    model_dir = base_dir / "ml"
    model_dir.mkdir(exist_ok=True)
    model_path = model_dir / "model.skops"
    
    # Cache model state internally
    sio.dump(model, model_path)
        
    # Also save to Azure ML 'outputs' directory if it exists
    outputs_dir = Path("outputs")
    if outputs_dir.exists():
        sio.dump(model, outputs_dir / "model.skops")
        console.print("[bold green]✔ Model also saved to Azure ML outputs directory.[/]")
        
    # Invalidate in-memory cache to ensure the new model is loaded
    clear_model_cache()

    console.print(f"[bold green]✔ Model efficiently saved natively to {model_path}[/]")

    # Run evaluation harness
    from ml.evaluate import evaluate_model
    evaluate_model(X, y)

if __name__ == "__main__":
    train_model()
