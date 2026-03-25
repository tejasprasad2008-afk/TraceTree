import os
import pickle
from pathlib import Path
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.console import Console
from sklearn.ensemble import RandomForestClassifier
from google.cloud import storage

def load_dataset(filepath: str) -> list:
    if not Path(filepath).exists():
        return []
    with open(filepath, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def train_model():
    console = Console()
    
    # Must correctly resolve absolute paths to data lists
    base_dir = Path(__file__).parent.parent
    malicious_pkgs = load_dataset(base_dir / "data" / "malicious_packages.txt")
    clean_pkgs = load_dataset(base_dir / "data" / "clean_packages.txt")
    
    if not malicious_pkgs or not clean_pkgs:
        console.print("[bold red]Error:[/] Dataset files missing in data/ directory.")
        return

    from sandbox.sandbox import run_sandbox
    from monitor.parser import parse_strace_log
    from graph.builder import build_cascade_graph
    from ml.detector import map_features
    
    X = []
    y = []
    
    # Supervised Binary Representation
    all_packages = [(pkg, 1) for pkg in malicious_pkgs] + [(pkg, 0) for pkg in clean_pkgs]
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(f"[cyan]Training model sequentially across {len(all_packages)} packages...", total=len(all_packages))
        
        for pkg, label in all_packages:
            progress.update(task, description=f"[cyan]Executing sandbox targeting {pkg}...")
            
            try:
                log_path = run_sandbox(pkg)
                if not log_path:
                    progress.advance(task)
                    continue
                    
                parsed = parse_strace_log(log_path)
                graph = build_cascade_graph(parsed)
                features = map_features(graph, parsed)
                
                X.append(features)
                y.append(label)
            except Exception as e:
                console.print(f"\n[red]Failed to extract features for {pkg}: {e}[/]")
            
            progress.advance(task)

    if not X:
        console.print("[bold red]Failed to extract meaningful features from any sandbox execution.[/]")
        return
        
    console.print("[green]Optimizing RandomForestClassifier weights...[/]")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    
    model_dir = base_dir / "ml"
    model_dir.mkdir(exist_ok=True)
    model_path = model_dir / "model.pkl"
    
    # Cache model state internally
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
        
    console.print(f"[bold green]✔ Model efficiently saved natively to {model_path}[/]")
    
    # Sync pipeline state cleanly with remote target GCS tracking endpoint natively
    try:
        console.print("[cyan]Pushing weights into global Google Cloud Storage cache (`cascade-analyzer-models`)...[/]")
        client = storage.Client() # Expects GOOGLE_APPLICATION_CREDENTIALS or gcloud auth
        bucket = client.bucket("cascade-analyzer-models")
        blob = bucket.blob("model.pkl")
        blob.upload_from_filename(str(model_path))
        console.print("[bold green]✔ Model uploaded directly cleanly to remote GCS successfully![/]")
    except Exception as e:
        console.print(f"[bold yellow]⚠ GCS Auth Upload Skipped (Non-Fatal):[/] {e}")

if __name__ == "__main__":
    train_model()
