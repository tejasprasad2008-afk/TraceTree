import json
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
from rich.console import Console
from rich.table import Table


def evaluate_model(X, y, test_size=0.3, random_state=42):
    console = Console()
    
    # 1. Stratified train/test split
    X = np.array(X)
    y = np.array(y)
    
    # Check that we have enough samples of both classes
    unique_classes, counts = np.unique(y, return_counts=True)
    if len(unique_classes) < 2 or any(c < 2 for c in counts):
        console.print("[yellow]⚠ Not enough samples of both classes to perform stratified split. Skipping evaluation metrics export.[/]")
        return
        
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    
    # 2. Train model on training split
    clf = RandomForestClassifier(n_estimators=100, random_state=random_state, class_weight='balanced')
    clf.fit(X_train, y_train)
    
    # 3. Predict on test split
    y_pred = clf.predict(X_test)
    
    # 4. Compute metrics
    precision = float(precision_score(y_test, y_pred, zero_division=0))
    recall = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    
    metrics = {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4)
    }
    
    # Write to metrics.json
    metrics_path = Path(__file__).parent / "metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
        
    # Render rich table of results
    table = Table(title="Model Evaluation Metrics (Stratified Split)", border_style="cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right", style="green")
    
    table.add_row("Precision", f"{precision:.4f}")
    table.add_row("Recall (Sensitivity)", f"{recall:.4f}")
    table.add_row("F1 Score", f"{f1:.4f}")
    table.add_row("False Positive Rate (FPR)", f"{fpr:.4f}")
    
    console.print(table)
    console.print(f"[bold green]✔ Evaluation metrics exported to {metrics_path}[/]")

if __name__ == "__main__":
    from ml.trainer import _load_features_from_csv
    base_dir = Path(__file__).parent.parent
    csv_path = base_dir / "data" / "ingested_training_data.csv"
    X, y = _load_features_from_csv(csv_path)
    if not X:
        fixtures_path = base_dir / "data" / "labeled_fixtures.csv"
        X, y = _load_features_from_csv(fixtures_path)
    if X:
        evaluate_model(X, y)
    else:
        print("No training data or labeled fixtures found to evaluate.")
