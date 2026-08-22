"""
Retrain TraceTree's Random Forest model from the expanded labeled_fixtures.csv.

Reads the 5000+ row fixture file (original 30 rows + 5000 CIC-derived rows),
trains a RandomForestClassifier with cross-validation, evaluates it, and saves
the model in skops format at ml/model.skops.
"""

import csv
import json
import sys
from pathlib import Path

# Ensure project root on path
sys.path.insert(0, str(Path(__file__).parent))


def load_fixtures(csv_path):
    """Load features and labels from labeled_fixtures.csv."""
    feature_columns = [
        "node_count", "edge_count", "network_conn_count", "file_read_count",
        "execve_count", "total_severity", "suspicious_network_count",
        "sensitive_file_count", "max_severity", "temporal_pattern_count",
    ]
    X, y = [], []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                features = [float(row.get(c, 0) or 0) for c in feature_columns]
                label = int(row.get("is_malicious", 0))
                X.append(features)
                y.append(label)
            except (ValueError, TypeError):
                continue
    return X, y


def main():
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import (
        precision_score, recall_score, f1_score, confusion_matrix,
        classification_report, accuracy_score,
    )
    import skops.io as sio

    base_dir = Path(__file__).parent
    csv_path = base_dir / "data" / "labeled_fixtures.csv"
    model_path = base_dir / "ml" / "model.skops"
    metrics_path = base_dir / "ml" / "metrics.json"

    if not csv_path.exists():
        print("ERROR: {} not found. Run bridge_cic_to_tracetree.py first.".format(csv_path))
        sys.exit(1)

    # 1. Load data
    print("1. Loading training data from {}...".format(csv_path.name))
    X, y = load_fixtures(csv_path)
    X = np.array(X)
    y = np.array(y)
    print("   Loaded {} samples ({} benign, {} malicious)".format(
        len(y), np.sum(y == 0), np.sum(y == 1)
    ))

    # 2. Train/test split
    print("2. Splitting into 80% train / 20% test (stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print("   Train: {} samples  |  Test: {} samples".format(len(y_train), len(y_test)))

    # 3. Train model
    print("3. Training RandomForestClassifier (200 trees, balanced weights)...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    # 4. Evaluate
    print("4. Evaluating on held-out test set...")
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    print("\n   === Test Set Results ===")
    print("   Accuracy:             {:.4f}".format(accuracy))
    print("   Precision:            {:.4f}".format(precision))
    print("   Recall (Sensitivity): {:.4f}".format(recall))
    print("   F1 Score:             {:.4f}".format(f1))
    print("   False Positive Rate:  {:.4f}".format(fpr))
    print("   Confusion Matrix:  TP={} FP={} FN={} TN={}".format(tp, fp, fn, tn))
    print("\n" + classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))

    # 5. Cross-validation for robustness
    print("5. Running 5-fold cross-validation...")
    cv_scores = cross_val_score(model, X, y, cv=5, scoring="accuracy")
    print("   CV Accuracy: {:.4f} (+/- {:.4f})".format(cv_scores.mean(), cv_scores.std() * 2))

    # 6. Feature importances
    feature_names = [
        "node_count", "edge_count", "network_conn_count", "file_read_count",
        "execve_count", "total_severity", "suspicious_network_count",
        "sensitive_file_count", "max_severity", "temporal_pattern_count",
    ]
    importances = model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    print("\n6. Feature Importances:")
    for i in sorted_idx:
        bar = "█" * int(importances[i] * 50)
        print("   {:30s} {:.4f}  {}".format(feature_names[i], importances[i], bar))

    # 7. Save model
    print("\n7. Saving model to {}...".format(model_path))
    sio.dump(model, model_path)
    print("   ✔ Model saved ({:.1f} KB)".format(model_path.stat().st_size / 1024))

    # 8. Save metrics
    metrics = {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "accuracy": round(accuracy, 4),
        "cv_accuracy_mean": round(float(cv_scores.mean()), 4),
        "cv_accuracy_std": round(float(cv_scores.std()), 4),
        "training_samples": int(len(y)),
        "n_estimators": 200,
    }
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print("   ✔ Metrics saved to {}".format(metrics_path))

    print("\n" + "=" * 60)
    print("✅ DONE! TraceTree model retrained on {} samples.".format(len(y)))
    print("   Model: {}".format(model_path))
    print("   Metrics: {}".format(metrics_path))
    print("=" * 60)


if __name__ == "__main__":
    main()
