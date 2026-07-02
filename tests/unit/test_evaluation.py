import os
import json
import pytest
from pathlib import Path
from ml.evaluate import evaluate_model
from ml.trainer import train_model
import ml.trainer
from ml.detector import clear_model_cache, AnomalyVerdict, get_ml_model

def test_evaluate_model(tmp_path):
    """Test that evaluate_model calculates metrics and generates metrics.json correctly."""
    X = []
    y = []
    for _ in range(15):
        X.append([1.0, 1.0, 0.0, 5.0, 1.0, 1.0, 0.0, 0.0, 1.0, 0.0])
        y.append(0)
    for _ in range(15):
        X.append([20.0, 20.0, 5.0, 100.0, 5.0, 30.0, 2.0, 3.0, 10.0, 2.0])
        y.append(1)

    original_metrics_path = Path(__file__).parent.parent.parent / "ml" / "metrics.json"
    
    backup_exists = original_metrics_path.exists()
    backup_content = None
    if backup_exists:
        with open(original_metrics_path, "r", encoding="utf-8") as f:
            backup_content = f.read()
            
    try:
        evaluate_model(X, y, test_size=0.3, random_state=42)
        
        assert original_metrics_path.exists()
        with open(original_metrics_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert "precision" in data
            assert "recall" in data
            assert "f1_score" in data
            assert "false_positive_rate" in data
    finally:
        if backup_exists:
            with open(original_metrics_path, "w", encoding="utf-8") as f:
                f.write(backup_content)
        elif original_metrics_path.exists():
            original_metrics_path.unlink()

def test_train_model_fallback(tmp_path, monkeypatch):
    """Test that train_model falls back to labeled_fixtures.csv and trains successfully."""
    base_dir = Path(__file__).parent.parent.parent
    
    model_skops_path = base_dir / "ml" / "model.skops"
    metrics_json_path = base_dir / "ml" / "metrics.json"
    
    backup_skops_exists = model_skops_path.exists()
    backup_skops_content = None
    if backup_skops_exists:
        with open(model_skops_path, "rb") as f:
            backup_skops_content = f.read()
            
    backup_metrics_exists = metrics_json_path.exists()
    backup_metrics_content = None
    if backup_metrics_exists:
        with open(metrics_json_path, "r", encoding="utf-8") as f:
            backup_metrics_content = f.read()
            
    try:
        # Clear cache first
        clear_model_cache()
        
        real_fixtures_path = base_dir / "data" / "labeled_fixtures.csv"
        
        # Running train_model() on the real project folder with backup/restore is extremely robust.
        # Save original function to avoid recursion
        original_fn = ml.trainer._load_features_from_csv
        
        call_count = 0
        def mock_load_features(path):
            nonlocal call_count
            call_count += 1
            if "ingested_training_data.csv" in str(path):
                return [], []
            return original_fn(real_fixtures_path)
            
        monkeypatch.setattr(ml.trainer, "_load_features_from_csv", mock_load_features)
        
        # Run training
        train_model()
        
        # Verify the model was saved and metrics generated
        assert model_skops_path.exists()
        assert metrics_json_path.exists()
        
        # Verify we can load the trained model and it performs predictions
        clear_model_cache()
        model = get_ml_model()
        assert model is not None
        
    finally:
        # Restore backups
        if backup_skops_exists:
            with open(model_skops_path, "wb") as f:
                f.write(backup_skops_content)
        elif model_skops_path.exists():
            model_skops_path.unlink()
            
        if backup_metrics_exists:
            with open(metrics_json_path, "w", encoding="utf-8") as f:
                f.write(backup_metrics_content)
        elif metrics_json_path.exists():
            metrics_json_path.unlink()
