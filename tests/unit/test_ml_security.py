import os
import pytest
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier, IsolationForest
import numpy as np
import skops.io as sio

from ml.detector import safe_load_model, get_ml_model, clear_model_cache

class ForbiddenPayload:
    def __reduce__(self):
        # In a real exploit, this would execute arbitrary code
        # We'll just return a dummy function to prove it was deserialized/called
        return (os.path.join, ("a", "b"))

def test_legitimate_model_loading(tmp_path):
    """Test that a normally trained RandomForestClassifier loads and predicts successfully."""
    rf = RandomForestClassifier(n_estimators=5, random_state=42)
    X = np.random.rand(10, 10)
    y = np.random.randint(0, 2, size=10)
    rf.fit(X, y)
    
    model_path = tmp_path / "model.skops"
    sio.dump(rf, model_path)
    
    # Safely load the model
    loaded_model = safe_load_model(model_path)
    assert isinstance(loaded_model, RandomForestClassifier)
    
    # Assert same predictions
    np.testing.assert_array_equal(rf.predict(X), loaded_model.predict(X))

def test_forbidden_payload_refused(tmp_path):
    """Test that a skops file containing a non-allowlisted class is refused."""
    payload = ForbiddenPayload()
    model_path = tmp_path / "malicious.skops"
    sio.dump(payload, model_path)
    
    with pytest.raises(ValueError, match="Security error"):
        safe_load_model(model_path)

def test_legacy_pickle_warning_and_fallback(tmp_path, monkeypatch):
    """Test that if a legacy model.pkl exists, a warning is printed and we fall back to IsolationForest."""
    # Write a dummy pickle file (even a valid pickling, or invalid one)
    import pickle
    legacy_path = tmp_path / "model.pkl"
    rf = RandomForestClassifier(n_estimators=5, random_state=42)
    X = np.random.rand(10, 10)
    y = np.random.randint(0, 2, size=10)
    rf.fit(X, y)
    with open(legacy_path, "wb") as f:
        pickle.dump(rf, f)
        
    # Monkeypatch get_ml_model paths or locate local file path
    # We patch ml.detector.Path pointing to local model
    original_parent = Path(__file__).parent.parent.parent / "ml"
    
    # Clear cache
    clear_model_cache()
    
    # We mock Path to return the temp path for our legacy check
    # Let's override Path in ml.detector or patch it
    with monkeypatch.context() as m:
        m.setattr("ml.detector.Path", lambda *args, **kwargs: legacy_path)
        # We expect a warning to be printed/displayed or fall back to isolation forest
        # Since model_path doesn't exist under legacy_path (we pointed to legacy_path),
        # get_ml_model should fall back to the IsolationForest baseline
        model = get_ml_model()
        assert isinstance(model, IsolationForest)
