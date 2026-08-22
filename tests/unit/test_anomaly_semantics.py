import pytest
from ml.detector import AnomalyVerdict, _severity_adjusted_confidence, detect_anomaly
from sklearn.ensemble import RandomForestClassifier
import numpy as np

def test_anomaly_verdict_tuple_compatibility():
    """Verify that AnomalyVerdict behaves as a 2-tuple for backward compatibility."""
    verdict = AnomalyVerdict(
        is_malicious=True,
        risk_score=85.5,
        ml_probability=75.0,
        reasons=["Test reason"]
    )
    
    # 2-tuple unpacking
    is_mal, score = verdict
    assert is_mal is True
    assert score == 85.5
    
    # Subclass and attributes
    assert isinstance(verdict, tuple)
    assert len(verdict) == 2
    assert verdict[0] is True
    assert verdict[1] == 85.5
    assert verdict.is_malicious is True
    assert verdict.risk_score == 85.5
    assert verdict.ml_probability == 75.0
    assert verdict.reasons == ["Test reason"]

def test_severity_adjusted_confidence_rules():
    """Test all heuristic risk score adjustment rules."""
    # 1. Base case: no boosts, no severity, no temporal
    is_mal, score, reasons = _severity_adjusted_confidence(
        is_malicious=False,
        ml_confidence=50.0,
        total_severity=0.0,
        sensitive_file_count=0,
        suspicious_network_count=0,
        temporal_pattern_count=0
    )
    assert is_mal is False
    assert score == 50.0
    assert not reasons

    # 2. Critical severity override (total_severity >= 30)
    is_mal, score, reasons = _severity_adjusted_confidence(
        is_malicious=False,
        ml_confidence=50.0,
        total_severity=35.0,
        sensitive_file_count=0,
        suspicious_network_count=0,
        temporal_pattern_count=0
    )
    assert is_mal is True
    # confidence + 25.0 -> 50.0 + 25.0 -> 75.0
    assert score == 75.0
    assert any("Critical syscall severity" in r for r in reasons)

    # 3. High severity boost (total_severity >= 15)
    is_mal, score, reasons = _severity_adjusted_confidence(
        is_malicious=False,
        ml_confidence=40.0,
        total_severity=20.0,
        sensitive_file_count=0,
        suspicious_network_count=0,
        temporal_pattern_count=0
    )
    # confidence = 40.0 + 30.0 = 70.0. Since 70.0 > 60.0, flips to malicious.
    assert is_mal is True
    assert score == 70.0
    assert any("High syscall severity boost" in r for r in reasons)
    assert any("Verdict flipped to malicious" in r for r in reasons)

    # 4. Medium severity boost (total_severity >= 5)
    is_mal, score, reasons = _severity_adjusted_confidence(
        is_malicious=False,
        ml_confidence=40.0,
        total_severity=8.0,
        sensitive_file_count=0,
        suspicious_network_count=0,
        temporal_pattern_count=0
    )
    # confidence = 40.0 + 10.0 = 50.0. Does not flip.
    assert is_mal is False
    assert score == 50.0
    assert any("Medium syscall severity boost" in r for r in reasons)

    # 5. Temporal patterns, sensitive files, suspicious networks
    is_mal, score, reasons = _severity_adjusted_confidence(
        is_malicious=False,
        ml_confidence=40.0,
        total_severity=0.0,
        sensitive_file_count=2,
        suspicious_network_count=3,
        temporal_pattern_count=1
    )
    # 40.0 + 1*15 (temporal) + 2*5 (files) + 3*5 (networks) = 80.0
    assert is_mal is False
    assert score == 80.0
    assert any("Temporal patterns matched: 1" in r for r in reasons)
    assert any("Sensitive file accesses: 2" in r for r in reasons)
    assert any("Suspicious network connections: 3" in r for r in reasons)

    # 6. Verdict flipped by multiple temporal patterns (>= 2)
    is_mal, score, reasons = _severity_adjusted_confidence(
        is_malicious=False,
        ml_confidence=30.0,
        total_severity=0.0,
        sensitive_file_count=0,
        suspicious_network_count=0,
        temporal_pattern_count=2
    )
    # 30.0 + 30.0 = 60.0. Verdict flips to malicious due to multiple temporal patterns.
    assert is_mal is True
    assert score == 60.0
    assert any("multiple suspicious temporal patterns" in r for r in reasons)
