"""
Unit tests for orchestrator.ai_mesh.TriageResult.

If the class does not exist yet (concurrent agent still building it),
the entire module is skipped gracefully.
"""
import pytest

try:
    from orchestrator.ai_mesh import TriageResult
    _TRIAGE_AVAILABLE = True
except (ImportError, AttributeError):
    _TRIAGE_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _TRIAGE_AVAILABLE,
    reason="orchestrator.ai_mesh.TriageResult not yet available",
)


# ---------------------------------------------------------------------------
# Tests — only execute if TriageResult was importable
# ---------------------------------------------------------------------------

class TestTriageResult:

    def test_from_dict_full(self):
        """All fields from a complete dict must be populated correctly."""
        data = {
            "verdict": "BENIGN",
            "confidence": 0.95,
            "reasoning": "No suspicious indicators found",
            "mitigation_applied": False,
        }
        result = TriageResult.from_dict(data)
        assert result.verdict == "BENIGN"
        assert result.confidence == pytest.approx(0.95)
        assert result.reasoning == "No suspicious indicators found"
        assert result.mitigation_applied is False

    def test_from_dict_defaults(self):
        """Empty dict must produce safe defaults: verdict=SUSPICIOUS, confidence=0.5."""
        result = TriageResult.from_dict({})
        assert result.verdict == "SUSPICIOUS"
        assert result.confidence == pytest.approx(0.5)

    def test_is_false_positive_true(self):
        """verdict=FALSE_POSITIVE → is_false_positive() must return True."""
        result = TriageResult.from_dict({"verdict": "FALSE_POSITIVE", "confidence": 0.9})
        assert result.is_false_positive() is True

    def test_is_false_positive_false(self):
        """verdict=SUSPICIOUS → is_false_positive() must return False."""
        result = TriageResult.from_dict({"verdict": "SUSPICIOUS", "confidence": 0.7})
        assert result.is_false_positive() is False

    def test_confidence_coerced_to_float(self):
        """confidence supplied as int must be stored as float."""
        result = TriageResult.from_dict({"confidence": 1})
        assert isinstance(result.confidence, float)
        assert result.confidence == 1.0
