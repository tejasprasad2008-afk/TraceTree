"""
Unit tests for monitor.yara._compile_yara_rules.

Skipped entirely if yara-python is not installed (pytest.importorskip).

Covers:
- SyntaxError in an external MCP rule file → RuntimeError raised
- OSError reading MCP rule file → falls back to embedded rules successfully
- MCP file missing (Path.exists → False) → falls back to embedded rules
"""
import pytest

yara = pytest.importorskip("yara", reason="yara-python not installed")

from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

from monitor.yara import _compile_yara_rules, _YARA_RULES_SRC


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_yara_mock(syntax_error=False):
    """Return a yara-module mock.

    If ``syntax_error=True`` the mock's compile() raises yara.SyntaxError
    for any call that receives combined_src (i.e. one containing extra rules).
    Otherwise it behaves like a working yara module.
    """
    mock_yara = MagicMock()
    mock_yara.SyntaxError = yara.SyntaxError  # use real exception class so isinstance works

    def _compile(source=None):
        if syntax_error and source and source != _YARA_RULES_SRC:
            raise yara.SyntaxError("fake syntax error")
        return MagicMock(name="compiled_rules")

    mock_yara.compile.side_effect = _compile
    return mock_yara


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCompileYaraRules:

    def test_raises_runtime_error_on_syntax_error(self):
        """A syntax error in the MCP YARA file must propagate as RuntimeError."""
        mock_yara = _make_yara_mock(syntax_error=True)

        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.read_text", return_value="rule Bad { condition: THIS IS NOT VALID YARA }"):
                with pytest.raises(RuntimeError, match="MCP YARA rule syntax error"):
                    _compile_yara_rules(mock_yara)

    def test_falls_back_on_os_error(self):
        """OSError reading the MCP file must NOT raise; must compile embedded rules instead."""
        mock_yara = MagicMock()
        mock_yara.SyntaxError = yara.SyntaxError
        compiled = MagicMock(name="embedded_compiled")
        mock_yara.compile.return_value = compiled

        with patch("pathlib.Path.exists", return_value=True):
            with patch("builtins.open", side_effect=OSError("disk read error")):
                result = _compile_yara_rules(mock_yara)

        assert result is not None
        assert mock_yara.compile.called

    def test_compiles_embedded_when_mcp_missing(self):
        """When the MCP YARA file does not exist, embedded rules must be compiled."""
        mock_yara = MagicMock()
        mock_yara.SyntaxError = yara.SyntaxError
        compiled = MagicMock(name="embedded_compiled")
        mock_yara.compile.return_value = compiled

        with patch("pathlib.Path.exists", return_value=False):
            result = _compile_yara_rules(mock_yara)

        assert result is not None
        assert mock_yara.compile.called
        # Check that compile was called with the correct source content
        last_call_args, last_call_kwargs = mock_yara.compile.call_args
        assert last_call_kwargs.get("source") == _YARA_RULES_SRC
