"""
Unit tests for cli._is_port_in_use.

Uses unittest.mock to avoid any real network calls.
Covers:
- Port in use (connect_ex → 0) → True
- Port free (connect_ex → non-zero) → False
- Custom host is forwarded correctly to connect_ex
"""
import sys
from unittest.mock import patch, MagicMock

with patch.dict("sys.modules", {
    "typer": MagicMock(),
    "rich": MagicMock(),
    "rich.console": MagicMock(),
    "rich.panel": MagicMock(),
    "rich.progress": MagicMock(),
    "rich.tree": MagicMock(),
    "rich.text": MagicMock(),
    "rich.align": MagicMock(),
    "rich.columns": MagicMock(),
    "rich.layout": MagicMock(),
    "rich.style": MagicMock(),
    "docker": MagicMock(),
    "sandbox": MagicMock(),
    "sandbox.sandbox": MagicMock(),
}):
    from cli import _is_port_in_use


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_socket_mock(connect_ex_return: int):
    """Return a mock socket context manager that yields a socket with the given connect_ex result."""
    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = connect_ex_return
    # Support `with socket.socket(...) as s:` usage
    mock_sock.__enter__ = lambda self: self
    mock_sock.__exit__ = MagicMock(return_value=False)
    mock_socket_cls = MagicMock(return_value=mock_sock)
    return mock_socket_cls, mock_sock


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_port_in_use_returns_true():
    """connect_ex returning 0 (success) means port IS in use → True."""
    mock_socket_cls, mock_sock = _make_socket_mock(connect_ex_return=0)
    with patch("cli.socket.socket", mock_socket_cls):
        assert _is_port_in_use(8080) is True


def test_port_free_returns_false():
    """connect_ex returning non-zero (failure) means port is FREE → False."""
    mock_socket_cls, mock_sock = _make_socket_mock(connect_ex_return=111)
    with patch("cli.socket.socket", mock_socket_cls):
        assert _is_port_in_use(8080) is False


def test_custom_host_is_passed():
    """Verify that a custom host string is forwarded verbatim to connect_ex."""
    mock_socket_cls, mock_sock = _make_socket_mock(connect_ex_return=1)
    with patch("cli.socket.socket", mock_socket_cls):
        _is_port_in_use(9999, host="0.0.0.0")
    mock_sock.connect_ex.assert_called_once_with(("0.0.0.0", 9999))


def test_default_host_is_loopback():
    """Default host must be 127.0.0.1 (not 0.0.0.0 or localhost)."""
    mock_socket_cls, mock_sock = _make_socket_mock(connect_ex_return=1)
    with patch("cli.socket.socket", mock_socket_cls):
        _is_port_in_use(1234)
    mock_sock.connect_ex.assert_called_once_with(("127.0.0.1", 1234))
