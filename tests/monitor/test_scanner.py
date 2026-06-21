import pytest
from unittest.mock import patch, mock_open
from pathlib import Path
from monitor.scanner import scan_file_for_secrets

def test_scan_file_for_secrets_unicode_decode_error():
    """Test that scan_file_for_secrets handles UnicodeDecodeError gracefully."""
    file_path = Path("test_unicode.txt")

    with patch("builtins.open", side_effect=UnicodeDecodeError("utf-8", b"", 0, 1, "reason")):
        results = list(scan_file_for_secrets(file_path))
        assert len(results) == 0

def test_scan_file_for_secrets_value_error():
    """Test that scan_file_for_secrets handles ValueError gracefully."""
    file_path = Path("test_value.txt")

    with patch("builtins.open", side_effect=ValueError("Mocked value error")):
        results = list(scan_file_for_secrets(file_path))
        assert len(results) == 0

def test_scan_file_for_secrets_os_error():
    """Test that scan_file_for_secrets handles OSError gracefully."""
    file_path = Path("test_os.txt")

    with patch("builtins.open", side_effect=OSError("Mocked OS error")):
        results = list(scan_file_for_secrets(file_path))
        assert len(results) == 0

def test_scan_file_for_secrets_permission_error():
    """Test that scan_file_for_secrets handles PermissionError gracefully."""
    file_path = Path("test_permission.txt")

    with patch("builtins.open", side_effect=PermissionError("Mocked permission error")):
        results = list(scan_file_for_secrets(file_path))
        assert len(results) == 0

def test_scan_file_for_secrets_binary_file_skipping():
    """Test that binary files are skipped correctly based on the null byte check."""
    file_path = Path("test_binary.bin")

    # Mock open to return a binary chunk with a null byte
    m = mock_open(read_data=b"some data\x00more data")
    with patch("builtins.open", m):
        results = list(scan_file_for_secrets(file_path))
        assert len(results) == 0

def test_scan_file_for_secrets_ignored_extensions():
    """Test that files with ignored extensions are skipped."""
    ignored_files = [
        Path("test.log"),
        Path("test.pkl"),
        Path("test.exe"),
        Path("test.dmg"),
        Path("test.zip"),
    ]

    for fpath in ignored_files:
        results = list(scan_file_for_secrets(fpath))
        assert len(results) == 0
