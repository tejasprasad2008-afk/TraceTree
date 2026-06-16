import pytest
from unittest.mock import patch
from monitor.ngrams import (
    extract_ngrams,
    ngram_similarity,
    weighted_ngram_similarity,
    detect_suspicious_ngrams,
    _parse_syscall_categories,
    _SUSPICIOUS_NGRAMS,
    MAX_STRACE_LINES,
)

def test_parse_syscall_categories_formats(tmp_path):
    """Test various strace line formats."""
    log_content = (
        "openat(AT_FDCWD, \"/etc/passwd\", O_RDONLY) = 3\n"  # Standard
        "1234 openat(AT_FDCWD, \"/etc/passwd\", O_RDONLY) = 3\n"  # PID
        "1234 12:34:56.789012 openat(AT_FDCWD, \"/etc/passwd\", O_RDONLY) = 3\n"  # PID + timestamp
    )
    log_file = tmp_path / "strace.log"
    log_file.write_text(log_content)

    categories = _parse_syscall_categories(str(log_file))
    assert categories == ["file_open", "file_open", "file_open"]

def test_parse_syscall_categories_continuation(tmp_path):
    """Test continuation lines starting with <..."""
    log_content = (
        "1234 openat(AT_FDCWD, \"/etc/passwd\", O_RDONLY <unfinished ...>\n"
        "1234 <... openat resumed>) = 3\n"
        "1234 <... close resumed>) = 0\n"
    )
    log_file = tmp_path / "strace.log"
    log_file.write_text(log_content)

    categories = _parse_syscall_categories(str(log_file))
    assert categories == ["file_open", "file_open", "file_close"]

def test_parse_syscall_categories_malformed(tmp_path):
    """Test malformed and empty lines."""
    log_content = (
        "\n"
        "   \n"
        "short\n"
        "1234\n"
        "1234 12:34:56\n"
    )
    log_file = tmp_path / "strace.log"
    log_file.write_text(log_content)

    categories = _parse_syscall_categories(str(log_file))
    assert categories == []

def test_parse_syscall_categories_exception(tmp_path):
    """Test exception handling during parsing."""
    with patch("builtins.open", side_effect=Exception("Simulated error")):
        categories = _parse_syscall_categories("some_file")
        assert categories == []

def test_extract_ngrams_basic(tmp_path):
    """Test basic n-gram extraction and fingerprinting."""
    log_content = (
        "socket(AF_INET, SOCK_STREAM, 0) = 3\n"
        "connect(3, {sa_family=AF_INET, sin_port=htons(80), ...}, 16) = 0\n"
        "write(3, \"GET / HTTP/1.1\\r\\n\", 18) = 18\n"
        "socket(AF_INET, SOCK_STREAM, 0) = 4\n"
        "connect(4, {sa_family=AF_INET, sin_port=htons(80), ...}, 16) = 0\n"
        "write(4, \"GET / HTTP/1.1\\r\\n\", 18) = 18\n"
    )
    log_file = tmp_path / "strace.log"
    log_file.write_text(log_content)

    result = extract_ngrams(str(log_file), n=2)

    # Categories: net_socket, net_connect, file_write, net_socket, net_connect, file_write
    # Bigrams:
    # (net_socket, net_connect) - 2
    # (net_connect, file_write) - 2
    # (file_write, net_socket) - 1

    assert result["total_syscalls"] == 6
    assert result["unique_ngrams"] == 3
    assert result["ngrams"]["net_socket,net_connect"] == 2
    assert result["ngrams"]["net_connect,file_write"] == 2
    assert result["ngrams"]["file_write,net_socket"] == 1

    assert len(result["categories"]) == 6
    assert len(result["top_ngrams"]) == 3
    assert result["fingerprint"] != ""

def test_extract_ngrams_truncation(tmp_path):
    """Test truncation logic by patching MAX_STRACE_LINES."""
    log_content = "open() = 3\n" * 10
    log_file = tmp_path / "strace.log"
    log_file.write_text(log_content)

    with patch("monitor.ngrams.MAX_STRACE_LINES", 5):
        result = extract_ngrams(str(log_file))
        assert result["total_syscalls"] == 5

def test_extract_ngrams_empty(tmp_path):
    """Test handling of empty or non-existent files."""
    # Empty file
    log_file = tmp_path / "empty.log"
    log_file.write_text("")
    result = extract_ngrams(str(log_file))
    assert result["total_syscalls"] == 0
    assert result["fingerprint"] == ""

    # Non-existent file
    result = extract_ngrams("/non/existent/path")
    assert result["total_syscalls"] == 0

def test_ngram_similarity():
    """Test Jaccard similarity."""
    ngrams_a = {"ngrams": {"a,b,c": 1, "b,c,d": 1}}
    ngrams_b = {"ngrams": {"a,b,c": 1, "x,y,z": 1}}

    # Intersection: {"a,b,c"} (1)
    # Union: {"a,b,c", "b,c,d", "x,y,z"} (3)
    # Similarity: 1/3
    assert ngram_similarity(ngrams_a, ngrams_b) == pytest.approx(1/3)

    assert ngram_similarity({}, {}) == 0.0
    assert ngram_similarity({"ngrams": {}}, {"ngrams": {"a": 1}}) == 0.0

def test_weighted_ngram_similarity():
    """Test weighted cosine similarity."""
    ngrams_a = {"ngrams": {"a": 1, "b": 2}}
    ngrams_b = {"ngrams": {"a": 1, "b": 2}}

    # Identical: 1.0
    assert weighted_ngram_similarity(ngrams_a, ngrams_b) == pytest.approx(1.0)

    ngrams_c = {"ngrams": {"a": 1, "b": 0}}
    ngrams_d = {"ngrams": {"a": 0, "b": 1}}
    # Orthogonal: 0.0
    assert weighted_ngram_similarity(ngrams_c, ngrams_d) == 0.0

    # Zero magnitude vectors
    assert weighted_ngram_similarity({"ngrams": {"a": 0}}, {"ngrams": {"a": 1}}) == 0.0
    assert weighted_ngram_similarity({"ngrams": {"a": 1}}, {"ngrams": {"a": 0}}) == 0.0

    assert weighted_ngram_similarity({}, {}) == 0.0

@pytest.mark.parametrize("pattern,description", _SUSPICIOUS_NGRAMS.items())
def test_detect_suspicious_ngrams(pattern, description):
    """Test detection of each suspicious pattern."""
    ngrams = {"ngrams": {pattern: 5}}
    findings = detect_suspicious_ngrams(ngrams)

    assert len(findings) == 1
    assert findings[0]["ngram"] == pattern
    assert findings[0]["description"] == description
    assert findings[0]["count"] == "5"

def test_detect_suspicious_ngrams_none():
    """Test detection with no suspicious patterns."""
    ngrams = {"ngrams": {"safe,ngram,here": 10}}
    findings = detect_suspicious_ngrams(ngrams)
    assert len(findings) == 0
