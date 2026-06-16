import pytest
import os
from unittest.mock import patch, MagicMock, mock_open, ANY
from monitor.ai_analyzer import is_ollama_installed, is_ollama_alive

@patch("shutil.which")
def test_is_ollama_installed(mock_which):
    # Case 1: Ollama is installed
    mock_which.return_value = "/usr/local/bin/ollama"
    assert is_ollama_installed() is True

    # Case 2: Ollama is not installed
    mock_which.return_value = None
    assert is_ollama_installed() is False

@patch("requests.get")
def test_is_ollama_alive(mock_get):
    # Case 1: Service is alive (200 OK)
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_get.return_value = mock_response
    assert is_ollama_alive() is True

    # Case 2: Service returns an error (e.g., 500)
    mock_response.status_code = 500
    assert is_ollama_alive() is False

    # Case 3: Request raises an exception (e.g., connection error)
    mock_get.side_effect = Exception("Connection refused")
    assert is_ollama_alive() is False

@patch("pathlib.Path.exists")
@patch("builtins.open", new_callable=mock_open, read_data="line1\nline2\nline3\nline4\nline5\n")
def test_get_file_context(mock_file, mock_exists):
    from pathlib import Path
    from monitor.ai_analyzer import get_file_context

    # Case 1: File does not exist
    mock_exists.return_value = False
    assert get_file_context(Path("test.py"), 1) == ""

    # Case 2: File exists, get context
    mock_exists.return_value = True
    # line_number is 1-indexed in get_file_context
    # window=1, line_number=3 should give lines 2, 3, 4
    # start = max(0, 3 - 1 - 1) = 1
    # end = min(5, 3 + 1) = 4
    # lines[1:4] = ["line2\n", "line3\n", "line4\n"]
    context = get_file_context(Path("test.py"), 3, window=1)
    assert context == "line2\nline3\nline4\n"

    # Case 3: Exception during file read
    mock_file.side_effect = Exception("Read error")
    assert get_file_context(Path("test.py"), 3) == ""

@patch("monitor.ai_analyzer.is_ollama_alive")
@patch("requests.post")
def test_analyze_finding_with_ai(mock_post, mock_alive):
    from monitor.ai_analyzer import analyze_finding_with_ai

    # Case 1: Ollama not alive
    mock_alive.return_value = False
    result = analyze_finding_with_ai("test.py", 1, "type", "rule", "content")
    assert "error" in result
    assert "Ollama not running" in result["error"]

    # Case 2: Success
    mock_alive.return_value = True
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"response": '{"is_vulnerable": true, "severity": 8, "reason": "test"}'}
    mock_post.return_value = mock_response

    result = analyze_finding_with_ai("test.py", 1, "type", "rule", "content")
    assert result["is_vulnerable"] is True
    assert result["severity"] == 8

    # Case 3: Ollama returns error status
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    result = analyze_finding_with_ai("test.py", 1, "type", "rule", "content")
    assert "error" in result
    assert "Ollama returned error" in result["error"]

    # Case 4: AI returns invalid JSON
    mock_response.status_code = 200
    mock_response.json.return_value = {"response": "invalid json"}
    result = analyze_finding_with_ai("test.py", 1, "type", "rule", "content")
    assert "error" in result
    assert "AI returned invalid JSON" in result["error"]

    # Case 5: AI response missing keys
    mock_response.json.return_value = {"response": '{"severity": 8}'}
    result = analyze_finding_with_ai("test.py", 1, "type", "rule", "content")
    assert "error" in result
    assert "missing 'is_vulnerable' key" in result["error"]

    # Case 6: Exception during request
    mock_post.side_effect = Exception("Network error")
    result = analyze_finding_with_ai("test.py", 1, "type", "rule", "content")
    assert "error" in result
    assert "Network error" in result["error"]

@patch("monitor.ai_analyzer.is_ollama_alive")
@patch("shutil.which")
@patch("platform.system")
@patch("rich.prompt.Confirm.ask")
@patch("subprocess.run")
@patch("subprocess.Popen")
@patch("requests.get")
@patch("rich.console.Console")
def test_ensure_ollama_and_model(
    mock_console, mock_get, mock_popen, mock_run, mock_ask, mock_system, mock_which, mock_alive
):
    from monitor.ai_analyzer import ensure_ollama_and_model

    # Case 1: Everything already set up
    mock_which.return_value = "/usr/local/bin/ollama"
    mock_alive.side_effect = [True, True] # is_ollama_alive() called twice
    mock_response = MagicMock()
    mock_response.json.return_value = {"models": [{"name": "qwen2.5-coder:7b"}]}
    mock_get.return_value = mock_response

    assert ensure_ollama_and_model() is True

    # Case 2: Ollama not installed, user declines install
    mock_which.return_value = None
    mock_ask.return_value = False
    assert ensure_ollama_and_model() is False

    # Case 3: Ollama not installed, user accepts install (macOS)
    mock_which.side_effect = [None, "/usr/local/bin/ollama"] # first check none, second check success
    mock_ask.return_value = True
    mock_system.return_value = "Darwin"
    # mock shutil.which("brew")
    with patch("shutil.which", side_effect=[None, "/usr/local/bin/brew", "/usr/local/bin/ollama"]):
         # reset mock_which for this subtest
         assert ensure_ollama_and_model() is True
         mock_run.assert_any_call(["/usr/local/bin/brew", "install", "ollama"], env=ANY, check=True)

    # Reset side effects
    mock_which.side_effect = None
    mock_which.return_value = "/usr/local/bin/ollama"
    mock_ask.side_effect = None
    mock_ask.return_value = True

    # Case 4: Ollama service not running, user starts it
    mock_alive.side_effect = [False, True]
    mock_response.json.return_value = {"models": [{"name": "qwen2.5-coder:7b"}]}
    assert ensure_ollama_and_model() is True
    mock_popen.assert_called()

    # Case 5: Model not found, user pulls it
    mock_alive.side_effect = None
    mock_alive.return_value = True
    mock_response.json.return_value = {"models": [{"name": "other-model"}]}
    assert ensure_ollama_and_model() is True
    mock_run.assert_any_call(["/usr/local/bin/ollama", "pull", "qwen2.5-coder:7b"], env=ANY, check=True)
