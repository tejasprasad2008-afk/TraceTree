import tempfile
import os
from hypothesis import given, strategies as st, settings, HealthCheck
from monitor.parser import parse_strace_log

@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
@given(st.text())
def test_parse_strace_log_fuzz(fuzz_text):
    """Ensure parse_strace_log gracefully handles any arbitrary text log without unhandled crashes."""
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", errors="ignore") as tmp:
        tmp.write(fuzz_text)
        tmp_path = tmp.name

    try:
        result = parse_strace_log(tmp_path)
        assert isinstance(result, dict)
    except Exception as e:
        # FileNotFoundError or ValueError might be expected for invalid files, but general crashes should fail
        if not isinstance(e, (FileNotFoundError, ValueError)):
            assert False, f"parse_strace_log crashed on fuzzed log content with error: {type(e).__name__}: {e}"
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
