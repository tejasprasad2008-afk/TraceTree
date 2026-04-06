from mcp.sandbox import _build_npm_server_command, _build_local_server_command, _build_sandbox_script
import shlex

def test_package_injection():
    malicious_input = "; touch /tmp/pwned"
    command = _build_npm_server_command(malicious_input, "stdio", 3000)
    print(f"Generated command: {command}")

    quoted = shlex.quote(malicious_input)
    assert quoted in command
    assert f"npm install -g {quoted}" in command
    assert f"npx --yes {quoted}" in command

def test_port_injection():
    # Test that invalid port raises ValueError
    try:
        _build_npm_server_command("test-pkg", "http", "3000; touch /tmp/pwned")
        assert False, "Should have raised ValueError"
    except ValueError:
        print("Caught expected ValueError for npm server command port injection")

    try:
        _build_local_server_command("/tmp/path", "http", "3000; touch /tmp/pwned")
        assert False, "Should have raised ValueError"
    except ValueError:
        print("Caught expected ValueError for local server command port injection")

def test_none_port():
    # Test that None port is handled safely (e.g. for stdio)
    command = _build_npm_server_command("test-pkg", "stdio", None)
    assert "--port 0" not in command # stdio shouldn't have port

    command = _build_local_server_command("/tmp/path", "stdio", None)
    assert "--port 0" in command # local command template includes it

    script = _build_sandbox_script("some_command", False, "stdio", None)
    assert "echo MCP_SERVER_PORT=0" not in script # stdio script doesn't echo port

    script = _build_sandbox_script("some_command", False, "http", None)
    assert "echo MCP_SERVER_PORT=0" in script

def test_transport_injection():
    malicious_transport = "http\"; $(touch /tmp/pwned); echo \""
    script = _build_sandbox_script("some_command", False, malicious_transport, 3000)

    quoted = shlex.quote(malicious_transport)
    assert f"echo MCP_TRANSPORT={quoted}" in script
    # Verify no double quotes around it that would allow expansion
    assert f"echo \"MCP_TRANSPORT={quoted}\"" not in script

if __name__ == "__main__":
    test_package_injection()
    test_port_injection()
    test_none_port()
    test_transport_injection()
    print("All tests passed!")
