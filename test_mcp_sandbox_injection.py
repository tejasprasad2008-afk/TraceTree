from mcp.sandbox import _build_npm_server_command, _build_local_server_command
import shlex

def test_package_injection():
    malicious_input = "; touch /tmp/pwned"
    command = _build_npm_server_command(malicious_input, "stdio", 3000)
    print(f"Generated command: {command}")

    quoted = shlex.quote(malicious_input)
    assert quoted in command
    # shlex.quote('; touch /tmp/pwned') -> "'; touch /tmp/pwned'"
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

if __name__ == "__main__":
    test_package_injection()
    test_port_injection()
    print("All tests passed!")
