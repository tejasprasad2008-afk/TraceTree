# Sentinel Journal - Critical Security Learnings

## 2025-05-14 - [Command Injection and Path Traversal in Sandbox]
**Vulnerability:** The `target` parameter in `run_sandbox` was directly interpolated into a shell script executed by the Docker container, and also used in constructing local file paths.
**Learning:** External inputs should always be sanitized before being used in shell commands or file operations, even if they are intended to be package names or file paths.
**Prevention:** Use `shlex.quote()` for shell command interpolation and `Path(target).name` to ensure only the filename is used for local path construction.
