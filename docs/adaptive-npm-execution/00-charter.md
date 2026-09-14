# Adaptive npm execution engine

## Goal

Increase evidence coverage for npm packages whose behavior is hidden behind
public APIs, while preserving TraceTree's existing install-time scan.

## MVP boundary

The first vertical slice supports Node-compatible JavaScript libraries only:
immutable artifact storage, bounded verified runtime dependency closure, static
package mapping, import probes, constrained function-call plans, native V8
coverage, and fresh Docker sandboxes.

## Non-goals

- A universal clean/malicious score.
- Arbitrary AI-generated code or shell commands.
- Real credentials, user data, or outbound Internet access.
- Browser, cloud, CI, native-addon, or cross-platform simulation in the MVP.
- Dev, peer, git, file, workspace, or package-alias dependency installation.
