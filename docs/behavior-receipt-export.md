# Behavior receipt export

TraceTree already produces the hard part: sandboxed runtime evidence for what a package, binary, or MCP server actually did. A small receipt export makes that evidence easier to attach to CI, pull requests, package-review tickets, and agent permission decisions without copying raw `strace` logs or secrets into chat.

## Boundary to prove

A behavior receipt should answer one narrow question:

> Which target was executed, in which sandbox policy, what behavior was observed, and why was the final verdict accepted or escalated?

Keep the full trace artifacts local or in the CI artifact store. The receipt should carry hashes, coarse counts, and the evidence needed for review.

```json
{
  "schema": "tracetree.behavior_receipt.v1",
  "run_id": "tracetree-2026-07-05T12:00:00Z",
  "target": {
    "type": "npm",
    "name": "example-package",
    "version": "1.2.3",
    "source": "package-lock",
    "artifact_sha256": "sha256:..."
  },
  "sandbox": {
    "mode": "docker-strace",
    "network_policy": "blocked-after-fetch",
    "timeout_seconds": 30,
    "image_digest": "sha256:..."
  },
  "artifacts": {
    "strace_log_sha256": "sha256:...",
    "graph_sha256": "sha256:...",
    "sarif_sha256": "sha256:..."
  },
  "observed_behavior": {
    "process_count": 4,
    "file_write_count": 2,
    "external_connect_count": 0,
    "sensitive_file_read_count": 0,
    "matched_signatures": [],
    "matched_temporal_patterns": []
  },
  "verdict": {
    "decision": "clean",
    "confidence": 0.723,
    "reason": "no suspicious footprints flagged",
    "review_required": false
  },
  "privacy": {
    "raw_syscalls_included": false,
    "environment_values_included": false,
    "secrets_included": false
  }
}
```

## CI / agent use

Use the receipt as the object an agent or reviewer can safely read before deciding what to do next:

- allow dependency update when `decision=clean` and artifact hashes match the current lockfile;
- request human review when confidence is low, signatures match, or sandbox policy was weakened;
- block automatic install when the receipt is missing, stale, or for a different package artifact;
- attach the receipt to a PR while keeping raw traces out of the model-visible conversation.

## Suggested invariants

1. The target artifact hash must match the lockfile or downloaded artifact being reviewed.
2. Sandbox policy must be explicit; `network_policy`, timeout, and image digest are part of the evidence.
3. Raw logs stay out of the receipt by default; include artifact hashes and storage pointers instead.
4. A clean verdict is not portable across package versions, lockfile changes, sandbox-image changes, or weakened policies.
5. Any suspicious signature, temporal pattern, external connection after a sensitive read, or missing artifact hash should downgrade to `review_required`.
