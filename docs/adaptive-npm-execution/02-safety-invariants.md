# Safety invariants

1. Every static and dynamic result references an immutable artifact SHA-256.
2. Every import or harness attempt runs in a new sandbox.
3. Adaptive execution never uses TraceTree direct mode.
4. The planner returns validated data, never executable source code.
5. Environment profiles contain synthetic values only.
6. Raw traces and synthetic secret values never enter LLM context by default.
7. Uncovered, unsupported, and failed paths remain visible in the result.
8. Synthetic canaries are redacted from persisted logs before session storage.
9. Adaptive package code runs as an unprivileged user with no network, no host
   bind mounts, no Linux capabilities, a read-only root filesystem, and bounded
   CPU, memory, process, and temporary-storage limits. A fresh Docker-managed
   volume is filled only by a short-lived no-network loader, then mounted
   read-only into the execution container; the package never sees it writable.
   A separate fresh evidence volume is writable only at `/out` and is deleted
   immediately after extraction and canary redaction. Its initializer has only
   `CHOWN` and `FOWNER`, never receives package bytes, and exits before the
   package container starts.
