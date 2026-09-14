# Adaptive npm execution status

## Current phase

Phase 3 (in progress) — hardened import-only execution and native coverage.

## Completed

- Isolated subsystem charter and safety invariants.
- Content-addressed tarball storage with safe extraction policy.
- HTTPS-only npm registry broker for names plus exact versions/dist-tags; it
  streams and verifies npm's sha512 integrity before storage and never invokes
  npm on the host. It resolves bounded common semver ranges for runtime
  dependencies.
- Static CJS/ESM entrypoint and export mapping with explicit unsupported states.
- Versioned environment profiles and validated declarative harness plans.
- Offline V8 coverage normalisation compared with the static package map.
- Per-run `node-library-v1` and `developer-workstation-v1` synthetic profiles
  with generated canaries and output redaction.
- Per-run scenario profiles for CI runners, cloud services, and commerce
  clients. Each supplies only synthetic files, event/request fixtures, and
  generated canaries; all remain offline and Node-compatible.
- Fresh adaptive import runner contract: non-root user, no network, no host
  bind mounts, read-only root filesystem, dropped capabilities, process/CPU/
  memory limits, `strace`, and native V8 coverage.
- Docker-managed input/evidence volumes: a short-lived no-network loader
  materialises each immutable input, the target mounts it read-only, and both
  volumes are removed after the attempt.
- Validated declarative harnesses now run in the same hardened, fresh-container
  path; the renderer resolves only static-map entrypoint paths inside the
  immutable package directory.
- High-level adaptive orchestration now preserves artifact identity through the
  static map, fresh import attempt, native coverage, and deterministic trace
  evidence. It deliberately reports unresolved paths instead of a blanket
  clean verdict.
- Deterministic post-import policy gate: static/behavioral suspicion can
  produce a reviewable, profile-bound declarative harness plan; clean baseline
  results stop after import and retain uncovered exports as unresolved. The
  AI-planner input is an allowlisted JSON context, and any future proposal
  remains subject to the existing plan validator and profile gate.
- Adaptive receipt export: preserves immutable artifact identity, per-attempt
  coverage/behavior summaries, artifact hashes, the gate/plan decision, and
  privacy metadata without including raw logs, package source, fake values, or
  rendered harness code. A baseline-only result is **inconclusive**, never
  automatically clean.
- Receipts include a combined V8 coverage view across fresh import and harness
  attempts, while retaining each attempt separately. This is export coverage,
  not a claim of complete branch or environment coverage.
- A completed harness attempt now produces a first-class adaptive execution
  result. Its merged coverage removes only the exports actually exercised from
  the unresolved set; unsupported paths and all remaining gaps stay visible.
- Provider-agnostic model-planner adapter: a future model integration receives
  only the compact planner context and must return a <=16 KiB JSON plan. It has
  no access to source, raw traces, synthetic values, shell commands, paths, or
  execution authority; its plan is revalidated against the gate and schema.
- Concrete model adapters: Ollama is local-only by default and uses its JSON
  schema chat mode; OpenRouter is an explicit opt-in and uses strict structured
  output. Both receive the same bounded context and cannot auto-execute a
  returned plan.
- Planner responses get at most one repair pass after malformed JSON or a
  validation failure. Only the generic validator feedback is returned to the
  model; a second invalid response stops the workflow.
- Bounded runtime dependency closure: production dependencies and optional
  dependencies are fetched as independently verified tarballs, placed at
  explicit `node_modules` paths in the read-only input tree, and never passed
  through `npm install` or lifecycle scripts.
- Real Docker smoke test passes with a harmless local fixture: ESM import and
  CommonJS require, a synthetic developer canary, redaction, syscall trace,
  V8 coverage, and a validated harness call.

## Next

- Pin the Node base image digest in the Dockerfile and run the Docker smoke
  test in CI.
- Migrate the legacy pipeline to the new pure trace-analysis adapter without
  changing its existing verdict semantics.
- Add registry-cache and dependency-closure provenance retention suitable for
  larger dependency graphs and CI use.
- Add explicit CLI/UI review and opt-in execution of a gate-selected harness;
  only then configure a model provider for the constrained planner adapter.

## Current MVP limits

- Node-compatible JavaScript libraries only: browser, CLI, native-addon, and
  source-only TypeScript paths stay explicitly unresolved.
- The commerce profile is not a browser emulator: DOM events, visual clicks,
  and real payment flows remain unresolved until a separately hardened browser
  execution profile is designed.
- Runtime dependencies use a bounded nested `node_modules` tree (depth 5,
  100 packages) without lifecycle scripts. Peer, dev, git, file, workspace,
  alias, and unsupported semver dependencies remain explicit unresolved paths.
- The harness accepts only validated direct calls to statically mapped exports.
  Planner-generated JavaScript, shell, paths, environment variables, and
  network privileges are not supported.
- A generated harness plan is not auto-executed: it must be reviewed and
  explicitly passed to the fresh-sandbox execution boundary.

## Opt-in local command

Build the dedicated Node 24 LTS image first (with a digest-pinned Node base in
production):

```sh
docker build -f sandbox/Dockerfile.adaptive -t tracetree-adaptive-node:latest sandbox
```

Then use the new, separate experimental command. It does not replace the
legacy install-time scanner:

```sh
cascade-adaptive-npm scan example-package@1.2.3
```

Use `--run-harness` only after reviewing the returned gate and plan. It runs
the already-authorized plan in a **second fresh** sandbox; it never reuses the
import container. If no plan was authorized, the receipt records that it was
not executed.

To request a model-authored plan explicitly, choose the provider. A model plan
is still schema- and gate-validated; adding `--run-harness` executes that
validated plan in a new sandbox.

```sh
cascade-adaptive-npm scan example-package@1.2.3 --planner ollama
cascade-adaptive-npm scan example-package@1.2.3 --planner openrouter --run-harness
```

Ollama defaults to the local `qwen2.5-coder:7b` model and does not use a key.
OpenRouter reads `OPENROUTER_API_KEY` only at runtime. Neither provider is
contacted unless `--planner` is supplied.

Use `--static-only` to fetch, verify, content-address, and source-map a
tarball without dynamic execution.

The Docker smoke test is intentionally opt-in:

```sh
TRACETREE_RUN_DOCKER_INTEGRATION=1 pytest -m integration tests/npm_adaptive/test_docker_integration.py
```
