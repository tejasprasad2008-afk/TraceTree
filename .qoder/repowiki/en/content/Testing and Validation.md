# Testing and Validation

<cite>
**Referenced Files in This Document**
- [README.md](file://README.md)
- [pyproject.toml](file://pyproject.toml)
- [cli.py](file://cli.py)
- [tests/mcp/test_sandbox_injection.py](file://tests/mcp/test_sandbox_injection.py)
- [mcp/sandbox.py](file://mcp/sandbox.py)
- [mcp/client.py](file://mcp/client.py)
- [mcp/features.py](file://mcp/features.py)
- [mcp/classifier.py](file://mcp/classifier.py)
- [mcp/report.py](file://mcp/report.py)
</cite>

## Table of Contents
1. [Introduction](#introduction)
2. [Project Structure](#project-structure)
3. [Core Components](#core-components)
4. [Architecture Overview](#architecture-overview)
5. [Detailed Component Analysis](#detailed-component-analysis)
6. [Dependency Analysis](#dependency-analysis)
7. [Performance Considerations](#performance-considerations)
8. [Troubleshooting Guide](#troubleshooting-guide)
9. [Conclusion](#conclusion)
10. [Appendices](#appendices)

## Introduction
This document describes TraceTree’s testing framework and validation procedures with a focus on unit testing, integration testing, and security validation for MCP (Model Context Protocol) servers. It explains the test suite organization, MCP security testing approach (injection vulnerability testing, adversarial input validation, and response analysis), testing data management, and guidance for writing custom tests, validating analysis results, and performance benchmarking. It also covers continuous integration patterns and quality assurance procedures to maintain analysis accuracy and reliability.

## Project Structure
TraceTree integrates MCP security analysis into the main CLI pipeline. The MCP workflow is orchestrated by the CLI and validated through targeted unit tests. The MCP module consists of:
- Sandbox orchestration and Docker containerization
- Simulated MCP client for discovery, invocation, and adversarial probing
- Feature extraction from syscall traces
- Rule-based threat classification
- Report generation

```mermaid
graph TB
CLI["CLI (cli.py)"] --> Sandbox["MCP Sandbox (mcp/sandbox.py)"]
CLI --> Client["MCP Client (mcp/client.py)"]
CLI --> Features["Features Extraction (mcp/features.py)"]
CLI --> Classifier["Threat Classifier (mcp/classifier.py)"]
CLI --> Report["Report Generator (mcp/report.py)"]
Tests["Unit Tests (tests/mcp/test_sandbox_injection.py)"] --> Sandbox
Tests --> Client
Tests --> Features
Tests --> Classifier
Tests --> Report
```

**Diagram sources**
- [cli.py:564-744](file://cli.py#L564-L744)
- [mcp/sandbox.py:41-146](file://mcp/sandbox.py#L41-L146)
- [mcp/client.py:18-473](file://mcp/client.py#L18-L473)
- [mcp/features.py:32-206](file://mcp/features.py#L32-L206)
- [mcp/classifier.py:61-96](file://mcp/classifier.py#L61-L96)
- [mcp/report.py:27-74](file://mcp/report.py#L27-L74)
- [tests/mcp/test_sandbox_injection.py:1-57](file://tests/mcp/test_sandbox_injection.py#L1-L57)

**Section sources**
- [README.md:265-305](file://README.md#L265-L305)
- [cli.py:564-744](file://cli.py#L564-L744)

## Core Components
- MCP Sandbox: Builds and runs the MCP server in a Docker container with strace instrumentation, enforcing network isolation and extracting logs.
- MCP Client: Simulates an MCP client to perform JSON-RPC 2.0 handshake, discover tools, invoke them with safe synthetic arguments, and run adversarial probes.
- Features Extraction: Parses strace logs and extracts MCP-specific features grouped by tool-call activity (network, process, filesystem, injection response).
- Threat Classifier: Applies rule-based checks to derive threat categories and compute a risk score.
- Report Generator: Produces Rich console reports and JSON outputs for machine-readable consumption.

**Section sources**
- [mcp/sandbox.py:41-146](file://mcp/sandbox.py#L41-L146)
- [mcp/client.py:18-473](file://mcp/client.py#L18-L473)
- [mcp/features.py:32-206](file://mcp/features.py#L32-L206)
- [mcp/classifier.py:61-96](file://mcp/classifier.py#L61-L96)
- [mcp/report.py:27-74](file://mcp/report.py#L27-L74)

## Architecture Overview
The MCP security analysis pipeline integrates with the main CLI. It orchestrates sandboxing, client simulation, feature extraction, classification, and reporting.

```mermaid
sequenceDiagram
participant User as "User"
participant CLI as "CLI (cli.py)"
participant Sandbox as "MCP Sandbox (mcp/sandbox.py)"
participant Parser as "Strace Parser"
participant Client as "MCP Client (mcp/client.py)"
participant Feat as "Features (mcp/features.py)"
participant Class as "Classifier (mcp/classifier.py)"
participant Rep as "Report (mcp/report.py)"
User->>CLI : "cascade-analyze mcp ..."
CLI->>Sandbox : run_mcp_sandbox(...)
Sandbox-->>CLI : log_path
CLI->>Parser : parse_strace_log(log_path)
Parser-->>CLI : parsed_data
CLI->>Client : connect(), discover_tools(), invoke_all_tools(), run_adversarial_probes()
Client-->>CLI : tools, call_log, adversarial_log, prompt_injection_findings
CLI->>Feat : extract_mcp_features(log_path, call_log, adversarial_log, server_type)
Feat-->>CLI : features
CLI->>Class : classify_mcp_threats(features, findings, adversarial_log, server_type)
Class-->>CLI : threats, risk_score
CLI->>Rep : generate_mcp_report(...)
Rep-->>User : Rich report or JSON
```

**Diagram sources**
- [cli.py:564-744](file://cli.py#L564-L744)
- [mcp/sandbox.py:41-146](file://mcp/sandbox.py#L41-L146)
- [mcp/client.py:78-195](file://mcp/client.py#L78-L195)
- [mcp/features.py:32-206](file://mcp/features.py#L32-L206)
- [mcp/classifier.py:61-96](file://mcp/classifier.py#L61-L96)
- [mcp/report.py:27-74](file://mcp/report.py#L27-L74)

## Detailed Component Analysis

### Unit Tests: MCP Sandbox Injection
The unit test suite validates MCP sandbox command construction and injection protections. It ensures:
- Package name injection is safely quoted in generated commands
- Port injection is rejected with ValueError
- Transport injection is safely quoted in environment variables
- None port handling behaves consistently across transports

```mermaid
flowchart TD
Start(["Test Entry"]) --> BuildNPM["Build NPM command with malicious package"]
BuildNPM --> QuoteCheck["Assert package is quoted in command"]
QuoteCheck --> PortInject["Test port injection with malicious value"]
PortInject --> ValueErr["Expect ValueError for invalid port"]
ValueErr --> NonePort["Test None port handling for stdio vs http"]
NonePort --> TransportInject["Test transport injection with malicious value"]
TransportInject --> TransportQuote["Assert transport is quoted in env var"]
TransportQuote --> End(["Test Exit"])
```

**Diagram sources**
- [tests/mcp/test_sandbox_injection.py:4-50](file://tests/mcp/test_sandbox_injection.py#L4-L50)

**Section sources**
- [tests/mcp/test_sandbox_injection.py:1-57](file://tests/mcp/test_sandbox_injection.py#L1-L57)
- [mcp/sandbox.py:235-271](file://mcp/sandbox.py#L235-L271)

### MCP Client: Adversarial Probing and Safe Argument Generation
The MCP client simulates a JSON-RPC 2.0 client to:
- Auto-detect transport (stdio vs http)
- Perform handshake and tool discovery
- Invoke tools with safe synthetic arguments derived from JSON schemas
- Run adversarial probes with predefined payloads
- Scan tool manifests for prompt injection indicators

```mermaid
classDiagram
class MCPClient {
+connect() bool
+discover_tools() List
+invoke_all_tools() List
+run_adversarial_probes() List
+close() void
-_detect_transport() str
-_start_stdio() bool
-_verify_http() bool
-_handshake() bool
-_send_request(method, params) Dict
-_send_notification(method, params) void
-_send_stdio(message) Dict
-_send_http(message) Dict
-_generate_safe_args(input_schema) Dict
-_safe_value_for_type(field_type, field_def) Any
-_inject_payload(input_schema, payload) Dict
-_scan_tool_manifests(tools) void
-_scan_text_field(text, location, tool_name) void
}
```

**Diagram sources**
- [mcp/client.py:18-473](file://mcp/client.py#L18-L473)

**Section sources**
- [mcp/client.py:78-195](file://mcp/client.py#L78-L195)
- [mcp/client.py:364-418](file://mcp/client.py#L364-L418)
- [mcp/client.py:423-473](file://mcp/client.py#L423-L473)

### MCP Features Extraction: Syscall Trace Analysis
The features extractor parses strace logs and builds MCP-specific features:
- Network behavior: unexpected outbound connections, DNS lookups, per-tool connection counts
- Process behavior: child process spawning, shell invocations, execve targets
- Filesystem behavior: sensitive path reads, outside-working-directory reads
- Injection response: behavior change under adversarial input, shell spawn during injection
- Baseline comparison: deviation from known server type baselines

```mermaid
flowchart TD
Log["Strace Log"] --> Parse["Parse Events"]
Parse --> Timeline["Build Timestamp → Tool Mapping"]
Timeline --> Net["Aggregate Network Features"]
Timeline --> Proc["Aggregate Process Features"]
Timeline --> FS["Aggregate Filesystem Features"]
Net --> Adv["Compute Adversarial Delta"]
Proc --> Adv
FS --> Adv
Adv --> Baseline["Compare to Known Baseline"]
Baseline --> Output["Features Dict"]
```

**Diagram sources**
- [mcp/features.py:109-206](file://mcp/features.py#L109-L206)
- [mcp/features.py:324-473](file://mcp/features.py#L324-L473)

**Section sources**
- [mcp/features.py:32-206](file://mcp/features.py#L32-L206)
- [mcp/features.py:387-422](file://mcp/features.py#L387-L422)

### Threat Classification: Rule-Based MCP Detection
The classifier applies rule-based checks to derive threat categories and compute a risk score:
- COMMAND_INJECTION: shell spawn during injection, behavior change under adversarial input, crashes from probes
- CREDENTIAL_EXFILTRATION: sensitive file access followed by network connections
- COVERT_NETWORK_CALL: unexpected outbound connections and DNS during tool calls
- PATH_TRAVERSAL: reads outside working directory and sensitive path accesses
- EXCESSIVE_PROCESS_SPAWNING: disproportionate child processes relative to tool calls
- PROMPT_INJECTION_VECTOR: zero-width characters and prompt injection language in tool descriptions

```mermaid
flowchart TD
Features["Features"] --> CheckCmd["COMMAND_INJECTION"]
Features --> CheckCred["CREDENTIAL_EXFILTRATION"]
Features --> CheckNet["COVERT_NETWORK_CALL"]
Features --> CheckPath["PATH_TRAVERSAL"]
Features --> CheckSpawn["EXCESSIVE_PROCESS_SPAWNING"]
Findings["Prompt Injection Findings"] --> CheckPrompt["PROMPT_INJECTION_VECTOR"]
CheckCmd --> Threats["Threat List"]
CheckCred --> Threats
CheckNet --> Threats
CheckPath --> Threats
CheckSpawn --> Threats
CheckPrompt --> Threats
Threats --> Score["compute_risk_score()"]
```

**Diagram sources**
- [mcp/classifier.py:61-96](file://mcp/classifier.py#L61-L96)
- [mcp/classifier.py:99-127](file://mcp/classifier.py#L99-L127)
- [mcp/classifier.py:239-268](file://mcp/classifier.py#L239-L268)

**Section sources**
- [mcp/classifier.py:21-58](file://mcp/classifier.py#L21-L58)
- [mcp/classifier.py:99-127](file://mcp/classifier.py#L99-L127)
- [mcp/classifier.py:239-268](file://mcp/classifier.py#L239-L268)

### Report Generation: Structured Output
The report generator produces:
- Tool manifest with descriptions and parameters
- Prompt injection scan results
- Per-tool syscall summaries
- Threat detections with evidence
- Adversarial probe results
- Overall risk score and baseline comparison
- JSON output for automation and CI integration

```mermaid
classDiagram
class ReportGenerator {
+generate_mcp_report(target, server_type, tools, features, threats, prompt_injection_findings, adversarial_log, risk_score, baseline_comparison, is_malicious, ml_confidence, output_format) str
-_generate_json_report(...)
-_generate_rich_report(...)
-_syscall_categories(events) List
}
```

**Diagram sources**
- [mcp/report.py:27-74](file://mcp/report.py#L27-L74)
- [mcp/report.py:76-134](file://mcp/report.py#L76-L134)
- [mcp/report.py:136-302](file://mcp/report.py#L136-L302)

**Section sources**
- [mcp/report.py:27-74](file://mcp/report.py#L27-L74)
- [mcp/report.py:76-134](file://mcp/report.py#L76-L134)
- [mcp/report.py:136-302](file://mcp/report.py#L136-L302)

## Dependency Analysis
The MCP pipeline depends on Docker for sandboxing and strace for syscall tracing. The CLI orchestrates the entire workflow and exposes the MCP subcommand. Unit tests target the MCP components directly to validate security-critical behaviors.

```mermaid
graph TB
Docker["Docker SDK"] --> Sandbox["mcp/sandbox.py"]
Strace["strace binary"] --> Sandbox
CLI["cli.py"] --> Sandbox
CLI --> Client["mcp/client.py"]
CLI --> Features["mcp/features.py"]
CLI --> Classifier["mcp/classifier.py"]
CLI --> Report["mcp/report.py"]
Tests["tests/mcp/test_sandbox_injection.py"] --> Sandbox
Tests --> Client
Tests --> Features
Tests --> Classifier
Tests --> Report
```

**Diagram sources**
- [mcp/sandbox.py:24-28](file://mcp/sandbox.py#L24-L28)
- [cli.py:564-744](file://cli.py#L564-L744)
- [tests/mcp/test_sandbox_injection.py:1-57](file://tests/mcp/test_sandbox_injection.py#L1-L57)

**Section sources**
- [mcp/sandbox.py:24-28](file://mcp/sandbox.py#L24-L28)
- [pyproject.toml:14-24](file://pyproject.toml#L14-L24)

## Performance Considerations
- Timeout control: The MCP sandbox enforces a configurable timeout to prevent runaway containers.
- Container resource constraints: The sandbox drops network and runs with non-root privileges to reduce overhead and risk.
- strace filtering: The MCP pipeline focuses on a curated set of syscalls to balance completeness and performance.
- JSON-RPC I/O: The MCP client uses buffered I/O and timeouts to avoid blocking on network or stdio transport.

[No sources needed since this section provides general guidance]

## Troubleshooting Guide
Common issues and resolutions:
- Docker not installed or unreachable: The CLI performs a preflight check and instructs users to install/start Docker.
- Sandbox fails to produce logs: The MCP workflow aborts early if no strace log is found.
- MCP client cannot connect: In stdio mode, connection failures are expected; analysis proceeds using strace features only.
- Port injection validation: Invalid ports raise ValueError to prevent command injection.
- Transport injection protection: Transport values are safely quoted in environment variables.

**Section sources**
- [cli.py:74-111](file://cli.py#L74-L111)
- [cli.py:631-636](file://cli.py#L631-L636)
- [cli.py:689-691](file://cli.py#L689-L691)
- [tests/mcp/test_sandbox_injection.py:14-27](file://tests/mcp/test_sandbox_injection.py#L14-L27)
- [tests/mcp/test_sandbox_injection.py:42-49](file://tests/mcp/test_sandbox_injection.py#L42-L49)

## Conclusion
TraceTree’s MCP testing framework combines unit tests for security-critical command construction, integration tests through the CLI pipeline, and robust security validation via adversarial probing and rule-based classification. The modular design enables targeted testing and reliable validation of MCP server behavior, supporting continuous integration and quality assurance workflows.

[No sources needed since this section summarizes without analyzing specific files]

## Appendices

### Writing Custom Tests
Guidance for extending the MCP test suite:
- Use the existing unit test pattern to validate command construction and injection protections.
- Add tests for new MCP client behaviors (e.g., additional JSON-RPC methods, transport modes).
- Extend feature extraction tests to cover new syscall categories or server types.
- Add adversarial probe coverage for additional payload types or prompt injection patterns.
- Include JSON report validation for machine-readable output consistency.

**Section sources**
- [tests/mcp/test_sandbox_injection.py:1-57](file://tests/mcp/test_sandbox_injection.py#L1-L57)
- [mcp/client.py:32-49](file://mcp/client.py#L32-L49)
- [mcp/features.py:387-422](file://mcp/features.py#L387-L422)

### Validating Analysis Results
Validation steps:
- Confirm strace logs are produced and parsable.
- Verify MCP client successfully connects and discovers tools.
- Ensure adversarial probes are sent and recorded.
- Review threat classifications and risk scores for plausibility.
- Validate report output (console and JSON) includes expected sections.

**Section sources**
- [cli.py:646-652](file://cli.py#L646-L652)
- [cli.py:674-691](file://cli.py#L674-L691)
- [mcp/report.py:27-74](file://mcp/report.py#L27-L74)

### Performance Benchmarking
Benchmarking recommendations:
- Measure end-to-end MCP analysis duration across different server types and transports.
- Track container startup time, sandbox runtime, and report generation latency.
- Monitor strace parsing throughput and feature extraction time.
- Compare risk scoring and classification latency for large tool manifests.

[No sources needed since this section provides general guidance]

### Continuous Integration Patterns
Recommended CI practices:
- Run unit tests for MCP components on every pull request.
- Execute the MCP CLI subcommand in a Docker-enabled environment to validate sandboxing and reporting.
- Store and compare JSON reports for regression detection.
- Integrate SARIF export for security tooling compatibility.

**Section sources**
- [README.md:265-305](file://README.md#L265-L305)
- [cli.py:564-744](file://cli.py#L564-L744)
- [mcp/report.py:61-73](file://mcp/report.py#L61-L73)