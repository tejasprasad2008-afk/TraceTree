"""
Simulated MCP client for security analysis.

Supports both stdio and HTTP/SSE transports. Performs the full JSON-RPC 2.0
handshake, discovers tools, generates safe synthetic arguments, and sends
adversarial injection probes to detect vulnerable servers.
"""

import json
import time
import subprocess
import threading
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import requests


class MCPClient:
    """
    Simulated MCP client that connects to an MCP server, performs the
    initialize handshake, discovers tools, invokes them with synthetic
    arguments, and runs adversarial probes.

    Attributes:
        transport: 'stdio' or 'http' — auto-detected if not set.
        host: HTTP host for HTTP/SSE transport.
        port: HTTP port for HTTP/SSE transport.
        command: Shell command to start the server (stdio transport).
        tool_delay: Seconds to wait between tool calls (default 2).
    """

    ADVERSARIAL_PAYLOADS = [
        "; ls /etc",
        "../../../etc/passwd",
        "<script>alert(1)</script>",
    ]

    ZERO_WIDTH_CHARS = ["\u200b", "\u200c", "\u200d", "\ufeff"]

    PROMPT_INJECTION_PATTERNS = [
        "ignore previous instructions",
        "disregard",
        "system:",
        "you are now",
        "ignore all previous",
        "forget all previous",
        "do not follow",
        "override",
    ]

    def __init__(
        self,
        transport: Optional[str] = None,
        host: str = "localhost",
        port: int = 3000,
        command: Optional[str] = None,
        tool_delay: float = 2.0,
    ):
        self.transport = transport
        self.host = host
        self.port = port
        self.command = command
        self.tool_delay = tool_delay

        self._process: Optional[subprocess.Popen] = None
        self._tools: List[Dict[str, Any]] = []
        self._server_info: Dict[str, Any] = {}
        self._call_log: List[Dict[str, Any]] = []
        self._adversarial_log: List[Dict[str, Any]] = []
        self._prompt_injection_findings: List[Dict[str, Any]] = []
        self._initialized = False
        self._next_id = 1

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def connect(self) -> bool:
        """
        Start the MCP server (stdio) or verify HTTP endpoint, then perform
        the full JSON-RPC 2.0 initialize handshake.

        Returns True on success, False on failure.
        """
        if self.transport is None:
            self.transport = self._detect_transport()

        if self.transport == "stdio":
            if not self._start_stdio():
                return False
        else:
            if not self._verify_http():
                return False

        return self._handshake()

    def discover_tools(self) -> List[Dict[str, Any]]:
        """
        Call tools/list and return the discovered tool manifest.
        Also runs a static scan of tool descriptions for prompt injection.
        """
        if not self._initialized:
            return []

        result = self._send_request("tools/list", {})
        raw_tools = result.get("result", {}).get("tools", []) if result else []

        self._tools = raw_tools
        self._scan_tool_manifests(raw_tools)
        return raw_tools

    def invoke_all_tools(self) -> List[Dict[str, Any]]:
        """
        For each discovered tool, generate safe synthetic arguments and
        invoke it.  Records which tool was active at each timestamp.

        Returns a list of call records (tool name, arguments, response,
        timestamp, success).
        """
        if not self._tools:
            self.discover_tools()

        for tool in self._tools:
            tool_name = tool.get("name", "unknown")
            input_schema = tool.get("inputSchema", {})
            safe_args = self._generate_safe_args(input_schema)

            time.sleep(self.tool_delay)
            timestamp = time.time()

            response = self._send_request(
                "tools/call",
                {"name": tool_name, "arguments": safe_args},
            )

            success = response is not None and "error" not in response
            self._call_log.append({
                "tool_name": tool_name,
                "arguments": safe_args,
                "response": response,
                "timestamp": timestamp,
                "success": success,
            })

        return list(self._call_log)

    def run_adversarial_probes(self) -> List[Dict[str, Any]]:
        """
        For each discovered tool, re-invoke it with adversarial arguments
        one at a time.  Records whether the server's behaviour changes.

        Returns a list of probe records.
        """
        if not self._tools:
            self.discover_tools()

        for tool in self._tools:
            tool_name = tool.get("name", "unknown")
            input_schema = tool.get("inputSchema", {})

            for payload in self.ADVERSARIAL_PAYLOADS:
                adversarial_args = self._inject_payload(input_schema, payload)

                time.sleep(self.tool_delay)
                timestamp = time.time()

                response = self._send_request(
                    "tools/call",
                    {"name": tool_name, "arguments": adversarial_args},
                )

                self._adversarial_log.append({
                    "tool_name": tool_name,
                    "payload": payload,
                    "arguments": adversarial_args,
                    "response": response,
                    "timestamp": timestamp,
                    "server_crashed": response is None or (
                        isinstance(response, dict) and "error" in response
                        and response["error"].get("code") == -32603
                    ),
                })

        return list(self._adversarial_log)

    def close(self):
        """Shut down the stdio subprocess if running."""
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception:
                self._process.kill()
            self._process = None

    # ------------------------------------------------------------------ #
    #  Accessors for downstream consumers
    # ------------------------------------------------------------------ #

    @property
    def tools(self) -> List[Dict[str, Any]]:
        return list(self._tools)

    @property
    def server_info(self) -> Dict[str, Any]:
        return dict(self._server_info)

    @property
    def call_log(self) -> List[Dict[str, Any]]:
        return list(self._call_log)

    @property
    def adversarial_log(self) -> List[Dict[str, Any]]:
        return list(self._adversarial_log)

    @property
    def prompt_injection_findings(self) -> List[Dict[str, Any]]:
        return list(self._prompt_injection_findings)

    @property
    def tool_call_timestamps(self) -> List[Tuple[str, float]]:
        """List of (tool_name, timestamp) for attribution of syscalls."""
        return [(r["tool_name"], r["timestamp"]) for r in self._call_log]

    # ------------------------------------------------------------------ #
    #  Private: transport helpers
    # ------------------------------------------------------------------ #

    def _detect_transport(self) -> str:
        """
        Auto-detect: if command is provided, default to stdio.
        If a port is provided, default to http.
        """
        if self.command:
            return "stdio"
        return "http"

    def _start_stdio(self) -> bool:
        if not self.command:
            return False
        try:
            self._process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            return True
        except Exception:
            return False

    def _verify_http(self) -> bool:
        """Check that the HTTP/SSE endpoint is reachable."""
        try:
            resp = requests.get(
                f"http://{self.host}:{self.port}/sse",
                timeout=3,
            )
            return resp.status_code in (200, 202, 405)
        except Exception:
            return False

    def _handshake(self) -> bool:
        """Perform the full MCP initialize handshake."""
        # 1. Send initialize
        init_response = self._send_request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "TraceTree-Scanner",
                    "version": "1.0.0",
                },
            },
        )

        if init_response is None:
            return False

        self._server_info = init_response.get("result", {})

        # 2. Send initialized notification
        self._send_notification("notifications/initialized", {})

        self._initialized = True
        return True

    def _send_request(self, method: str, params: Dict[str, Any]) -> Optional[Dict]:
        """Send a JSON-RPC 2.0 request and return the response dict."""
        message = {
            "jsonrpc": "2.0",
            "id": self._next_id,
            "method": method,
            "params": params,
        }
        self._next_id += 1

        if self.transport == "stdio":
            return self._send_stdio(message)
        else:
            return self._send_http(message)

    def _send_notification(self, method: str, params: Dict[str, Any]):
        """Send a JSON-RPC 2.0 notification (no id, no response expected)."""
        message = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }
        if self.transport == "stdio":
            self._send_stdio(message)
        else:
            self._send_http(message)

    def _send_stdio(self, message: Dict) -> Optional[Dict]:
        """Write JSON-RPC message to stdin and read response from stdout."""
        if not self._process or self._process.stdin is None:
            return None

        body = json.dumps(message)
        header = f"Content-Length: {len(body)}\r\n\r\n"
        try:
            self._process.stdin.write(header + body)
            self._process.stdin.flush()
        except Exception:
            return None

        # Read response with timeout — simple approach: read Content-Length
        # then read body.  This is a best-effort reader.
        try:
            header_line = self._process.stdout.readline()  # Content-Length header
            if not header_line.strip():
                return None
            # Skip blank line separator
            self._process.stdout.readline()
            length = int(header_line.split(":")[1].strip())
            response_body = self._process.stdout.read(length)
            return json.loads(response_body)
        except Exception:
            return None

    def _send_http(self, message: Dict) -> Optional[Dict]:
        """Send JSON-RPC message over HTTP POST to /mcp endpoint."""
        try:
            resp = requests.post(
                f"http://{self.host}:{self.port}/mcp",
                json=message,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if resp.status_code == 200:
                return resp.json()
            return {"error": {"code": resp.status_code, "message": resp.text}}
        except Exception:
            return None

    # ------------------------------------------------------------------ #
    #  Private: synthetic argument generation
    # ------------------------------------------------------------------ #

    def _generate_safe_args(self, input_schema: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate safe synthetic arguments for a tool based on its JSON schema.
        Strings get "test_value", numbers get 0, booleans get false,
        arrays get [], required fields always populated.
        """
        properties = input_schema.get("properties", {})
        required = set(input_schema.get("required", []))
        args: Dict[str, Any] = {}

        for field_name, field_def in properties.items():
            field_type = field_def.get("type", "string")
            args[field_name] = self._safe_value_for_type(field_type, field_def)

        # Ensure required fields exist even if not in properties
        for field_name in required:
            if field_name not in args:
                args[field_name] = "test_value"

        return args

    def _safe_value_for_type(
        self, field_type: str, field_def: Dict[str, Any]
    ) -> Any:
        """Return a safe default for a JSON schema type."""
        if field_type == "string":
            return "test_value"
        elif field_type in ("integer", "number"):
            return 0
        elif field_type == "boolean":
            return False
        elif field_type == "array":
            return []
        elif field_type == "object":
            return {}
        return "test_value"

    def _inject_payload(
        self, input_schema: Dict[str, Any], payload: str
    ) -> Dict[str, Any]:
        """
        Build tool arguments where one string field contains the adversarial
        payload.  Other fields get safe defaults.
        """
        args = self._generate_safe_args(input_schema)
        properties = input_schema.get("properties", {})

        # Inject payload into the first string-typed field
        for field_name, field_def in properties.items():
            if field_def.get("type") == "string":
                args[field_name] = payload
                break

        return args

    # ------------------------------------------------------------------ #
    #  Private: prompt injection static analysis
    # ------------------------------------------------------------------ #

    def _scan_tool_manifests(self, tools: List[Dict[str, Any]]):
        """
        Scan tool names, descriptions, and parameter descriptions for
        zero-width characters, unusual unicode, and prompt injection
        language patterns.
        """
        for tool in tools:
            self._scan_text_field(
                tool.get("name", ""), "tool name", tool.get("name", "")
            )
            self._scan_text_field(
                tool.get("description", ""),
                "tool description",
                tool.get("name", ""),
            )

            input_schema = tool.get("inputSchema", {})
            for field_name, field_def in input_schema.get("properties", {}).items():
                self._scan_text_field(
                    field_def.get("description", ""),
                    f"parameter description ({field_name})",
                    tool.get("name", ""),
                )

    def _scan_text_field(self, text: str, location: str, tool_name: str):
        """Scan a single text string for suspicious patterns."""
        findings: List[str] = []

        # Check zero-width characters
        for char in self.ZERO_WIDTH_CHARS:
            if char in text:
                findings.append(
                    f"Zero-width character U+{ord(char):04X} found in {location}"
                )

        # Check prompt injection language patterns
        text_lower = text.lower()
        for pattern in self.PROMPT_INJECTION_PATTERNS:
            if pattern in text_lower:
                findings.append(
                    f"Prompt injection pattern '{pattern}' found in {location}"
                )

        if findings:
            self._prompt_injection_findings.append({
                "tool_name": tool_name,
                "location": location,
                "findings": findings,
                "text_sample": text[:120] + ("..." if len(text) > 120 else ""),
            })
