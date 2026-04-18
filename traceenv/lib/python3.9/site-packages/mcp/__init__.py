"""
MCP (Model Context Protocol) Server Security Analysis module.

Extends TraceTree's runtime behavioral analysis pipeline to cover
MCP servers — detecting command injection, credential exfiltration,
covert network calls, path traversal, and prompt injection vectors.
"""

from .client import MCPClient
from .sandbox import run_mcp_sandbox
from .features import extract_mcp_features
from .classifier import classify_mcp_threats
from .report import generate_mcp_report

__all__ = [
    "MCPClient",
    "run_mcp_sandbox",
    "extract_mcp_features",
    "classify_mcp_threats",
    "generate_mcp_report",
]
