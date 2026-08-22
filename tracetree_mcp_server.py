import sys
import json
import logging
import traceback
from typing import Dict, Any
from monitor.parser import parse_strace_log
from monitor.signatures import load_signatures, match_signatures
from monitor.yara import scan_with_yara

# Configure logging to stderr (since stdout is used for JSON-RPC)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("tracetree-mcp")

def send_response(response: Dict[str, Any]):
    """Send JSON-RPC response to stdout."""
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()

def handle_request(request: Dict[str, Any]):
    """Handle incoming JSON-RPC request."""
    method = request.get("method")
    params = request.get("params", {})
    req_id = request.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {
                        "listChanged": False
                    }
                },
                "serverInfo": {
                    "name": "tracetree-native-mcp",
                    "version": "1.0.0"
                }
            }
        }

    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "analyze_strace",
                        "description": "Analyze a strace log for malicious behavior using TraceTree signatures and YARA rules.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "log_path": {
                                    "type": "string",
                                    "description": "Absolute path to the strace log file."
                                },
                                "pkg_path": {
                                    "type": "string",
                                    "description": "Absolute path to the extracted package directory (for YARA scanning)."
                                }
                            },
                            "required": ["log_path", "pkg_path"]
                        }
                    }
                ]
            }
        }

    elif method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if tool_name == "analyze_strace":
            log_path = arguments.get("log_path")
            pkg_path = arguments.get("pkg_path")

            if not log_path or not pkg_path:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "Missing log_path or pkg_path"}
                }

            try:
                # 1. Parse strace log
                parsed_data = parse_strace_log(log_path)
                
                # 2. Match behavioral signatures
                signatures = load_signatures()
                signature_matches = match_signatures(parsed_data, signatures)
                
                # 3. Run YARA scans
                yara_matches = scan_with_yara(log_path, pkg_path)

                # Combine results
                report = {
                    "verdict": "MALICIOUS" if (signature_matches or yara_matches) else "BENIGN",
                    "total_severity": parsed_data.get("total_severity_score", 0),
                    "signature_matches": signature_matches,
                    "yara_matches": yara_matches,
                    "flags": parsed_data.get("flags", []),
                    "network_destinations": parsed_data.get("network_destinations", [])
                }

                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(report, indent=2)
                            }
                        ]
                    }
                }
            except Exception as e:
                logger.error(f"Error in analyze_strace: {str(e)}\n{traceback.format_exc()}")
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32603, "message": str(e)}
                }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"}
    }

def main():
    """Main loop for stdio JSON-RPC."""
    logger.info("TraceTree Native MCP Server started")
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            request = json.loads(line)
            response = handle_request(request)
            send_response(response)
        except json.JSONDecodeError:
            logger.error(f"Failed to decode JSON: {line}")
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    main()
