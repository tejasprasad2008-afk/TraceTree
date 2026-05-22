"""
TraceTree Assistive AI Mesh Orchestrator (orchestrator/ai_mesh.py)

This module handles the AI-native orchestration for Qwen 2.5 Coder 7B.
It compresses deterministic data pipelines (syscall traces, graph vectors, signatures,
and adversarial payloads) into highly compressed text chunks, invokes the local Ollama
instance in JSON mode, and renders beautiful visual panels for the security analyst.
"""

import os
import json
import requests
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.style import Style

log = logging.getLogger("tracetree.ai_mesh")
console = Console()

# Configure Ollama endpoint
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_GENERATE_URL = f"{OLLAMA_HOST}/api/generate"
MODEL_NAME = "qwen2.5-coder:7b"

class AIMeshOrchestrator:
    """
    Orchestrates the chunking, formatting, and calling of Qwen 2.5 Coder 7B
    across the 8 legs of TraceTree.
    """

    def __init__(self, ollama_url: str = OLLAMA_GENERATE_URL, model: str = MODEL_NAME):
        self.ollama_url = ollama_url
        self.model = model

    def _clean_and_parse_json(self, raw_text: str) -> Optional[Dict[str, Any]]:
        """Cleans and parses JSON from the LLM, handling raw newlines inside string literals."""
        try:
            return json.loads(raw_text)
        except json.JSONDecodeError:
            # Try to sanitize raw unescaped newlines inside JSON string values.
            # We look for text between double quotes and replace raw newlines with escaped \n.
            import re
            def replacer(match):
                s = match.group(0)
                # Replace literal newlines and carriage returns with escaped counterparts
                s_escaped = s.replace('\n', '\\n').replace('\r', '\\r')
                return s_escaped

            # Find all double-quoted strings and escape raw newlines within them
            sanitized = re.sub(r'"(?:[^"\\]|\\.)*"', replacer, raw_text, flags=re.DOTALL)
            try:
                return json.loads(sanitized)
            except Exception as e:
                log.error(f"Failed to parse sanitized JSON: {e}. Raw: {raw_text}")
                return None

    def _invoke_llm(self, prompt: str) -> Optional[Dict[str, Any]]:
        """Utility to invoke Ollama with Qwen 2.5 Coder forcing JSON output."""
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {
                    "temperature": 0.0,
                    "num_predict": 1024
                }
            }
            response = requests.post(self.ollama_url, json=payload, timeout=60)
            if response.status_code == 200:
                raw_text = response.json().get("response", "{}")
                return self._clean_and_parse_json(raw_text)
            else:
                log.error(f"Ollama returned error status: {response.status_code}")
                return None
        except Exception as e:
            log.error(f"Ollama invocation failed: {e}")
            return None

    # =========================================================================
    # LEGS 1 & 2: Sandbox Isolation & Syscall Parsing (Log Simplifier Chunk)
    # =========================================================================
    def simplify_syscall_log(self, parsed_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Compresses a verbose syscall stream into a small, high-severity subset
        and asks Qwen to explain the execution chain.
        """
        # Deterministically filter for high-severity events (severity >= 6)
        important_events = [
            e for e in parsed_events 
            if e.get("severity", 0) >= 6 or e.get("type") in ("connect", "execve", "mprotect")
        ]
        
        # Aggregate counts by syscall type
        summary_counts = {}
        for e in parsed_events:
            t = e.get("type", "unknown")
            summary_counts[t] = summary_counts.get(t, 0) + 1

        # Keep only the first 15 critical sequences to save context window tokens
        compact_sequences = []
        for e in important_events[:15]:
            compact_sequences.append({
                "pid": e.get("pid"),
                "syscall": e.get("type"),
                "target": e.get("target"),
                "details": e.get("details", {})
            })

        system_prompt = (
            "You are a Forensic Syscall Analyst. Parse the high-severity syscall trace chunk.\n"
            "Identify the operational intent (e.g. process spawning, writing to system paths, exfiltrating info).\n"
            "Return a clean explanation of what the process attempted to do.\n"
            "Format your response EXACTLY as a JSON object matching this schema:\n"
            "{\n"
            "  \"is_suspicious\": boolean,\n"
            "  \"explanation\": \"natural language summary of what the syscalls represent\",\n"
            "  \"urgency\": \"LOW\" | \"MEDIUM\" | \"HIGH\" | \"CRITICAL\"\n"
            "}"
        )

        user_content = {
            "syscall_distribution": summary_counts,
            "critical_sequence": compact_sequences
        }

        prompt = f"{system_prompt}\n\n### Syscall Data:\n{json.dumps(user_content, indent=2)}"
        return self._invoke_llm(prompt) or {
            "is_suspicious": False,
            "explanation": "Deterministic fallback: No LLM response.",
            "urgency": "LOW"
        }

    # =========================================================================
    # LEGS 3 & 4: Behavioral Graphing & ML Anomaly Detection (Vector Descriptor)
    # =========================================================================
    def describe_feature_vector(self, feature_vector: Dict[str, Any]) -> Dict[str, Any]:
        """
        Takes the 10-sensor numeric vector generated by TraceTree's ML pipeline
        and explains why the ML model categorized it based on numbers alone.
        """
        # Format the 10 sensors into a clean text descriptor
        sensor_names = [
            "node_count", "edge_count", "network_connections", "file_reads",
            "execve_count", "total_severity", "suspicious_networks",
            "sensitive_files", "max_severity", "temporal_pattern_count"
        ]
        
        vector_str = ", ".join(f"{name}: {feature_vector.get(name, 0)}" for name in sensor_names)

        system_prompt = (
            "You are a Machine Learning Threat Contextualizer.\n"
            "You are given the 10-sensor behavioral feature vector used by TraceTree's Random Forest classifier.\n"
            "Compare the provided sensor counts against typical malware vs. benign baseline statistics:\n"
            "- Malware: High executables (execve), network connections, sensitive file reads, high max severity.\n"
            "- Benign: High node/edge count, but zero suspicious networks and zero sensitive file reads.\n"
            "Return a JSON response conforming to this schema:\n"
            "{\n"
            "  \"prediction_validation\": \"explanation of why these numbers flag or clear the package\",\n"
            "  \"suspected_threat_vector\": \"e.g., typosquatting exfiltration, container escape, or benign installer\",\n"
            "  \"risk_multiplier\": number (1.0 to 3.0 scale matching structural risk)\n"
            "}"
        )

        prompt = f"{system_prompt}\n\n### Feature Vector sensors:\n[{vector_str}]"
        return self._invoke_llm(prompt) or {
            "prediction_validation": "Fallback descriptor active.",
            "suspected_threat_vector": "UNKNOWN",
            "risk_multiplier": 1.0
        }

    # =========================================================================
    # LEGS 5 & 8: YARA Signatures & Temporal Sequences (False Positive Juror)
    # =========================================================================
    def triage_false_positive(self, matched_rule: Dict[str, Any], package_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Acts as a False Positive Juror. Evaluates triggered alerts against
        baseline context and triages false alarms using rules configured in data/ai_triage_rules.json.
        """
        # Load local heuristics
        heuristics_data = {}
        rules_path = Path(__file__).parent.parent / "data" / "ai_triage_rules.json"
        if rules_path.exists():
            try:
                with open(rules_path, "r") as f:
                    heuristics_data = json.load(f)
            except Exception:
                pass

        system_prompt = (
            "You are a False Positive Juror. Your objective is to check if a security alert is a false positive.\n"
            "You will be given the matched security pattern, package metadata, and standard triage heuristics.\n"
            "Assess the context. For example, if a package manager loads a .npmrc and connects to npm registry,\n"
            "or a database library reads local credentials and connects to local db port, it is benign.\n"
            "Return a JSON response conforming to this schema:\n"
            "{\n"
            "  \"verdict\": \"FALSE_POSITIVE\" | \"SUSPICIOUS\",\n"
            "  \"confidence\": float (0.0 to 1.0),\n"
            "  \"mitigation_applied\": boolean,\n"
            "  \"reasoning\": \"detailed explanation of the context analysis\"\n"
            "}"
        )

        user_content = {
            "matched_pattern": matched_rule,
            "package_metadata": package_metadata,
            "triage_baselines": heuristics_data.get("exception_rules", [])
        }

        prompt = f"{system_prompt}\n\n### Triage Context:\n{json.dumps(user_content, indent=2)}"
        return self._invoke_llm(prompt) or {
            "verdict": "SUSPICIOUS",
            "confidence": 0.5,
            "mitigation_applied": False,
            "reasoning": "Failed to invoke local AI juror."
        }

    # =========================================================================
    # LEGS 6 & 7: MCP Security & Security Guardian (Adversarial Explainer)
    # =========================================================================
    def explain_mcp_remediation(self, vulnerable_schema: Dict[str, Any], failing_payload: str) -> Dict[str, Any]:
        """
        Isolates the vulnerability in a Model Context Protocol tool schema and
        provides immediate, sanitized python remediation code.
        """
        system_prompt = (
            "You are an Application Security Refactoring Agent.\n"
            "An adversarial client probe triggered a security warning in a Model Context Protocol (MCP) tool.\n"
            "You are given the vulnerable tool definition schema and the failing injection payload.\n"
            "Draft a sanitized Python function implementing this tool. Validate the parameters using regex or\n"
            "strict path checks to block Command Injection (e.g. shell metacharacters like ;) and Path Traversal (../).\n"
            "Ensure that any code returned inside the JSON string escapes all newlines as '\\n' and does NOT contain\n"
            "literal raw unescaped multi-line linebreaks, to ensure valid JSON parsing.\n"
            "Return a JSON response conforming to this schema:\n"
            "{\n"
            "  \"vulnerability_type\": \"COMMAND_INJECTION\" | \"PATH_TRAVERSAL\",\n"
            "  \"remediation_code\": \"def view_file(path):\\n    # Safe code here\",\n"
            "  \"best_practices\": [\"list of secure coding best practices applied\"]\n"
            "}"
        )

        user_content = {
            "vulnerable_schema": vulnerable_schema,
            "failing_payload": failing_payload
        }

        prompt = f"{system_prompt}\n\n### Vulnerability Context:\n{json.dumps(user_content, indent=2)}"
        return self._invoke_llm(prompt) or {
            "vulnerability_type": "COMMAND_INJECTION",
            "remediation_code": "# Fallback: Ensure path uses os.path.basename and escapes shell execution.",
            "best_practices": ["Sanitize all input", "Avoid shell=True"]
        }


# =============================================================================
# Developer UI Panel Rendering (surfacing back to analyst console)
# =============================================================================
def render_ai_triage_panel(leg_name: str, results: Dict[str, Any]):
    """Renders a beautiful Rich Panel output for terminal displays."""
    title = f"[bold yellow]🧠 Assistive AI Leg Check - {leg_name}[/]"
    
    if leg_name in ("Legs 1 & 2: Syscall Simplifier", "Syscall Parser"):
        content_table = Table(show_header=False, box=None)
        content_table.add_column("Key", style="bold cyan")
        content_table.add_column("Value")
        
        is_susp = results.get("is_suspicious", False)
        status_color = "red" if is_susp else "green"
        status_text = "[bold red]SUSPICIOUS[/]" if is_susp else "[bold green]SAFE[/]"
        
        content_table.add_row("Verdict Status", status_text)
        content_table.add_row("Urgency Level", f"[{status_color}]{results.get('urgency', 'LOW')}[/]")
        content_table.add_row("Analysis Summary", results.get("explanation", ""))
        
        console.print(Panel(
            content_table,
            title=title,
            border_style=status_color,
            expand=False
        ))

    elif leg_name in ("Legs 3 & 4: Anomaly Feature Vector", "ML Detector"):
        content_table = Table(show_header=False, box=None)
        content_table.add_column("Key", style="bold cyan")
        content_table.add_column("Value")
        
        content_table.add_row("Validation", results.get("prediction_validation", ""))
        content_table.add_row("Suspected Threat", results.get("suspected_threat_vector", ""))
        content_table.add_row("Risk Scale Multiplier", f"[yellow]{results.get('risk_multiplier', 1.0)}x[/]")
        
        console.print(Panel(
            content_table,
            title=title,
            border_style="magenta",
            expand=False
        ))

    elif leg_name in ("Legs 5 & 8: False Positive Jury", "FP Juror"):
        verdict = results.get("verdict", "SUSPICIOUS")
        border = "green" if verdict == "FALSE_POSITIVE" else "red"
        
        content_table = Table(show_header=False, box=None)
        content_table.add_column("Key", style="bold cyan")
        content_table.add_column("Value")
        
        content_table.add_row("Jury Verdict", f"[bold {border}]{verdict}[/]")
        content_table.add_row("Confidence Score", f"{results.get('confidence', 0.0) * 100:.1f}%")
        content_table.add_row("Exception Mitigated", "Yes" if results.get("mitigation_applied") else "No")
        content_table.add_row("Reasoning", results.get("reasoning", ""))
        
        console.print(Panel(
            content_table,
            title=title,
            border_style=border,
            expand=False
        ))

    elif leg_name in ("Legs 6 & 7: MCP Security Remediation", "MCP Explainer"):
        content_table = Table(show_header=False, box=None)
        content_table.add_column("Key", style="bold cyan")
        content_table.add_column("Value")
        
        content_table.add_row("Vulnerability Class", f"[bold red]{results.get('vulnerability_type', 'COMMAND_INJECTION')}[/]")
        
        # Format code snippet nicely
        remediation_code = results.get("remediation_code", "")
        code_display = f"\n[dim white]```python\n{remediation_code}\n```[/]"
        content_table.add_row("Suggested Remediation", code_display)
        
        bp_list = "\n".join(f"• {bp}" for bp in results.get("best_practices", []))
        content_table.add_row("Secure Coding Guidelines", bp_list)
        
        console.print(Panel(
            content_table,
            title=title,
            border_style="yellow",
            expand=False
        ))
