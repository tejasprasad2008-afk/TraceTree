"""
TraceTree Assistive AI Mesh Orchestrator (orchestrator/ai_mesh.py)

This module handles the AI-native orchestration for Qwen 2.5 Coder 7B.
It compresses deterministic data pipelines (syscall traces, graph vectors, signatures,
and adversarial payloads) into highly compressed text chunks, invokes the local Ollama
instance in JSON mode, and renders beautiful visual panels for the security analyst.
"""

import os
import json
import random
import time
import requests
import logging
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

log = logging.getLogger("tracetree.ai_mesh")
console = Console()

# Configure Ollama endpoint
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
if not OLLAMA_HOST.startswith("http://") and not OLLAMA_HOST.startswith("https://"):
    OLLAMA_HOST = f"http://{OLLAMA_HOST}"
OLLAMA_GENERATE_URL = f"{OLLAMA_HOST}/api/generate"
MODEL_NAME = "qwen2.5-coder:7b"

class AIConnectionRefusedError(Exception):
    """Raised when the Ollama API connection is refused or offline."""
    pass

class AIBadResponseError(Exception):
    """Raised when Ollama returns an error code or invalid/unparsable JSON."""
    pass


@dataclass
class TriageResult:
    """Typed schema for the AI False Positive Jury verdict.
    Replaces raw dict passing, making the contract explicit.
    """
    verdict: str          # "FALSE_POSITIVE" | "SUSPICIOUS"
    confidence: float     # 0.0 to 1.0
    mitigation_applied: bool
    reasoning: str

    @classmethod
    def from_dict(cls, data: dict) -> "TriageResult":
        """Construct from LLM-returned dict with safe defaults."""
        return cls(
            verdict=str(data.get("verdict", "SUSPICIOUS")),
            confidence=float(data.get("confidence", 0.5)),
            mitigation_applied=bool(data.get("mitigation_applied", False)),
            reasoning=str(data.get("reasoning", "No reasoning provided")),
        )

    def is_false_positive(self) -> bool:
        return self.verdict == "FALSE_POSITIVE"


class AIMeshOrchestrator:
    """
    Orchestrates the chunking, formatting, and calling of Qwen 2.5 Coder 7B
    across the 8 legs of TraceTree.
    """

    def __init__(self, ollama_url: str = OLLAMA_GENERATE_URL, model: str = MODEL_NAME, dry_run: bool = False, verbose: bool = False):
        if not ollama_url.startswith("http://") and not ollama_url.startswith("https://"):
            ollama_url = f"http://{ollama_url}"
        self.ollama_url = ollama_url
        self.model = model
        self.dry_run = dry_run
        self.verbose = verbose

    def check_connection_health(self) -> bool:
        """Performs a ping or head request to http://localhost:11434/api/tags."""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(self.ollama_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            tags_url = f"{base_url}/api/tags"
            response = requests.head(tags_url, timeout=5)
            if response.status_code != 200:
                response = requests.get(tags_url, timeout=5)
            if response.status_code == 200:
                return True
            else:
                log.error(f"AI_CONNECTION_REFUSED: tags endpoint returned status {response.status_code}")
                raise AIConnectionRefusedError(f"AI_CONNECTION_REFUSED: tags endpoint returned status {response.status_code}")
        except requests.exceptions.ConnectionError as e:
            log.error(f"AI_CONNECTION_REFUSED: Connection refused at {tags_url}. Details: {e}")
            raise AIConnectionRefusedError(f"AI_CONNECTION_REFUSED: Connection refused at {tags_url}. Details: {e}") from e
        except Exception as e:
            if not isinstance(e, AIConnectionRefusedError):
                log.error(f"AI_CONNECTION_REFUSED: Check failed. Details: {e}")
                raise AIConnectionRefusedError(f"AI_CONNECTION_REFUSED: Check failed. Details: {e}") from e
            raise e

    def _clean_and_parse_json(self, raw_text: str) -> Optional[Dict[str, Any]]:
        """Cleans and parses JSON from the LLM, handling raw newlines inside string literals."""
        try:
            return json.loads(raw_text)
        except json.JSONDecodeError as jde:
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
                log.error(f"AI_BAD_RESPONSE: Failed to parse sanitized JSON: {e}. Raw: {raw_text}")
                raise AIBadResponseError(f"AI_BAD_RESPONSE: JSON decoding failed. Details: {e}. Raw response text: {raw_text}") from jde

    def _invoke_with_retry(
        self,
        url: str,
        json_data: Dict[str, Any],
        headers: Dict[str, str],
        timeout: int = 60,
        max_attempts: int = 3,
        base: float = 1.0,
        max_delay: float = 10.0,
    ) -> "requests.Response":
        """
        Wraps a single ``requests.post`` call with exponential-backoff retry logic.

        Retries *only* on transient conditions:
          - ``requests.exceptions.ConnectionError``
          - ``requests.exceptions.Timeout``
          - HTTP 503 responses

        Non-retryable conditions (raised immediately):
          - HTTP 4xx responses
          - ``AIBadResponseError``
          - Any other exception type

        Delay formula:  min(base * 2^(attempt-1) + jitter, max_delay)
        where jitter ~ Uniform[0, 0.5).

        On final failure after all retries the original exception is re-raised.
        """
        last_exc: Optional[Exception] = None

        for attempt in range(1, max_attempts + 1):
            try:
                response = requests.post(url, json=json_data, headers=headers, timeout=timeout)

                # HTTP 503 is a transient server-overload signal — retry.
                if response.status_code == 503:
                    transient_err = requests.exceptions.ConnectionError(
                        f"HTTP 503 received from {url}"
                    )
                    if attempt < max_attempts:
                        delay = min(base * (2 ** (attempt - 1)) + random.uniform(0, 0.5), max_delay)
                        log.warning(
                            f"Ollama transient error (attempt {attempt}/{max_attempts}), "
                            f"retrying in {delay:.1f}s: {transient_err}"
                        )
                        time.sleep(delay)
                        last_exc = transient_err
                        continue
                    raise transient_err

                # Any other status code (including 4xx) is returned as-is;
                # AIBadResponseError will be raised by the caller.
                return response

            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                last_exc = e
                if attempt < max_attempts:
                    delay = min(base * (2 ** (attempt - 1)) + random.uniform(0, 0.5), max_delay)
                    log.warning(
                        f"Ollama transient error (attempt {attempt}/{max_attempts}), "
                        f"retrying in {delay:.1f}s: {e}"
                    )
                    time.sleep(delay)
                else:
                    raise

        # Should only be reached if max_attempts == 0 (not normally possible).
        raise last_exc  # type: ignore[misc]

    def _invoke_llm(self, prompt: str) -> Optional[Dict[str, Any]]:
        """Utility to invoke Ollama with Qwen 2.5 Coder forcing JSON output."""
        # Issue 6 fix: per-call health check removed.
        # The pre-flight check_connection_health() in cli.py already validates connectivity
        # before the first LLM call. Adding it here causes 1 extra HTTP GET per leg (3 total
        # for a full triage pass) with zero added safety — the ConnectionError catch on
        # _invoke_with_retry below already handles Ollama going down mid-session.

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

        # Verbose AI Logging: dump raw JSON prompt
        if self.verbose or self.dry_run:
            console.print("\n[bold magenta]========================= [AI DEBUG: PROMPT] =========================[/]")
            console.print(json.dumps(payload, indent=2))
            console.print("[bold magenta]======================================================================[/]\n")

        headers = {
            "Content-Type": "application/json",
            "format": "json"  # strictly include "format": "json" in request headers
        }

        try:
            response = self._invoke_with_retry(self.ollama_url, payload, headers, timeout=60)
        except requests.exceptions.ConnectionError as e:
            log.error(f"AI_CONNECTION_REFUSED: Connection refused during post to {self.ollama_url}")
            raise AIConnectionRefusedError(f"AI_CONNECTION_REFUSED: Connection refused at {self.ollama_url}. Details: {e}") from e
        except Exception as e:
            log.error(f"Ollama post failed: {e}")
            raise e

        # Verbose AI Logging: dump raw status code
        if self.verbose or self.dry_run:
            console.print(f"[bold magenta][AI DEBUG: STATUS CODE] {response.status_code}[/]\n")

        # Debug Trace: dry-run mode prints raw HTTP response
        if self.dry_run:
            console.print("[bold magenta]======================== [AI DEBUG: RESPONSE] ========================[/]")
            console.print(response.text)
            console.print("[bold magenta]======================================================================[/]\n")

        if response.status_code != 200:
            log.error(f"Ollama returned error status: {response.status_code}")
            raise AIBadResponseError(f"AI_BAD_RESPONSE: Ollama returned status {response.status_code}. Response text: {response.text}")

        try:
            response_json = response.json()
        except json.JSONDecodeError as e:
            log.error(f"AI_BAD_RESPONSE: Failed to parse response wrapper JSON: {e}")
            raise AIBadResponseError(f"AI_BAD_RESPONSE: Failed to parse response wrapper JSON. Details: {e}. Raw text: {response.text}") from e

        raw_text = response_json.get("response", "{}")
        return self._clean_and_parse_json(raw_text)


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
    def triage_false_positive(self, matched_rule: Dict[str, Any], package_metadata: Dict[str, Any]) -> "TriageResult":
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
            "CRITICAL SECURITY GUIDELINES:\n"
            "1. DEFAULT STANCE: The default verdict is 'SUSPICIOUS'. You must ONLY rule 'FALSE_POSITIVE' if there is clear, explicit, positive, and undeniable evidence matching a whitelisted benign exception rule in 'triage_baselines' or if the package is a verified, standard benign dependency/tool performing standard actions.\n"
            "2. WHITELIST-ONLY EXCEPTION STRATEGY: Do NOT downgrade an alert to 'FALSE_POSITIVE' unless it explicitly fits a whitelisted exception rule in 'triage_baselines'. In the absence of matching exception rules or explicit verification, the verdict MUST remain 'SUSPICIOUS'.\n"
            "3. NO LACK-OF-EVIDENCE DOWNGRADES: A lack of additional suspicious features (such as no network activity, no sensitive file reads, or a lack of known threat data) is NOT a reason to clear an alert. Lack of evidence confirming a threat does NOT make the alert a false positive.\n"
            "4. HIGH SEVERITY ALERTS: If the matched pattern has a high severity (severity >= 7.0/10), be extremely conservative. Patterns like 'process_injection' (e.g., modifying memory protections like PROT_EXEC, executing unexpected binaries, mprotect/mmap manipulations, or spawning unexpected shells/subprocesses) represent critical threats and must NEVER be marked 'FALSE_POSITIVE' unless they match a highly specific whitelisted exceptions rule.\n"
            "5. ANOMALOUS METADATA: Pay close attention to package names. If the package 'name' looks like a random hash (e.g. SHA-256/MD5 hex strings like 'd59a0308d2a3ba15b1f5f71269...zip'), UUID, temporary upload file, or random characters, it is typical of malware samples and sandbox targets. Such files must NEVER be cleared as false positives without positive whitelist matches.\n"
            "6. REASONING REQUIREMENT: The 'reasoning' field must clearly state which specific whitelisted exception rule was matched. If no exception was matched, state clearly that it remains 'SUSPICIOUS' due to lack of a matching exception.\n\n"
            "Return a JSON response conforming to this schema:\n"
            "{\n"
            "  \"verdict\": \"FALSE_POSITIVE\" | \"SUSPICIOUS\",\n"
            "  \"confidence\": float (0.0 to 1.0),\n"
            "  \"mitigation_applied\": boolean,\n"
            "  \"reasoning\": \"detailed explanation of the context analysis and which exception rule matched\"\n"
            "}"
        )

        user_content = {
            "matched_pattern": matched_rule,
            "package_metadata": package_metadata,
            "triage_baselines": heuristics_data.get("exception_rules", [])
        }

        prompt = f"{system_prompt}\n\n### Triage Context:\n{json.dumps(user_content, indent=2)}"
        result = self._invoke_llm(prompt)
        if result is None or not isinstance(result, dict):
            raise AIBadResponseError("triage_false_positive: LLM returned non-dict result")
        return TriageResult.from_dict(result)

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
