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
from urllib.parse import urlparse
import re

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
            "You are a Machine Learning Feature Vector Translator.\n"
            "You are given the 10-sensor behavioral feature vector used by TraceTree's Random Forest classifier.\n"
            "Your only job is to describe what the raw sensor numbers represent. Do not decide whether the package is malicious or benign.\n"
            "Provide an objective natural language summary of what these statistics imply about the installer behavior.\n"
            "Return a JSON response conforming to this schema:\n"
            "{\n"
            "  \"prediction_validation\": \"objective natural language translation of what the raw counts indicate\",\n"
            "  \"suspected_threat_vector\": \"characterization of observed behavior profile (e.g. heavy network downloader, quiet library, process spawner)\",\n"
            "  \"risk_multiplier\": number (1.0 to 3.0 scale measuring system call density)\n"
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
    # Signatures that must never be cleared as false positives regardless of LLM output.
    _HARDBLOCK_SIGNATURES = frozenset({
        "process_injection",
        "injection",
        "container_escape",
        "privilege_escalation",
        "rootkit",
        "keylogger",
    })
    # Severity threshold above which LLM is not consulted — verdict stays SUSPICIOUS.
    _HARDBLOCK_SEVERITY = 8.0

    def _check_hard_blocks(
        self,
        matched_rule: Dict[str, Any],
        package_metadata: Dict[str, Any],
    ) -> Optional["TriageResult"]:
        """
        Returns a forced SUSPICIOUS TriageResult if any deterministic hard-block
        condition is met. Returns None when the LLM may proceed.

        Hard blocks (LLM cannot override):
        1. Severity >= _HARDBLOCK_SEVERITY
        2. Any matched signature in _HARDBLOCK_SIGNATURES
        3. Package name looks like a hex hash / random sample filename
        """

        severity = float(matched_rule.get("severity", 0.0))
        all_sigs: List[str] = list(matched_rule.get("all_signatures", []))
        if matched_rule.get("rule_name"):
            all_sigs.append(matched_rule["rule_name"])
        pkg_name: str = str(package_metadata.get("name", ""))

        # Block 1: high severity
        if severity >= self._HARDBLOCK_SEVERITY:
            reason = (
                f"HARD BLOCK: severity {severity:.1f} >= {self._HARDBLOCK_SEVERITY}. "
                "LLM override disabled for critical-severity detections."
            )
            log.warning(f"triage_false_positive hard block (severity): {reason}")
            return TriageResult(
                verdict="SUSPICIOUS",
                confidence=1.0,
                mitigation_applied=False,
                reasoning=reason,
            )

        # Block 2: injection / escape / rootkit signatures
        lower_sigs = [s.lower() for s in all_sigs]
        for sig in lower_sigs:
            for blocked in self._HARDBLOCK_SIGNATURES:
                if blocked in sig:
                    reason = (
                        f"HARD BLOCK: matched signature '{sig}' contains blocked keyword '{blocked}'. "
                        "LLM override disabled for injection/escape/rootkit detections."
                    )
                    log.warning(f"triage_false_positive hard block (signature): {reason}")
                    return TriageResult(
                        verdict="SUSPICIOUS",
                        confidence=1.0,
                        mitigation_applied=False,
                        reasoning=reason,
                    )

        # Block 3: package name looks like a hex hash or random sample artifact
        basename = Path(pkg_name).name
        if re.fullmatch(r"[0-9a-fA-F]{16,}", basename) or re.fullmatch(r"[0-9a-fA-F]{16,}.*", basename):
            reason = (
                f"HARD BLOCK: package name '{basename}' matches hex-hash pattern typical of malware samples. "
                "LLM override disabled."
            )
            log.warning(f"triage_false_positive hard block (hash name): {reason}")
            return TriageResult(
                verdict="SUSPICIOUS",
                confidence=1.0,
                mitigation_applied=False,
                reasoning=reason,
            )

        return None

    def triage_false_positive(self, matched_rule: Dict[str, Any], package_metadata: Dict[str, Any]) -> "TriageResult":
        """
        Acts as a False Positive Juror. Evaluates triggered alerts against
        baseline context and triages false alarms using rules configured in data/ai_triage_rules.json.
        """
        # Deterministic hard blocks run before any LLM call.
        # These represent threats where a 7B LLM has no authority to override.
        hard_block = self._check_hard_blocks(matched_rule, package_metadata)
        if hard_block is not None:
            return hard_block

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

    def generate_analyst_report(self, behavior_receipt: Dict[str, Any]) -> Dict[str, Any]:
        """
        Takes the generated Behavior Receipt (including the RF verdict)
        and asks the AI to write a developer-friendly security explanation
        of the findings, explaining *why* the package was flagged or cleared.
        """
        system_prompt = (
            "You are a Security Analyst Explainer.\n"
            "You are given a Behavior Receipt summarizing a package's execution in a sandbox and the Random Forest model's verdict.\n"
            "Your job is to read this receipt and draft a developer-friendly, human-sounding report.\n"
            "Explain what the package did in plain English, why the Random Forest model made its decision, and what risk it poses to the developer's workstation.\n"
            "Do not use em dashes in your response. Keep it objective, professional, and clear.\n"
            "Return a JSON response conforming to this schema:\n"
            "{\n"
            "  \"summary\": \"natural language summary of the package activity and verdict\",\n"
            "  \"risk_assessment\": \"explanation of the risk posed (e.g. none, low, or high reverse-shell/exfiltration risk)\",\n"
            "  \"recommendation\": \"what the developer should do next (e.g. safe to install, review code, or block package)\"\n"
            "}"
        )

        prompt = f"{system_prompt}\n\n### Behavior Receipt:\n{json.dumps(behavior_receipt, indent=2)}"
        return self._invoke_llm(prompt) or {
            "summary": "Fallback analyst summary: no AI response received.",
            "risk_assessment": "UNKNOWN",
            "recommendation": "REVIEW"
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

    elif leg_name in ("Analyst Report", "Behavior Receipt Explainer"):
        content_table = Table(show_header=False, box=None)
        content_table.add_column("Key", style="bold cyan")
        content_table.add_column("Value")
        
        content_table.add_row("Summary", results.get("summary", ""))
        content_table.add_row("Risk Assessment", results.get("risk_assessment", ""))
        content_table.add_row("Recommendation", f"[bold yellow]{results.get('recommendation', 'REVIEW')}[/]")
        
        console.print(Panel(
            content_table,
            title=title,
            border_style="cyan",
            expand=False
        ))


def build_behavior_receipt(
    target: str,
    target_type: str,
    verdict: Any,  # AnomalyVerdict object
    graph_data: Dict[str, Any],
    parsed_data: Dict[str, Any],
    sig_matches: List[Dict[str, Any]],
    temp_patterns: List[Dict[str, Any]],
    yara_matches: List[Dict[str, Any]],
    log_path: Optional[str] = None,
    controlled_network: bool = False,
) -> Dict[str, Any]:
    """
    Builds a standardized behavior receipt dict conforming to
    docs/behavior-receipt-export.md schema.
    """
    import hashlib
    from datetime import datetime, timezone
    
    # 1. Target metadata
    # Parse version if name has @ (e.g. package@version)
    name = target
    version = "unknown"
    if "@" in target and not target.startswith("@"): # e.g. lodash@4.17.21
        parts = target.split("@")
        name = parts[0]
        version = parts[1]
    elif target.startswith("@") and target.count("@") > 1: # e.g. @types/node@14.0.0
        parts = target.rsplit("@", 1)
        name = parts[0]
        version = parts[1]
        
    # Calculate SHA256 of target file if exists, else hash the target name
    target_sha = "sha256:"
    target_path = Path(target)
    if target_path.is_file():
        try:
            h = hashlib.sha256()
            with open(target_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            target_sha += h.hexdigest()
        except Exception:
            target_sha += hashlib.sha256(target.encode()).hexdigest()
    else:
        target_sha += hashlib.sha256(target.encode()).hexdigest()

    # 2. Log and graph hashes
    strace_hash = ""
    if log_path and Path(log_path).exists():
        try:
            h = hashlib.sha256()
            with open(log_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            strace_hash = "sha256:" + h.hexdigest()
        except Exception:
            pass
            
    # Filter out non-serializable raw NetworkX graph object
    serializable_graph = {k: v for k, v in graph_data.items() if k != "raw_graph"}
    graph_str = json.dumps(serializable_graph)
    graph_hash = "sha256:" + hashlib.sha256(graph_str.encode()).hexdigest()

    # 3. Stats from graph_data or parsed_data
    stats = graph_data.get("stats", {})
    process_count = stats.get("node_count", 0) # approximation of nodes/processes
    # Count clone/execve if events exist
    events = parsed_data.get("events", [])
    if events:
        clones = sum(1 for e in events if e.get("type") in ("clone", "fork", "vfork", "execve"))
        if clones > 0:
            process_count = clones + 1
            
    file_write_count = stats.get("file_write_count", 0)
    if file_write_count == 0 and events:
        file_write_count = sum(1 for e in events if e.get("type") == "write" or (e.get("type") == "open" and "write" in str(e.get("details", {}).get("flags", ""))))

    external_connect = stats.get("network_conn_count", 0)
    sensitive_read = stats.get("sensitive_file_count", 0)

    # 4. Matched signatures
    matched_sigs = []
    for sm in sig_matches:
        matched_sigs.append(sm.get("name", ""))
    for ym in yara_matches:
        matched_sigs.append(ym.get("rule_name", ""))
        
    matched_temps = [p.get("pattern", str(p)) for p in temp_patterns]

    # 5. Verdict parameters
    is_malicious = getattr(verdict, "is_malicious", False)
    risk_score = float(getattr(verdict, "risk_score", 0.0))
    reasons = list(getattr(verdict, "reasons", []))
    reason_str = reasons[0] if reasons else ("suspicious behavior flagged" if is_malicious else "no suspicious footprints flagged")
    
    # 6. Build final schema
    net_policy = "controlled-network-sinkhole" if controlled_network else "blocked-after-fetch"
    
    receipt = {
        "schema": "tracetree.behavior_receipt.v1",
        "run_id": f"tracetree-{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "target": {
            "type": target_type,
            "name": name,
            "version": version,
            "source": "package-lock" if target_type in ("pip", "npm") else "direct",
            "artifact_sha256": target_sha
        },
        "sandbox": {
            "mode": "docker-strace",
            "network_policy": net_policy,
            "timeout_seconds": 30,
            "image_digest": "sha256:4b918b2c4bf8a332dfa9a3b6" # mock base container digest
        },
        "artifacts": {
            "strace_log_sha256": strace_hash,
            "graph_sha256": graph_hash,
            "sarif_sha256": ""
        },
        "observed_behavior": {
            "process_count": process_count,
            "file_write_count": file_write_count,
            "external_connect_count": external_connect,
            "sensitive_file_read_count": sensitive_read,
            "matched_signatures": matched_sigs,
            "matched_temporal_patterns": matched_temps
        },
        "verdict": {
            "decision": "suspicious" if is_malicious else "clean",
            "confidence": round(risk_score / 100.0, 3),
            "reason": reason_str,
            "review_required": is_malicious or len(matched_sigs) > 0 or risk_score >= 50.0
        },
        "privacy": {
            "raw_syscalls_included": False,
            "environment_values_included": False,
            "secrets_included": False
        }
    }
    return receipt
