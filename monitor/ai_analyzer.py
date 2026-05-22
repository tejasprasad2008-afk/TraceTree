"""
AI Analyzer: Contextual security auditing using local LLMs.

This module connects to a local Ollama instance to verify findings from
the static scanner, reducing false positives and identifying real vulnerabilities.
"""

import json
import logging
import requests
import os
from pathlib import Path

# Dynamically adjust PATH to prioritize typical macOS/Linux binary directories (e.g. Homebrew)
for _p in ["/opt/homebrew/bin", "/usr/local/bin"]:
    if _p not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = f"{_p}{os.pathsep}{os.environ.get('PATH', '')}"

from typing import Dict, Any, Optional, List

log = logging.getLogger(__name__)

# Configure Ollama URL dynamically to support Docker-to-Host connectivity
OLLAMA_BASE = os.getenv("OLLAMA_HOST", "localhost:11434")
if not OLLAMA_BASE.startswith("http"):
    OLLAMA_BASE = f"http://{OLLAMA_BASE}"

OLLAMA_URL = f"{OLLAMA_BASE}/api/generate"
MODEL_NAME = "qwen2.5-coder:7b"

PROMPT_TEMPLATE = """
You are a HIGHLY PARANOID senior security auditor and forensic investigator. 
Analyze the following code snippet flagged by a static scanner. 
Your goal is to catch sneakily injected malicious code (backdoors, exfiltrators, credential harvesters) that "dumb" scanners miss.

### Context:
File: {file_path}
Finding Type: {finding_type}
Rule Name: {rule_name}
Line Number: {line_number}

### Code Snippet:
```
{context_lines}
```

### CRITICAL AUDIT INSTRUCTIONS:
1. **Malicious Intent:** Look for actions that a legitimate library or application should NEVER perform. 
2. **Credential Harvesting:** Accessing private folders of other applications (e.g., Discord, Chrome, Browsers, .ssh, .aws, .env, /etc/passwd) is a CRITICAL VULNERABILITY.
3. **Data Exfiltration:** Collecting local data (tokens, environment variables, files) and sending it to an external URL or socket is a CRITICAL VULNERABILITY.
4. **Obfuscation:** Using base64, hex, or reflection to hide the names of sensitive functions or URLs is a major red flag.
5. **No Politeness:** If the code is doing something "unnatural" for its claimed purpose, mark it as VULNERABLE. 
6. **Dismissal Rule:** Only DISMISS if the code is 100% clearly a comment, documentation, a safe test case in a known test file, or a security rule definition (like a regex pattern).

Return ONLY a JSON object in this format:
{{
    "is_vulnerable": bool,
    "severity": int, (1-10)
    "reason": "DETAILED explanation of the attack vector"
}}
"""

def is_ollama_installed() -> bool:
    """Check if the ollama binary is available in the system PATH."""
    import shutil
    return shutil.which("ollama") is not None

def is_ollama_alive() -> bool:
    """Check if the local Ollama service is reachable."""
    try:
        # Use tags endpoint as a health check
        response = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=2)
        return response.status_code == 200
    except Exception:
        return False

def ensure_ollama_and_model() -> bool:
    """
    Interactively ensure Ollama is installed and the required model is pulled.
    Returns True if ready, False otherwise.
    """
    import subprocess
    import platform
    import shutil
    from rich.prompt import Confirm
    from rich.console import Console

    console = logging.getLogger("rich") # Use existing rich integration if possible, or create local
    console = Console()

    # 1. Check if Ollama is installed
    ollama_path = shutil.which("ollama")
    if ollama_path is None:
        console.print("[bold yellow]⚠ Ollama is not installed.[/] Ollama is required for local AI security audits.")
        if Confirm.ask("Would you like to install Ollama now? (macOS requires Homebrew)"):
            sys_os = platform.system().lower()
            if sys_os == "darwin":
                brew_path = shutil.which("brew")
                if brew_path is None:
                    console.print("[bold red]Error:[/] Homebrew ('brew') was not found in your PATH.")
                    console.print("Please install Ollama manually from: [blue]https://ollama.com[/]")
                    return False
                try:
                    console.print(f"[cyan]Running: {brew_path} install ollama...[/]")
                    subprocess.run([brew_path, "install", "ollama"], env=os.environ, check=True)
                    console.print("[bold green]✔ Ollama installed successfully![/]")
                    ollama_path = shutil.which("ollama") or "/opt/homebrew/bin/ollama"
                except Exception as e:
                    console.print(f"[bold red]Installation failed:[/] {e}. Please install manually from https://ollama.com")
                    return False
            else:
                console.print("[bold red]Automatic installation is only supported on macOS.[/] Please download from https://ollama.com")
                return False
        else:
            return False

    # 2. Check if Ollama is running
    if not is_ollama_alive():
        console.print("[bold yellow]⚠ Ollama service is not running.[/]")
        if Confirm.ask("Would you like to start Ollama now?"):
            try:
                # Start in background
                subprocess.Popen([ollama_path, "serve"], env=os.environ, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                import time
                console.print("[cyan]Waiting for Ollama to wake up...[/]")
                for _ in range(10):
                    time.sleep(2)
                    if is_ollama_alive():
                        break
            except Exception as e:
                console.print(f"[bold red]Failed to start Ollama:[/] {e}")
                return False

    # 3. Check if the model exists
    try:
        response = requests.get(f"{OLLAMA_BASE}/api/tags")
        models = [m["name"] for m in response.json().get("models", [])]
        if MODEL_NAME not in models and f"{MODEL_NAME}:latest" not in models:
            console.print(f"[bold yellow]⚠ Model '{MODEL_NAME}' not found.[/] This is a lightweight model (~4.7GB) optimized for security.")
            if Confirm.ask(f"Would you like to pull '{MODEL_NAME}' now?"):
                console.print(f"[cyan]Pulling {MODEL_NAME}... this may take a few minutes depending on your internet speed.[/]")
                # We use subprocess to show progress bar from ollama itself if possible, 
                # or we could use requests stream. Subprocess is cleaner for UX.
                subprocess.run([ollama_path, "pull", MODEL_NAME], env=os.environ, check=True)
                console.print(f"[bold green]✔ Model {MODEL_NAME} is ready![/]")
            else:
                return False
    except Exception as e:
        log.error(f"Failed to check models: {e}")
        return False

    return True

def analyze_finding_with_ai(
    file_path: str,
    line_number: int,
    finding_type: str,
    rule_name: str,
    content: str,
    full_context: str = ""
) -> Dict[str, Any]:
    """
    Send a finding to the local LLM for context-aware verification.
    """
    if not is_ollama_alive():
        return {"error": f"Ollama not running locally at {OLLAMA_BASE}"}

    prompt = PROMPT_TEMPLATE.format(
        file_path=file_path,
        line_number=line_number,
        finding_type=finding_type,
        rule_name=rule_name,
        context_lines=full_context if full_context else content
    )

    try:
        response = requests.post(OLLAMA_URL, json={
            "model": MODEL_NAME,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        }, timeout=30)
        
        if response.status_code != 200:
            return {"error": f"Ollama returned error: {response.text}"}

        data = response.json()
        raw_response = data.get("response", "{}")
        try:
            result_json = json.loads(raw_response)
        except json.JSONDecodeError:
            return {"error": f"AI returned invalid JSON: {raw_response[:100]}..."}

        # Validate required keys
        if "is_vulnerable" not in result_json:
            return {"error": f"AI response missing 'is_vulnerable' key: {raw_response[:100]}..."}
            
        return result_json

    except Exception as e:
        log.error(f"AI Analysis failed: {e}")
        return {"error": str(e)}

def get_file_context(file_path: Path, line_number: int, window: int = 10) -> str:
    """Extract a window of lines around the finding for context."""
    if not file_path.exists():
        return ""
    
    try:
        with open(file_path, 'r', errors='replace') as f:
            lines = f.readlines()
            
        start = max(0, line_number - window - 1)
        end = min(len(lines), line_number + window)
        
        context = "".join(lines[start:end])
        return context
    except Exception:
        return ""
