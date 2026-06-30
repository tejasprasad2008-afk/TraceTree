"""
Secret Guardian: Static scanning for credentials and suspicious logging.

This module provides heuristics to detect hardcoded secrets (API keys, tokens)
and risky debug logging patterns that commonly lead to credential leaks
in AI agent environments.
"""

import re
import math
import logging
from pathlib import Path
from typing import List, Dict, Any, Generator, Tuple
from monitor.yara import SCAN_EXCLUDE_EXTENSIONS, SCAN_EXCLUDE_DIRS
from typing import List, Dict, Any, Generator

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
#  Regex Patterns for Secrets
# --------------------------------------------------------------------------- #

SECRET_PATTERNS = {
    "NVIDIA API Key": r"nvapi-[A-Za-z0-9]{64}",
    "OpenAI API Key": r"sk-[A-Za-z0-9]{48,}",
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"(?i)aws_secret_access_key\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
    "Generic High-Entropy Hex": r"\b[a-f0-9]{64}\b",
    "Generic High-Entropy Base64": r"\b[A-Za-z0-9+/]{40,}={0,2}\b",
    "Private Key": r"-----BEGIN (?:RSA|OPENSSH|EC|PGP) PRIVATE KEY-----",
    "GitHub Token": r"gh[pous]_[a-zA-Z0-9]{36}",
}

# --------------------------------------------------------------------------- #
#  Heuristics for Suspicious Logging (The AI Agent Vector)
# --------------------------------------------------------------------------- #
# Based on research (arxiv.org/abs/2604.03070) showing 73.5% of leaks
# occur via stdout exposure (print/console.log).

LOGGING_KEYWORDS = ["api_key", "token", "secret", "password", "credentials", "auth_key", "nvapi"]
LOGGING_FUNCTIONS = [r"print", r"console\.log", r"logger\.(?:info|debug|warning|error|log)", r"sys\.stdout\.write"]

# Matches print(f"... {api_key} ...") or console.log("Key:", token)
SUSPICIOUS_LOGGING_REGEX = re.compile(
    r"(?:" + "|".join(LOGGING_FUNCTIONS) + r")\s*\(.*(?:" + "|".join(LOGGING_KEYWORDS) + r").*\)",
    re.IGNORECASE
)

# Heuristics for Malicious Code Injections (AI Agent Vector)
# These are patterns that might indicate an agent was tampered with to 
# inject a backdoor or exfiltrator.
MALICIOUS_HEURISTICS = [
    {
        "name": "Obfuscated Exfiltration",
        "regex": re.compile(r"(?:requests|urllib|socket|http|curl|wget)\..*(?:post|send|connect|get).*(?:base64|b64|hex|encode|payload)", re.IGNORECASE),
        "description": "Potential obfuscated data exfiltration via network."
    },
    {
        "name": "Dynamic Code Execution",
        "regex": re.compile(r"(?:\bexec\b|\beval\b|\bcompile\b)\s*\(.*(?:base64|b64|decode|zlib|chr\(|getattr|__import__)", re.IGNORECASE),
        "description": "Risky use of dynamic execution with obfuscated or reflected code."
    },
    {
        "name": "Reflection Backdoor",
        "regex": re.compile(r"(?:getattr|__getattribute__)\s*\(.*['\"](?:eval|exec|compile|system|Popen|subprocess|socket|requests|os)['\"]", re.IGNORECASE),
        "description": "Suspicious use of reflection to access sensitive built-ins or modules."
    },
    {
        "name": "Shell Injected in Source",
        "regex": re.compile(r"subprocess\.(?:run|Popen|call|check_output)\s*\(.*['\"]/(?:bin|usr/bin)/(?:bash|sh|zsh|dash|python|perl|php|ruby)['\"]", re.IGNORECASE),
        "description": "Hardcoded shell or interpreter invocation in application source."
    },
    {
        "name": "Credential Harvesting Path",
        "regex": re.compile(r"['\"](?:Discord|discordcanary|Google/Chrome|Local Storage/leveldb|\.aws/credentials|\.ssh/id_rsa|\.env)[\"']", re.IGNORECASE),
        "description": "Access to sensitive application paths used for credential storage."
    }
]

# --------------------------------------------------------------------------- #
#  Entropy Calculation
# --------------------------------------------------------------------------- #

def calculate_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

import os

# --------------------------------------------------------------------------- #
#  Scanner Core
# --------------------------------------------------------------------------- #

def scan_file_for_secrets(file_path: Path, skip_yara: bool = True) -> Generator[Dict[str, Any], None, None]:
    """
    Scan a single file for secrets, suspicious logging, and malicious code patterns.
    Yields dicts with: line_number, content, rule_name, type (secret/logging/malicious).
    """
    # Skip known large/uninteresting files or non-source files
    if file_path.suffix in ['.log', '.pkl', '.exe', '.dmg', '.zip', '.tar', '.gz', '.png', '.jpg', '.gif', '.pdf']:
        return

    try:
        # Safe binary probe to skip binary files
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            if b'\x00' in chunk: # Standard binary check
                return
    except (UnicodeDecodeError, ValueError, OSError, PermissionError):
        return

    # 1. YARA Scanning (Deep detection of known malware signatures)
    # Optimization: We now run YARA once for the entire directory in scan_directory()
    # to avoid the massive performance hit of redundant parent-directory scans.
    if not skip_yara:
        from monitor.yara import scan_with_yara
        yara_matches = scan_with_yara(package_dir=str(file_path.parent))
        for m in yara_matches:
            if m["file_path"] == str(file_path):
                yield {
                    "line_number": 0,
                    "content": m["description"],
                    "rule_name": f"YARA: {m['rule_name']}",
                    "type": "malicious",
                    "match": None
                }

    try:
        with open(file_path, 'r', errors='replace') as f:
            for line_num, line in enumerate(f, 1):
                stripped_line = line.strip()
                if not stripped_line or stripped_line.startswith("#") or stripped_line.startswith("//"):
                    continue

                # 2. Check for specific provider signatures
                for name, pattern in SECRET_PATTERNS.items():
                    matches = re.findall(pattern, stripped_line)
                    for m in matches:
                        # For generic high-entropy, verify it actually has high entropy
                        if "High-Entropy" in name:
                            # Higher threshold for Base64 to reduce noise (urls, etc)
                            threshold = 4.5 if "Base64" in name else 3.5
                            if calculate_entropy(m) < threshold:
                                continue
                        
                        yield {
                            "line_number": line_num,
                            "content": stripped_line,
                            "rule_name": name,
                            "type": "secret",
                            "match": m
                        }

                # 3. Check for suspicious logging (AI Agent vector)
                if SUSPICIOUS_LOGGING_REGEX.search(stripped_line):
                    # Ignore lines that are clearly reports or checks (common false positives)
                    if any(x in stripped_line.lower() for x in ["no secrets", "found malwarebazaar", "secret guardian pre-commit"]):
                        continue
                        
                    yield {
                        "line_number": line_num,
                        "content": stripped_line,
                        "rule_name": "Suspicious Debug Logging",
                        "type": "logging",
                        "match": None
                    }

                # 4. Check for malicious heuristics
                for h in MALICIOUS_HEURISTICS:
                    if h["regex"].search(stripped_line):
                        yield {
                            "line_number": line_num,
                            "content": stripped_line,
                            "rule_name": h["name"],
                            "type": "malicious",
                            "match": None
                        }

    except Exception as e:
        log.debug(f"Failed to scan {file_path}: {e}")

def scan_directory(root_path: Path, ignore_git: bool = True) -> List[Dict[str, Any]]:
    """Recursively scan a directory for secrets and malicious patterns."""
    results = []
    ignored_dirs = {'.git', 'venv', 'traceenv', 'node_modules', '__pycache__', '.ruff_cache', '.vscode', 'logs', 'mascot', 'cascade_analyzer.egg-info', 'dist', 'build'} | SCAN_EXCLUDE_DIRS
    ignored_files = {'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'}
    
    # 1. Optimized File Walk
    files_to_scan = []
    for root, dirs, files in os.walk(root_path):
        # Prune ignored directories in-place
        dirs[:] = [d for d in dirs if d not in ignored_dirs]
        
        for fname in files:
            if fname in ignored_files:
                continue
                
            fpath = Path(root) / fname
            # Skip non-source files and large files
            if fpath.suffix.lower() in ['.log', '.pkl', '.exe', '.dmg', '.zip', '.tar', '.gz', '.gif', '.pdf', '.ico'] or fpath.suffix.lower() in SCAN_EXCLUDE_EXTENSIONS:
                continue
                
            # Skip if any parent directory is excluded
            if any(part in SCAN_EXCLUDE_DIRS for part in fpath.parts):
                continue
                
            try:
                if fpath.stat().st_size > 1024 * 1024:
                    continue
                files_to_scan.append(fpath)
            except OSError:
                continue

    # 2. Batch YARA Scan (Huge performance gain)
    # We pass the collected files directly to the YARA engine if possible, 
    # but the current monitor.yara.scan_with_yara expects a directory.
    # To fix this properly, we'll scan the files one-by-one but we'll 
    # ignore the monitor directory itself to avoid self-flagging.
    from monitor.yara import scan_with_yara
    
    # Self-exclusion: Don't let the scanner report on its own rules
    source_files = [f for f in files_to_scan if 'monitor' not in f.parts]

    for fpath in source_files:
        # Run static heuristics (fast)
        for finding in scan_file_for_secrets(fpath, skip_yara=True):
            finding["file_path"] = str(fpath)
            results.append(finding)

    # Run YARA on the same list of source files
    try:
        # Optimization: Scan the root but filter results aggressively
        yara_matches = scan_with_yara(package_dir=str(root_path))
        for m in yara_matches:
            f_path = Path(m["file_path"])
            
            # 1. Filter out ignored dirs
            if any(part in ignored_dirs for part in f_path.parts):
                continue
            
            # 2. Filter out self-flagging
            if 'monitor' in f_path.parts:
                continue
            
            # 3. Filter out non-source files that YARA might have walked
            if f_path.suffix.lower() in ['.png', '.jpg', '.jpeg', '.gif', '.pdf', '.ico', '.svg', '.json', '.sql', '.db']:
                continue
                
            # 4. Filter out common noise in documentation
            if f_path.name in ['README.md', '.gitignore', 'TECH_REFERENCE.md', 'LICENSE', 'AGENTS.md', 'TABIB_AUDIT_REPORT.md', 'TEST_SCRIPT.md']:
                continue
                
            results.append({
                "file_path": str(f_path),
                "line_number": 0,
                "content": m["description"],
                "rule_name": f"YARA: {m['rule_name']}",
                "type": "malicious",
                "match": None
            })
    except Exception as e:
        log.debug(f"Batch YARA scan failed: {e}")
                
    return results
