"""
YARA rule integration for TraceTree.

Scans extracted package files and strace logs against embedded YARA rules
to detect known malware families, obfuscation patterns, and malicious payloads.

Usage:
    from monitor.yara import scan_with_yara

    matches = scan_with_yara("/path/to/strace.log", "/path/to/extracted/pkg/")
"""

import logging
import os
from pathlib import Path
from typing import List, Dict, Any, Optional

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
#  Embedded YARA rules (no external yara binary required)
# --------------------------------------------------------------------------- #
#
# These rules encode common supply-chain attack patterns as string/regex
# signatures that can be matched against extracted package contents and
# strace logs.  When the ``yara-python`` library is installed it is used;
# otherwise we fall back to a lightweight regex-based matcher that covers
# the same patterns.

_YARA_RULES_SRC = r"""
rule SuspiciousBase64Payload {
    meta:
        description = "Detects long base64-encoded payloads commonly used for obfuscation"
        severity = "high"
    strings:
        $b64 = /[A-Za-z0-9+/]{100,}={0,2}/ ascii
    condition:
        $b64
}

rule ReverseShellPattern {
    meta:
        description = "Detects reverse shell one-liners and common C2 patterns"
        severity = "critical"
    strings:
        $bash = "/bin/bash -i >& /dev/tcp/" nocase
        $nc = "nc -e /bin/" nocase
        $curl_sh = /curl\s+\S+\|.*(?:bash|sh)/ nocase
        $wget_sh = /wget\s+\S+\s+-O.*\|.*(?:bash|sh)/ nocase
    condition:
        any of them
}

rule CryptominerSignature {
    meta:
        description = "Detects cryptocurrency mining configuration and pool connections"
        severity = "critical"
    strings:
        $stratum = "stratum+tcp://" nocase
        $xmrig = "xmrig" nocase
        $coinhive = "coinhive" nocase
        $wallet = /0x[a-fA-F0-9]{40}/
    condition:
        2 of them
}

rule CredentialHarvester {
    meta:
        description = "Detects credential harvesting attempts targeting cloud/config files"
        severity = "high"
    strings:
        $aws = ".aws/credentials" nocase
        $npmrc = ".npmrc" nocase
        $pypirc = ".pypirc" nocase
        $ssh = ".ssh/id_rsa" nocase
        $env = ".env" nocase
        $git_cred = ".git-credentials" nocase
    condition:
        2 of them
}

rule PyInstallerUnpacker {
    meta:
        description = "Detects PyInstaller extracted archives with suspicious embedded scripts"
        severity = "medium"
    strings:
        $pyi = "PYZ-00.pyz" nocase
        $extract = "/tmp/_MEI" nocase
        $base_library = "base_library.zip" nocase
    condition:
        2 of them
}

rule ObfuscatedEval {
    meta:
        description = "Detects eval/exec of dynamically constructed code"
        severity = "high"
    strings:
        $eval_b64 = /eval\s*\(\s*(?:base64|decode|b64decode)\s*\(/ nocase
        $exec_comp = /exec\s*\(\s*(?:compile|__import__)\s*\(/ nocase
        $chr_exec = /chr\(\d+\)\s*\+\s*chr\(\d+\)/ ascii
    condition:
        any of them
}

rule MaliciousPostInstall {
    meta:
        description = "Detects post-install scripts with suspicious network/exfil behavior (not generic setup.py)"
        severity = "high"
    strings:
        $net_exfil = /(?:requests\.|urllib|wget|curl|socket\.)\s*(?:get|post|put|send)/ nocase
        $encode_exfil = /(?:base64|encode|b64encode)\s*\(.*(?:open|read|password|secret|token)/ nocase
        $c2_pattern = /(?:stratum\+tcp://|pastebin|transfer\.sh|file\.io|0x0\.st)/ nocase
    condition:
        2 of them
}
"""

# --------------------------------------------------------------------------- #
#  Public API
# --------------------------------------------------------------------------- #


def scan_with_yara(
    log_path: Optional[str] = None,
    package_dir: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Scan strace logs and/or extracted package files against YARA rules.

    Args:
        log_path: Path to a strace log file.
        package_dir: Path to an extracted package directory.

    Returns:
        List of match dicts with keys:
          rule_name, severity, description, file_path, matches (list of matched strings).
    """
    results: List[Dict[str, Any]] = []

    # Try real YARA first
    try:
        import yara
        rules = _compile_yara_rules(yara)
        if rules is None:
            return _fallback_regex_scan(log_path, package_dir)
    except ImportError:
        log.info("yara-python not installed — using fallback regex scanner")
        return _fallback_regex_scan(log_path, package_dir)
    except Exception as e:
        log.warning("YARA compilation failed (%s) — falling back", e)
        return _fallback_regex_scan(log_path, package_dir)

    # Scan files
    files_to_scan = _collect_files(log_path, package_dir)
    for fpath in files_to_scan:
        try:
            matches = rules.match(fpath)
            for m in matches:
                results.append({
                    "rule_name": m.rule,
                    "severity": m.meta.get("severity", "unknown"),
                    "description": m.meta.get("description", ""),
                    "file_path": str(fpath),
                    "matched_strings": [s for s, _ in m.strings],
                })
        except Exception as e:
            log.debug("YARA scan failed for %s: %s", fpath, e)

    return results


# --------------------------------------------------------------------------- #
#  YARA compilation (real library)
# --------------------------------------------------------------------------- #


def _compile_yara_rules(yara):
    """Compile embedded rules using yara-python."""
    try:
        return yara.compile(source=_YARA_RULES_SRC)
    except Exception as e:
        log.warning("YARA compile error: %s", e)
        return None


# --------------------------------------------------------------------------- #
#  Fallback regex scanner (used when yara-python is unavailable)
# --------------------------------------------------------------------------- #

import re as _re

_FALLBACK_PATTERNS = [
    {
        "rule_name": "SuspiciousBase64Payload",
        "severity": "high",
        "description": "Detects long base64-encoded payloads commonly used for obfuscation",
        "regex": _re.compile(r"[A-Za-z0-9+/]{100,}={0,2}"),
    },
    {
        "rule_name": "ReverseShellPattern",
        "severity": "critical",
        "description": "Detects reverse shell one-liners and common C2 patterns",
        "regex": _re.compile(
            r"(?:/bin/bash -i >& /dev/tcp/|nc -e /bin/|curl\s+\S+\|.*(?:bash|sh)|"
            r"wget\s+\S+\s+-O.*\|.*(?:bash|sh))",
            _re.IGNORECASE,
        ),
    },
    {
        "rule_name": "CryptominerSignature",
        "severity": "critical",
        "description": "Detects cryptocurrency mining configuration and pool connections",
        "regex": _re.compile(
            r"(?:stratum\+tcp://|xmrig|coinhive|0x[a-fA-F0-9]{40})",
            _re.IGNORECASE,
        ),
    },
    {
        "rule_name": "CredentialHarvester",
        "severity": "high",
        "description": "Detects credential harvesting attempts targeting cloud/config files",
        "regex": _re.compile(
            r"(?:\.aws/credentials|\.npmrc|\.pypirc|\.ssh/id_rsa|\.env|\.git-credentials)",
            _re.IGNORECASE,
        ),
    },
    {
        "rule_name": "PyInstallerUnpacker",
        "severity": "medium",
        "description": "Detects PyInstaller extracted archives with suspicious embedded scripts",
        "regex": _re.compile(
            r"(?:PYZ-00\.pyz|/tmp/_MEI|base_library\.zip)",
            _re.IGNORECASE,
        ),
    },
    {
        "rule_name": "ObfuscatedEval",
        "severity": "high",
        "description": "Detects eval/exec of dynamically constructed code",
        "regex": _re.compile(
            r"(?:eval\s*\(\s*(?:base64|decode|b64decode)\s*\(|"
            r"exec\s*\(\s*(?:compile|__import__)\s*\(|"
            r"chr\(\d+\)\s*\+\s*chr\(\d+\))",
            _re.IGNORECASE,
        ),
    },
    {
        "rule_name": "MaliciousPostInstall",
        "severity": "high",
        "description": "Detects post-install scripts with suspicious network/exfil behavior (not generic setup.py)",
        "regex": _re.compile(
            r"(?:(?:requests\.|urllib|wget|curl|socket\.)\s*(?:get|post|put|send)|"
            r"(?:base64|encode|b64encode)\s*\(.*(?:open|read|password|secret|token)|"
            r"(?:stratum\+tcp://|pastebin|transfer\.sh|file\.io|0x0\.st))",
            _re.IGNORECASE,
        ),
    },
]


def _fallback_regex_scan(
    log_path: Optional[str],
    package_dir: Optional[str],
) -> List[Dict[str, Any]]:
    """Scan files using the embedded regex patterns (yara-python not required).
    Streams files line-by-line to prevent OOM on large files."""
    results: List[Dict[str, Any]] = []
    files_to_scan = _collect_files(log_path, package_dir)
    max_file_size = 2 * 1024 * 1024  # 2 MB per file max
    max_lines = 50000  # 50K lines per file max

    for fpath in files_to_scan:
        try:
            if fpath.stat().st_size > max_file_size:
                log.debug("Skipping large file (%d bytes): %s", fpath.stat().st_size, fpath)
                continue
        except OSError:
            continue

        file_matches: Dict[str, List[str]] = {}  # rule_name -> [matched_strings]
        try:
            with open(fpath, 'r', errors='replace') as f:
                for line_num, line in enumerate(f, 1):
                    if line_num > max_lines:
                        log.debug("Truncated file at %d lines: %s", line_num, fpath)
                        break
                    for pattern in _FALLBACK_PATTERNS:
                        matches = pattern["regex"].findall(line)
                        if matches:
                            rule = pattern["rule_name"]
                            file_matches.setdefault(rule, []).extend(matches)
        except Exception:
            continue

        if file_matches:
            for rule_name, matched in file_matches.items():
                pattern_info = next(p for p in _FALLBACK_PATTERNS if p["rule_name"] == rule_name)
                results.append({
                    "rule_name": rule_name,
                    "severity": pattern_info["severity"],
                    "description": pattern_info["description"],
                    "file_path": str(fpath),
                    "matched_strings": list(set(matched))[:5],  # cap at 5 unique
                })

    return results


# --------------------------------------------------------------------------- #
#  File collection helpers
# --------------------------------------------------------------------------- #


def _collect_files(
    log_path: Optional[str],
    package_dir: Optional[str],
) -> List[Path]:
    """Gather all files to scan."""
    files: List[Path] = []

    if log_path and Path(log_path).exists():
        files.append(Path(log_path))

    if package_dir and Path(package_dir).is_dir():
        for root, _dirs, filenames in os.walk(package_dir):
            for fname in filenames:
                fpath = Path(root) / fname
                # Skip very large files (>5 MB) and binary formats we can't scan
                try:
                    if fpath.stat().st_size < 5 * 1024 * 1024:
                        files.append(fpath)
                except OSError:
                    continue

    return files
