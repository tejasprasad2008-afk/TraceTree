# MCP RCE Detection Extensions for TraceTree

## Overview

This extension adds comprehensive **Model Context Protocol (MCP) Remote Code Execution (RCE)** detection capabilities to TraceTree, based on the **OX Security April 2026 disclosure**.

### What's New

1. **10 MCP-Specific Behavioral Signatures** - Detect attack patterns in syscall traces
2. **27 YARA Rules** - Static detection of MCP RCE payloads in strace logs and package files
3. **CVE Correlation Database** - 9 CVEs (CVE-2026-30623 to CVE-2026-30631) with full metadata
4. **Detection Report Generator** - Structured reports with confidence scoring and MITRE ATT&CK mapping
5. **Attack Family Classification** - 4 distinct exploit families with targeted detection

---

## Attack Families Covered

### 1. UI Injection (`ui_injection`)
**Unauthenticated code execution via MCP tool response manipulation**

- HTML injection with cookie exfiltration
- Markdown XSS with javascript: URIs
- SVG injection with event handlers
- CSS-based data exfiltration
- iframe sandbox escape

**Example Detection:**
```python
from monitor.mcp_signatures import get_signatures_by_family

ui_sigs = get_signatures_by_family("ui_injection")
# Returns 5 signatures covering UI injection patterns
```

### 2. Marketplace Poisoning (`marketplace_poisoning`)
**Supply chain attacks via registry/package injection**

- Typosquatting (e.g., `mcp-server-filessystem`)
- Dependency confusion with high version numbers
- Malicious postinstall scripts
- Supply chain backdoors via dependencies

**Example Detection:**
```python
from monitor.mcp_signatures import get_signature_by_cve

marketplace_sigs = get_signature_by_cve("CVE-2026-30625")
# Returns signatures for marketplace poisoning
```

### 3. JSON Config RCE (`json_config_rce`)
**Configuration-based code execution (LiteLLM CVE-2026-30623 style)**

- LiteLLM `custom_llm_provider` injection
- YAML deserialization attacks
- Environment variable injection (NODE_OPTIONS, PYTHONPATH, LD_PRELOAD)
- Server-side template injection (Handlebars, Jinja)
- MCP server configuration abuse

**Example Detection:**
```python
from monitor.mcp_signatures import match_mcp_signatures

matches = match_mcp_signatures(parsed_data)
# Matches config-based RCE patterns in syscall sequences
```

### 4. Command Execution (`command_execution`)
**Shell metacharacter injection and reverse shell patterns**

- Shell metacharacter injection (`;`, `|`, `&&`)
- Command substitution (`$()`, backticks)
- Reverse shells (Bash, Python, Node.js)
- Base64-encoded command execution
- DNS-based data exfiltration

**Example Detection:**
```python
from monitor.mcp_signatures import load_mcp_signatures

sigs = load_mcp_signatures()
cmd_sigs = [s for s in sigs if s["attack_family"] == "command_execution"]
# Returns 3 command execution signatures
```

---

## CVE Database

| CVE ID | Title | CVSS | Severity | Attack Family |
|--------|-------|------|----------|---------------|
| CVE-2026-30623 | LiteLLM Configuration-Based RCE | 9.8 | Critical | json_config_rce |
| CVE-2026-30624 | MCP UI Injection via Tool Response | 8.5 | High | ui_injection |
| CVE-2026-30625 | MCP Marketplace Registry Poisoning | 9.1 | Critical | marketplace_poisoning |
| CVE-2026-30626 | MCP Command Injection via Tool Arguments | 9.8 | Critical | command_execution |
| CVE-2026-30627 | MCP Reverse Shell via Tool Invocation | 9.9 | Critical | command_execution |
| CVE-2026-30628 | MCP Environment Variable Injection | 8.8 | High | json_config_rce |
| CVE-2026-30629 | MCP YAML Deserialization RCE | 9.8 | Critical | json_config_rce |
| CVE-2026-30630 | MCP Server-Side Template Injection | 8.6 | High | json_config_rce |
| CVE-2026-30631 | MCP DNS-Based Data Exfiltration | 7.5 | High | command_execution |

---

## Usage

### 1. Basic Signature Matching

```python
from monitor.parser import parse_strace_log
from monitor.mcp_signatures import match_mcp_signatures

# Parse strace log
parsed_data = parse_strace_log("/path/to/strace.log")

# Match MCP signatures
matches = match_mcp_signatures(parsed_data)

for match in matches:
    print(f"Signature: {match['name']}")
    print(f"  Severity: {match['severity']}/10")
    print(f"  Family: {match['attack_family']}")
    print(f"  Confidence: {match['detection_confidence']}")
    print(f"  CVEs: {', '.join(match['cve_references'])}")
    print(f"  MITRE: {', '.join(match['mitre_techniques'])}")
```

### 2. YARA Scanning with MCP Rules

```python
from monitor.yara import scan_with_yara

# Scan strace log and package directory
yara_matches = scan_with_yara(
    log_path="/path/to/strace.log",
    package_dir="/path/to/extracted/package"
)

# Filter MCP-specific matches
mcp_yara = [m for m in yara_matches if m["rule_name"].startswith("MCP_")]

for match in mcp_yara:
    print(f"Rule: {match['rule_name']}")
    print(f"  Severity: {match['severity']}")
    print(f"  File: {match['file_path']}")
```

### 3. Generate Detection Report

```python
from monitor.mcp_report import generate_mcp_rce_report

report = generate_mcp_rce_report(
    target="mcp-server-filesystem",
    matches=mcp_signature_matches,
    yara_matches=yara_results,
    strace_log="/path/to/strace.log",
    output_path="mcp_detection_report.json"
)

# Access report sections
print(f"Overall Risk: {report['summary']['overall_risk_level']}")
print(f"Total Detections: {report['summary']['total_detections']}")
print(f"CVE Correlations: {len(report['cve_correlations'])}")
print(f"Recommendations: {len(report['recommendations'])}")
```

### 4. CVE Lookup

```python
from monitor.mcp_report import get_cve_details, search_cves_by_family

# Get specific CVE details
cve = get_cve_details("CVE-2026-30623")
print(f"Title: {cve['title']}")
print(f"CVSS: {cve['cvss_score']}")
print(f"Fix: {cve['fix_version']}")

# Search by attack family
config_cves = search_cves_by_family("json_config_rce")
for cve in config_cves:
    print(f"{cve['cve_id']}: {cve['title']}")
```

### 5. Calculate Overall Confidence

```python
from monitor.mcp_report import calculate_overall_confidence

confidence = calculate_overall_confidence(mcp_matches)
print(f"Overall detection confidence: {confidence}")
# Returns weighted average based on severity and individual confidences
```

---

## Integration with TraceTree Pipeline

### Full Analysis Example

```python
from monitor.mcp_signatures import load_mcp_signatures, match_mcp_signatures
from monitor.mcp_report import generate_mcp_rce_report
from monitor.signatures import load_signatures, match_signatures
from monitor.parser import parse_strace_log

def analyze_mcp_server(strace_log_path):
    # Parse strace log
    parsed_data = parse_strace_log(strace_log_path)
    
    # Match standard signatures
    standard_sigs = load_signatures()
    standard_matches = match_signatures(parsed_data, standard_sigs)
    
    # Match MCP-specific signatures
    mcp_matches = match_mcp_signatures(parsed_data)
    
    # Generate comprehensive report
    report = generate_mcp_rce_report(
        target=strace_log_path,
        matches=mcp_matches,
        strace_log=strace_log_path,
        output_path="mcp_report.json"
    )
    
    return report

# Run analysis
report = analyze_mcp_server("/path/to/strace.log")
print(f"Overall Risk: {report['summary']['overall_risk_level']}")
```

See [examples/mcp_rce_detection_example.py](examples/mcp_rce_detection_example.py) for a complete working example.

---

## Files Added

### Core Detection Modules

| File | Description |
|------|-------------|
| `monitor/mcp_signatures.py` | MCP behavioral signatures (10 signatures) |
| `monitor/mcp_report.py` | Detection report generator with CVE database |
| `data/mcp_rce_signatures.yara` | YARA rules for MCP RCE (27 rules) |

### Test & Example Files

| File | Description |
|------|-------------|
| `tests/monitor/test_mcp_rce_detection.py` | Comprehensive test suite |
| `examples/mcp_rce_detection_example.py` | Integration examples |

### Modified Files

| File | Changes |
|------|---------|
| `monitor/__init__.py` | Added exports for new modules |
| `monitor/yara.py` | Integrated MCP YARA rules loading |

---

## Signature Details

### Behavioral Signatures (monitor/mcp_signatures.py)

Each signature includes:
- **name**: Unique identifier
- **description**: Human-readable explanation
- **severity**: Risk level (0-10)
- **syscalls**: Required syscalls for matching
- **sequence**: Ordered syscall pattern (if applicable)
- **attack_family**: Exploit family classification
- **cve_references**: Related CVE IDs
- **mitre_techniques**: MITRE ATT&CK technique IDs
- **detection_confidence**: Base confidence score (0.0-1.0)

**Example Signature:**
```python
{
    "name": "mcp_config_rce_litellm",
    "description": "MCP JSON config RCE (LiteLLM style) — arbitrary code execution via custom_llm_provider injection",
    "severity": 10,
    "syscalls": ["execve", "openat", "read", "connect"],
    "sequence": [
        ["openat", "secret"],
        ["execve", "non_standard"],
        ["connect", "external"]
    ],
    "attack_family": "json_config_rce",
    "cve_references": ["CVE-2026-30623"],
    "mitre_techniques": ["T1059.006", "T1574.007"],
    "detection_confidence": 0.95,
}
```

### YARA Rules (data/mcp_rce_signatures.yara)

**27 rules across 4 categories:**

1. **UI Injection (5 rules)**
   - `MCP_UI_HTML_Injection`
   - `MCP_UI_Markdown_XSS`
   - `MCP_UI_SVG_Injection`
   - `MCP_UI_CSS_Exfiltration`

2. **Marketplace Poisoning (3 rules)**
   - `MCP_Marketplace_Typosquatting`
   - `MCP_Marketplace_DependencyConfusion`
   - `MCP_Marketplace_SupplyChainBackdoor`

3. **JSON Config RCE (5 rules)**
   - `MCP_Config_LiteLLM_Injection`
   - `MCP_Config_YAML_Deserialization`
   - `MCP_Config_EnvVariableInjection`
   - `MCP_Config_TemplateInjection`
   - `MCP_Config_ProtocolHandlerAbuse`

4. **Command Execution (9 rules)**
   - `MCP_Cmd_ShellMetacharacterInjection`
   - `MCP_Cmd_CommandSubstitution`
   - `MCP_Cmd_BashReverseShell`
   - `MCP_Cmd_PythonReverseShell`
   - `MCP_Cmd_NodeJSReverseShell`
   - `MCP_Cmd_EncodedExecution`
   - `MCP_Cmd_FileRedirection`
   - `MCP_Cmd_DNSExfiltration`

5. **MCP Protocol Indicators (5 rules)**
   - `MCP_Protocol_JSONRPC_Adversarial`
   - `MCP_Transport_ScriptInjection`

---

## Detection Report Structure

```json
{
  "metadata": {
    "report_type": "MCP RCE Detection Report",
    "generated_at": "2026-04-21T21:30:00",
    "target": "mcp-server-filesystem",
    "analyzer_version": "TraceTree 1.0.0",
    "disclosure_reference": "OX Security April 2026"
  },
  "summary": {
    "total_detections": 5,
    "overall_risk_level": "critical",
    "max_detection_confidence": 0.98,
    "severity_breakdown": {
      "critical": 3,
      "high": 2,
      "medium": 0,
      "low": 0
    },
    "attack_family_breakdown": {
      "command_execution": 3,
      "json_config_rce": 2
    }
  },
  "detections": [
    {
      "signature_name": "mcp_reverse_shell_injection",
      "severity": 10,
      "attack_family": "command_execution",
      "detection_confidence": 0.98,
      "cve_references": ["CVE-2026-30626", "CVE-2026-30627"],
      "mitre_techniques": ["T1059.004", "T1059.006"],
      "evidence": ["..."]
    }
  ],
  "cve_correlations": [
    {
      "cve_id": "CVE-2026-30627",
      "title": "MCP Reverse Shell via Tool Invocation",
      "cvss_score": 9.9,
      "severity": "critical",
      "affected_products": ["MCP servers with shell execution capabilities"],
      "fix_version": "Network restriction and command allowlisting required"
    }
  ],
  "recommendations": [
    "CRITICAL: Implement strict input validation...",
    "Deploy network restrictions..."
  ]
}
```

---

## Testing

Run the test suite:

```bash
python3 tests/monitor/test_mcp_rce_detection.py
```

Expected output:
```
✓ 10 MCP-specific behavioral signatures
✓ 27 YARA rules for MCP RCE detection
✓ 9 CVE correlations (CVE-2026-30623 to CVE-2026-30631)
✓ Detection report with CVE correlation and confidence scoring
✓ Attack family classification (4 families)
✓ MITRE ATT&CK technique mapping
```

---

## MITRE ATT&CK Coverage

| Technique ID | Name | Covered By |
|--------------|------|------------|
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Command Execution signatures |
| T1059.006 | Command and Scripting Interpreter: Python | Config RCE signatures |
| T1059.007 | Command and Scripting Interpreter: JavaScript | UI Injection signatures |
| T1189 | Drive-by Compromise | UI Injection signatures |
| T1195.001 | Supply Chain Compromise: Software Dependencies | Marketplace Poisoning signatures |
| T1574.007 | Hijack Execution Flow: Path Interception | Config RCE signatures |
| T1048.001 | Exfiltration Over Alternative Protocol: DNS | Command Execution signatures |
| T1005 | Data from Local System | UI Injection signatures |
| T1071.004 | Application Layer Protocol: DNS | Command Execution signatures |

---

## References

- **OX Security April 2026 Disclosure**: Original research on MCP server vulnerabilities
- **MITRE ATT&CK Framework**: https://attack.mitre.org/
- **MCP Specification**: https://spec.modelcontextprotocol.io/
- **NVD CVE Database**: https://nvd.nist.gov/vuln/

---

## License

Same as TraceTree project license.

---

## Contributing

To add new MCP RCE signatures:

1. Add behavioral signature to `MCP_SIGNATURES` in `monitor/mcp_signatures.py`
2. Add corresponding YARA rule to `data/mcp_rce_signatures.yara`
3. Add CVE details to `CVE_DATABASE` in `monitor/mcp_report.py`
4. Update tests in `tests/monitor/test_mcp_rce_detection.py`

---

## Support

For issues or questions:
- Open an issue on GitHub
- Review existing test cases for usage patterns
- Check the example file: `examples/mcp_rce_detection_example.py`
