"""
MCP RCE Detection Integration Example

Shows how to integrate the new MCP RCE detection capabilities into
TraceTree's existing analysis pipeline.

This example demonstrates:
1. Loading MCP signatures alongside standard signatures
2. Running YARA scans with MCP rules
3. Generating detection reports with CVE correlation
4. Combining ML detection with signature-based detection
"""

import json
from pathlib import Path
from monitor.mcp_signatures import load_mcp_signatures, match_mcp_signatures
from monitor.mcp_report import generate_mcp_rce_report, calculate_overall_confidence
from monitor.signatures import load_signatures, match_signatures
from monitor.yara import scan_with_yara


def analyze_mcp_server_complete(
    strace_log_path: str,
    package_dir: str = None,
    output_dir: str = "mcp_analysis_results",
):
    """
    Complete MCP server analysis with RCE detection.

    Args:
        strace_log_path: Path to strace log file
        package_dir: Optional path to extracted package directory
        output_dir: Directory to save analysis results
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("MCP Server Complete Analysis with RCE Detection")
    print("=" * 70)
    print()

    # Step 1: Parse strace log (using existing TraceTree parser)
    print("[1/5] Parsing strace log...")
    from monitor.parser import parse_strace_log
    
    try:
        parsed_data = parse_strace_log(strace_log_path)
        print(f"  ✓ Parsed {len(parsed_data.get('events', []))} events")
    except Exception as e:
        print(f"  ✗ Failed to parse strace log: {e}")
        return
    print()

    # Step 2: Load and match standard signatures
    print("[2/5] Matching standard behavioral signatures...")
    standard_sigs = load_signatures()
    standard_matches = match_signatures(parsed_data, standard_sigs)
    print(f"  ✓ Matched {len(standard_matches)} standard signature(s)")
    print()

    # Step 3: Load and match MCP-specific signatures
    print("[3/5] Matching MCP RCE signatures...")
    mcp_sigs = load_mcp_signatures()
    mcp_matches = match_mcp_signatures(parsed_data)
    print(f"  ✓ Matched {len(mcp_matches)} MCP RCE signature(s)")
    
    if mcp_matches:
        print()
        print("  MCP RCE Detections:")
        for match in mcp_matches:
            print(f"    - {match['name']}")
            print(f"      Severity: {match['severity']}/10")
            print(f"      Family: {match.get('attack_family', 'N/A')}")
            print(f"      Confidence: {match.get('detection_confidence', 0.0)}")
            print(f"      CVEs: {', '.join(match.get('cve_references', []))}")
            print()
    print()

    # Step 4: Run YARA scan with MCP rules
    print("[4/5] Running YARA scan (including MCP rules)...")
    yara_matches = scan_with_yara(strace_log_path, package_dir)
    print(f"  ✓ Found {len(yara_matches)} YARA match(es)")
    
    # Filter MCP-specific YARA matches
    mcp_yara_matches = [
        m for m in yara_matches
        if m.get("rule_name", "").startswith("MCP_")
    ]
    if mcp_yara_matches:
        print(f"    ({len(mcp_yara_matches)} MCP-specific)")
        for match in mcp_yara_matches[:3]:  # Show first 3
            print(f"    - {match['rule_name']} (severity: {match.get('severity', 'N/A')})")
    print()

    # Step 5: Generate comprehensive detection report
    print("[5/5] Generating MCP RCE detection report...")
    report = generate_mcp_rce_report(
        target=Path(strace_log_path).stem,
        matches=mcp_matches,
        yara_matches=mcp_yara_matches,
        strace_log=strace_log_path,
        output_path=str(output_path / "mcp_rce_report.json"),
    )
    
    # Calculate overall confidence
    overall_confidence = calculate_overall_confidence(mcp_matches)
    print(f"  ✓ Report saved to: {output_path / 'mcp_rce_report.json'}")
    print(f"  ✓ Overall detection confidence: {overall_confidence}")
    print()

    # Print summary
    summary = report["summary"]
    print("=" * 70)
    print("ANALYSIS SUMMARY")
    print("=" * 70)
    print(f"Target: {report['metadata']['target']}")
    print(f"Overall Risk: {summary['overall_risk_level'].upper()}")
    print(f"Total Detections: {summary['total_detections']}")
    print(f"  - Signature matches: {summary['signature_matches']}")
    print(f"  - YARA matches: {summary['yara_matches']}")
    print(f"Max Confidence: {summary['max_detection_confidence']}")
    print()
    
    # Show CVE correlations
    if report["cve_correlations"]:
        print("CVE Correlations:")
        for cve in report["cve_correlations"]:
            print(f"  - {cve['cve_id']}: {cve['title']}")
            print(f"    CVSS: {cve['cvss_score']} | Severity: {cve['severity']}")
        print()
    
    # Show top recommendations
    if report["recommendations"]:
        print("Top Recommendations:")
        for i, rec in enumerate(report["recommendations"][:3], 1):
            print(f"  {i}. {rec[:100]}...")
        print()
    
    print("=" * 70)
    print("Analysis complete!")
    print("=" * 70)

    return report


def analyze_mcp_with_mock_data():
    """
    Example using mock data to demonstrate the detection pipeline.
    """
    print("\n")
    print("=" * 70)
    print("MCP RCE Detection - Mock Data Example")
    print("=" * 70)
    print()

    # Create mock parsed data simulating a LiteLLM config RCE attack
    mock_parsed_data = {
        "events": [
            {
                "type": "openat",
                "target": "/etc/mcp/.env",
                "details": {},
                "timestamp": 1000.0,
            },
            {
                "type": "read",
                "target": "/etc/mcp/.env",
                "details": {},
                "timestamp": 1001.0,
            },
            {
                "type": "execve",
                "target": "/usr/bin/custom-binary",  # non_standard
                "details": {},
                "timestamp": 1002.0,
            },
            {
                "type": "connect",
                "target": "evil.com:443",
                "details": {"category": "suspicious"},
                "timestamp": 1003.0,
            },
        ],
        "flags": ["config_read", "external_connection"],
        "network_destinations": [
            {"ip": "evil.com", "port": 443, "category": "suspicious"}
        ],
    }

    # Match MCP signatures
    print("Matching MCP signatures against mock data...")
    mcp_matches = match_mcp_signatures(mock_parsed_data)
    print(f"Detected {len(mcp_matches)} MCP RCE signature(s)")
    print()

    # Generate report
    print("Generating detection report...")
    report = generate_mcp_rce_report(
        target="mock-mcp-server",
        matches=mcp_matches,
    )

    # Display results
    summary = report["summary"]
    print()
    print("Results:")
    print(f"  Overall Risk: {summary['overall_risk_level'].upper()}")
    print(f"  Detections: {summary['total_detections']}")
    print(f"  Max Confidence: {summary['max_detection_confidence']}")
    print()

    if report["cve_correlations"]:
        print("CVE Matches:")
        for cve in report["cve_correlations"]:
            print(f"  ✓ {cve['cve_id']}: {cve['title']}")
    print()

    return report


if __name__ == "__main__":
    # Run mock example (no actual strace log required)
    analyze_mcp_with_mock_data()
    
    print("\n")
    print("To analyze a real strace log, use:")
    print("  analyze_mcp_server_complete('/path/to/strace.log')")
    print()
