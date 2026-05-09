"""
Test script for MCP Payload Generator

Demonstrates how to use the PayloadGenerator module to:
1. Generate all payloads
2. Generate specific families
3. Access individual payload properties
4. Integrate with TraceTree's sandbox testing
"""

from mcp.payload_generator import PayloadGenerator


def test_generate_all():
    """Test generating all payload families."""
    print("=" * 60)
    print("TEST: Generate All Payloads")
    print("=" * 60)
    
    generator = PayloadGenerator()
    all_payloads = generator.generate_all()
    
    print(f"Total payloads generated: {len(all_payloads)}")
    print()
    
    # Group by family
    families = {}
    for payload in all_payloads:
        family = payload["exploit_family"]
        if family not in families:
            families[family] = []
        families[family].append(payload)
    
    print("Payloads by family:")
    for family, payloads in families.items():
        print(f"  - {family}: {len(payloads)} payloads")
    
    print()
    return all_payloads


def test_generate_specific_family():
    """Test generating a specific exploit family."""
    print("=" * 60)
    print("TEST: Generate Specific Family (command_execution)")
    print("=" * 60)
    
    generator = PayloadGenerator()
    cmd_payloads = generator.generate_family("command_execution")
    
    print(f"Command execution payloads: {len(cmd_payloads)}")
    print()
    
    for i, payload in enumerate(cmd_payloads[:3], 1):  # Show first 3
        print(f"Payload {i}:")
        print(f"  Type: {payload['payload_type']}")
        print(f"  Severity: {payload['severity']}")
        print(f"  Description: {payload['description']}")
        print(f"  Expected syscalls: {', '.join(payload['expected_syscalls'])}")
        print(f"  MITRE: {payload.get('mitre_technique', 'N/A')}")
        print()
    
    return cmd_payloads


def test_payload_properties():
    """Test accessing individual payload properties."""
    print("=" * 60)
    print("TEST: Payload Properties Access")
    print("=" * 60)
    
    generator = PayloadGenerator()
    all_payloads = generator.generate_all()
    
    # Show critical severity payloads
    critical_payloads = [p for p in all_payloads if p["severity"] == "critical"]
    print(f"Critical severity payloads: {len(critical_payloads)}")
    print()
    
    # Show first critical payload details
    if critical_payloads:
        payload = critical_payloads[0]
        print("Sample critical payload:")
        print(f"  Type: {payload['payload_type']}")
        print(f"  Family: {payload['exploit_family']}")
        print(f"  Severity: {payload['severity']}")
        print(f"  MITRE Technique: {payload.get('mitre_technique', 'N/A')}")
        print(f"  Description: {payload['description']}")
        print(f"  Raw payload: {payload['raw_payload'][:100]}...")
        print(f"  Expected syscalls: {payload['expected_syscalls']}")
        if "cve_reference" in payload:
            print(f"  CVE Reference: {payload['cve_reference']}")
    
    print()
    return critical_payloads


def test_export_json():
    """Test JSON export functionality."""
    print("=" * 60)
    print("TEST: JSON Export")
    print("=" * 60)
    
    generator = PayloadGenerator()
    
    # Export all
    output_path = generator.export_json("test_all_payloads.json")
    print(f"Exported all payloads to: {output_path}")
    
    # Export specific families
    output_path2 = generator.export_json(
        "test_specific_payloads.json",
        families=["ui_injection", "json_config_rce"]
    )
    print(f"Exported specific families to: {output_path2}")
    
    print()


def test_sandbox_integration():
    """
    Demonstrate how to integrate payloads with TraceTree's sandbox.
    
    This shows the conceptual integration - actual execution would
    require Docker and proper sandbox setup.
    """
    print("=" * 60)
    print("TEST: Sandbox Integration Example")
    print("=" * 60)
    
    generator = PayloadGenerator()
    cmd_payloads = generator.generate_family("command_execution")
    
    print("Example: Testing command_execution payloads in sandbox")
    print()
    
    for payload in cmd_payloads[:2]:  # Test first 2
        print(f"Testing: {payload['payload_type']}")
        print(f"  Severity: {payload['severity']}")
        print(f"  Expected syscalls to detect: {payload['expected_syscalls']}")
        print()
        print("  Integration steps:")
        print("  1. Create MCP server with vulnerable tool")
        print(f"  2. Inject payload: {payload['raw_payload'][:80]}...")
        print("  3. Run in TraceTree sandbox with strace monitoring")
        print(f"  4. Verify detection of syscalls: {', '.join(payload['expected_syscalls'])}")
        print("  5. Check if classifier flags as COMMAND_INJECTION")
        print()
    
    print("Note: Actual sandbox execution requires Docker setup")
    print()


def main():
    """Run all tests."""
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 10 + "MCP Payload Generator Test Suite" + " " * 16 + "║")
    print("╚" + "=" * 58 + "╝")
    print()
    
    # Run tests
    test_generate_all()
    test_generate_specific_family()
    test_payload_properties()
    test_export_json()
    test_sandbox_integration()
    
    print("=" * 60)
    print("All tests completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
