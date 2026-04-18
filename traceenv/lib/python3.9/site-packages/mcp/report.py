"""
MCP analysis report generation.

Produces a structured report containing:
- Tool manifest (discovered tools, schemas, descriptions)
- Prompt injection scan results
- Per-tool syscall summary
- Threat detections with evidence
- Adversarial probe results
- Overall risk score
- Comparison to known baseline
"""

import json
from typing import Dict, Any, List, Optional
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.text import Text
from rich.align import Align

console = Console()


def generate_mcp_report(
    target: str,
    server_type: Optional[str],
    tools: List[Dict[str, Any]],
    features: Dict[str, Any],
    threats: List[Dict[str, Any]],
    prompt_injection_findings: List[Dict[str, Any]],
    adversarial_log: List[Dict[str, Any]],
    risk_score: str,
    baseline_comparison: Dict[str, Any],
    is_malicious: bool = False,
    ml_confidence: float = 0.0,
    output_format: str = "report",
) -> str:
    """
    Generate the full MCP analysis report.

    Args:
        target: The package name or path that was analyzed.
        server_type: Detected server type (filesystem, github, etc.).
        tools: Tool manifest from tools/list.
        features: Extracted MCP features dict.
        threats: Triggered threat categories.
        prompt_injection_findings: Prompt injection scan results.
        adversarial_log: Adversarial probe results.
        risk_score: Overall risk rating (low/medium/high/critical).
        baseline_comparison: Comparison to known server baseline.
        is_malicious: ML classifier verdict.
        ml_confidence: ML classifier confidence percentage.
        output_format: 'report' for Rich console, 'json' for machine-readable.

    Returns:
        Rendered report string (for JSON output) or prints to console.
    """
    if output_format == "json":
        return _generate_json_report(
            target, server_type, tools, features, threats,
            prompt_injection_findings, adversarial_log,
            risk_score, baseline_comparison, is_malicious, ml_confidence,
        )
    else:
        _generate_rich_report(
            target, server_type, tools, features, threats,
            prompt_injection_findings, adversarial_log,
            risk_score, baseline_comparison, is_malicious, ml_confidence,
        )
        return ""


def _generate_json_report(
    target: str,
    server_type: Optional[str],
    tools: List[Dict[str, Any]],
    features: Dict[str, Any],
    threats: List[Dict[str, Any]],
    prompt_injection_findings: List[Dict[str, Any]],
    adversarial_log: List[Dict[str, Any]],
    risk_score: str,
    baseline_comparison: Dict[str, Any],
    is_malicious: bool,
    ml_confidence: float,
) -> str:
    """Generate a machine-readable JSON report."""

    # Clean features for JSON serialization (remove non-serializable types)
    clean_features = {}
    for k, v in features.items():
        if k == "events_by_tool":
            # Only store counts, not full event objects
            clean_features[k] = {
                tool: len(evts) for tool, evts in v.items()
            }
        elif isinstance(v, (str, int, float, bool, list, dict, type(None))):
            clean_features[k] = v

    report = {
        "target": target,
        "server_type": server_type or "unknown",
        "risk_score": risk_score.upper(),
        "ml_verdict": "MALICIOUS" if is_malicious else "CLEAN",
        "ml_confidence": ml_confidence,
        "tool_manifest": tools,
        "prompt_injection_scan": prompt_injection_findings,
        "per_tool_syscall_summary": {
            tool: {
                "total_syscalls": len(evts),
                "syscall_categories": _syscall_categories(
                    [e for e in evts if isinstance(e, dict)]
                ),
            }
            for tool, evts in features.get("events_by_tool", {}).items()
        },
        "threat_detections": threats,
        "adversarial_probe_results": [
            {
                "tool_name": r["tool_name"],
                "payload": r["payload"],
                "server_crashed": r.get("server_crashed", False),
                "response": str(r.get("response", ""))[:500],
            }
            for r in adversarial_log
        ],
        "features": clean_features,
        "baseline_comparison": baseline_comparison,
    }

    return json.dumps(report, indent=2, default=str)


def _generate_rich_report(
    target: str,
    server_type: Optional[str],
    tools: List[Dict[str, Any]],
    features: Dict[str, Any],
    threats: List[Dict[str, Any]],
    prompt_injection_findings: List[Dict[str, Any]],
    adversarial_log: List[Dict[str, Any]],
    risk_score: str,
    baseline_comparison: Dict[str, Any],
    is_malicious: bool,
    ml_confidence: float,
):
    """Render the full report to the Rich console."""

    # --- Header ---
    console.print("\n")
    header_text = Text(f" MCP SECURITY ANALYSIS REPORT ", style="bold white on blue")
    console.print(Align.center(header_text))
    console.print(Align.center(Text(f"Target: {target}", style="cyan")))
    if server_type:
        console.print(Align.center(Text(f"Server Type: {server_type}", style="dim cyan")))
    console.print("\n")

    # --- Risk Score ---
    risk_colors = {"low": "green", "medium": "yellow", "high": "orange3", "critical": "red"}
    risk_color = risk_colors.get(risk_score, "white")
    risk_style = f"bold white on {risk_color}"

    console.print(Align.center(Panel(
        Text(f"\n  {risk_score.upper()}  \n", style=risk_style, justify="center"),
        title="Overall Risk Score",
        border_style=risk_color,
    )))
    console.print()

    # --- ML Verdict (from existing TraceTree pipeline) ---
    console.print(Panel(
        f"ML Verdict: {'[bold red]MALICIOUS[/]' if is_malicious else '[bold green]CLEAN[/]'}  "
        f"(confidence: {ml_confidence}%)",
        title="[bold]TraceTree ML Analysis[/]",
        border_style="magenta",
        expand=False,
    ))
    console.print()

    # --- Tool Manifest ---
    if tools:
        tool_table = Table(show_header=True, header_style="bold cyan", border_style="cyan")
        tool_table.add_column("#", width=4)
        tool_table.add_column("Tool Name", style="bold magenta")
        tool_table.add_column("Description")
        tool_table.add_column("Parameters")

        for i, tool in enumerate(tools, 1):
            name = tool.get("name", "unknown")
            desc = (tool.get("description", "") or "")[:80]
            params = ", ".join(tool.get("inputSchema", {}).get("properties", {}).keys())
            tool_table.add_row(str(i), name, desc, params)

        console.print(Panel(tool_table, title="[bold]Tool Manifest[/]", border_style="cyan"))
        console.print()

    # --- Prompt Injection Scan ---
    if prompt_injection_findings:
        findings_tree = Tree("[bold red]Prompt Injection Findings[/]")
        for finding in prompt_injection_findings:
            branch = findings_tree.add(
                f"[bold]{finding.get('tool_name', 'unknown')}[/] — {finding.get('location', '')}"
            )
            for item in finding.get("findings", []):
                branch.add(f"[red]{item}[/]")
        console.print(Panel(findings_tree, title="[bold red]⚠ Prompt Injection Scan[/]", border_style="red"))
    else:
        console.print(Panel(
            "[bold green]No prompt injection patterns detected in tool descriptions.[/]",
            title="[bold]Prompt Injection Scan[/]",
            border_style="green",
            expand=False,
        ))
    console.print()

    # --- Per-Tool Syscall Summary ---
    events_by_tool = features.get("events_by_tool", {})
    if events_by_tool:
        syscall_table = Table(show_header=True, header_style="bold yellow", border_style="yellow")
        syscall_table.add_column("Tool", style="bold magenta")
        syscall_table.add_column("Total Syscalls", justify="right")
        syscall_table.add_column("Categories")

        for tool_name, evts in events_by_tool.items():
            categories = _syscall_categories(evts)
            syscall_table.add_row(
                tool_name,
                str(len(evts)),
                ", ".join(sorted(categories))[:60],
            )

        console.print(Panel(syscall_table, title="[bold]Per-Tool Syscall Summary[/]", border_style="yellow"))
        console.print()

    # --- Threat Detections ---
    if threats:
        threat_tree = Tree("[bold red]Threat Detections[/]")
        for threat in threats:
            severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
                threat["severity"], "⚪"
            )
            branch = threat_tree.add(
                f"{severity_icon} [bold]{threat['name']}[/] "
                f"([italic]{threat['severity'].upper()}[/])"
            )
            for ev in threat.get("evidence", []):
                branch.add(f"[yellow]{ev}[/]")
        console.print(Panel(threat_tree, title="[bold red]⚠ Threat Detections[/]", border_style="red"))
    else:
        console.print(Panel(
            "[bold green]No MCP-specific threats detected.[/]",
            title="[bold]Threat Analysis[/]",
            border_style="green",
            expand=False,
        ))
    console.print()

    # --- Adversarial Probe Results ---
    if adversarial_log:
        probe_table = Table(show_header=True, header_style="bold red", border_style="red")
        probe_table.add_column("Tool", style="bold magenta")
        probe_table.add_column("Payload", style="red")
        probe_table.add_column("Crashed", justify="center")
        probe_table.add_column("Response")

        for probe in adversarial_log[:20]:  # Limit to 20 rows
            probe_table.add_row(
                probe.get("tool_name", "unknown"),
                probe.get("payload", "")[:40],
                "YES" if probe.get("server_crashed") else "no",
                str(probe.get("response", ""))[:60] or "N/A",
            )

        console.print(Panel(probe_table, title="[bold]Adversarial Probe Results[/]", border_style="red"))
        console.print()

    # --- Baseline Comparison ---
    if baseline_comparison:
        status = baseline_comparison.get("status", "unknown")
        status_color = "green" if status == "within_baseline" else "red"
        deviations = baseline_comparison.get("deviations", [])

        if deviations:
            dev_tree = Tree(f"[bold {status_color}]{status.replace('_', ' ').title()}[/]")
            for dev in deviations:
                dev_tree.add(f"[yellow]{dev}[/]")
            console.print(Panel(dev_tree, title="[bold]Baseline Comparison[/]", border_style=status_color))
        else:
            console.print(Panel(
                f"[bold green]Behavior within expected baseline for {status.replace('_', ' ')} server.[/]",
                title="[bold]Baseline Comparison[/]",
                border_style="green",
                expand=False,
            ))
        console.print()

    console.print("─" * console.width)
    console.print(Align.center(Text(f"Report generated by TraceTree MCP Security Analyzer", style="dim")))
    console.print()


def _syscall_categories(events: List[Dict[str, Any]]) -> List[str]:
    """Extract unique syscall categories from a list of events."""
    categories = set()
    for evt in events:
        if not isinstance(evt, dict):
            continue
        syscall = evt.get("syscall", "unknown")
        if syscall in ("connect", "socket", "sendto", "recvfrom"):
            categories.add("network")
        elif syscall in ("execve", "clone", "fork"):
            categories.add("process")
        elif syscall in ("openat", "open", "stat", "access"):
            categories.add("filesystem")
        elif syscall in ("read", "write"):
            categories.add("io")
        else:
            categories.add(syscall)
    return sorted(categories)
