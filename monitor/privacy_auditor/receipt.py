"""
Offline Truth Receipt generator and Rich console renderer.
Evaluates recorded network flows against privacy claims and produces verifiable audit receipts.
"""
import json
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from monitor.privacy_auditor.schema import PrivacyReceipt, NetworkFlow
from monitor.privacy_auditor.speculative_executor import ExecutionSummary
from monitor.privacy_auditor.network_correlator import NetworkCorrelator


class ReceiptBuilder:
    """Constructs and formats the final Privacy & Offline Truth Receipt."""

    @staticmethod
    def build_receipt(
        target_app: str,
        bundle_id: Optional[str],
        summary: ExecutionSummary,
        correlator: NetworkCorrelator,
        entitlement_violations: Optional[List[Dict[str, Any]]] = None,
        inconclusive_reason: Optional[str] = None,
    ) -> PrivacyReceipt:
        """Evaluate session results and build a structured PrivacyReceipt."""
        all_flows = correlator.get_all_flows()
        violations = [v.to_dict() for v in correlator.get_violations()]

        if entitlement_violations:
            for ev in entitlement_violations:
                violations.append({
                    "category": "entitlement_violation",
                    "host": "macOS Kernel",
                    "detail": ev["detail"],
                    "associated_step_id": None,
                })

        # Determine verdict
        if inconclusive_reason or summary.stopped_reason in ("target_process_inaccessible", "target_not_found"):
            verdict = "INCONCLUSIVE"
        elif len(violations) == 0 and len(all_flows) == 0:
            verdict = "OFFLINE_VERIFIED"
        elif len(violations) == 0 and all(f.category == "whitelisted_auth" for f in all_flows):
            verdict = "CONDITIONAL_AUTH_ONLY"
        else:
            verdict = "PRIVACY_VIOLATION"

        now_iso = datetime.now(timezone.utc).isoformat()

        return PrivacyReceipt(
            target_app=target_app,
            bundle_id=bundle_id,
            timestamp=now_iso,
            audit_duration_seconds=round(summary.duration_seconds, 2),
            steps_executed=summary.total_steps_executed,
            replans_triggered=summary.replans_triggered,
            total_outbound_requests=len(all_flows),
            violation_count=len(violations),
            verdict=verdict,
            violations=violations,
            flows=[f.to_dict() for f in all_flows],
            diagnostic_note=inconclusive_reason,
        )

    @staticmethod
    def render_console_report(receipt: PrivacyReceipt, console: Console) -> None:
        """Render an audit receipt to the terminal using Rich styling."""
        if receipt.verdict == "OFFLINE_VERIFIED":
            status_text = "[bold green]✔ OFFLINE CLAIM VERIFIED[/bold green] (Zero Outbound Traffic)"
            border_color = "green"
        elif receipt.verdict == "CONDITIONAL_AUTH_ONLY":
            status_text = "[bold yellow]⚠ CONDITIONAL OFFLINE[/bold yellow] (OAuth / Auth Traffic Only)"
            border_color = "yellow"
        elif receipt.verdict == "INCONCLUSIVE":
            status_text = "[bold yellow]⚠ INCONCLUSIVE[/bold yellow] (Target Application Inaccessible / Not Audited)"
            border_color = "yellow"
        else:
            status_text = f"[bold red]✖ PRIVACY VIOLATION DETECTED[/bold red] ({receipt.violation_count} unauthorized transmissions)"
            border_color = "red"

        # Summary Table
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_row("[bold]Target Application:[/]", receipt.target_app)
        if receipt.bundle_id:
            table.add_row("[bold]Bundle Identifier:[/]", receipt.bundle_id)
        table.add_row("[bold]Audit Verdict:[/]", status_text)
        if receipt.diagnostic_note:
            table.add_row("[bold]Diagnostic Note:[/]", f"[yellow]{receipt.diagnostic_note}[/]")
        table.add_row("[bold]Audit Duration:[/]", f"{receipt.audit_duration_seconds:.1f}s")
        table.add_row("[bold]UI Actions Executed:[/]", str(receipt.steps_executed))
        table.add_row("[bold]Speculative Drift / Replans:[/]", str(receipt.replans_triggered))
        table.add_row("[bold]Total Network Requests:[/]", str(receipt.total_outbound_requests))
        table.add_row("[bold]Privacy Violations:[/]", str(receipt.violation_count))

        console.print(
            Panel(
                table,
                title="[bold]TraceTree Offline Truth Receipt[/bold]",
                border_style=border_color,
                expand=False,
            )
        )

        # Print Violations Breakdown if any exist
        if receipt.violations:
            v_table = Table(title="Detected Privacy Violations & Telemetry Beacons", expand=False)
            v_table.add_column("Step", style="dim", width=6)
            v_table.add_column("Category", style="bold red")
            v_table.add_column("Destination Host", style="cyan")
            v_table.add_column("Details", style="white")

            for v in receipt.violations:
                step_str = f"#{v.get('associated_step_id')}" if v.get("associated_step_id") else "Idle"
                v_table.add_row(
                    step_str,
                    v.get("category", "unknown").upper(),
                    v.get("host", ""),
                    v.get("detail", ""),
                )
            console.print(v_table)
