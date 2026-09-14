"""
TraceTree Autonomous Privacy & Offline Verifier.
Combines macOS Accessibility/CDP exploration, speculative batch action planning,
and real-time network flow correlation to audit offline privacy claims.
"""
from monitor.privacy_auditor.schema import (
    UIElement,
    Precondition,
    BatchStep,
    BatchPlan,
    NetworkFlow,
    PrivacyReceipt,
)
from monitor.privacy_auditor.ax_scraper import MacOSAccessibilityScraper
from monitor.privacy_auditor.cdp_client import ElectronCDPClient
from monitor.privacy_auditor.network_correlator import NetworkCorrelator
from monitor.privacy_auditor.batch_planner import BatchPlanner
from monitor.privacy_auditor.speculative_executor import (
    SpeculativeExecutor,
    ExecutionSummary,
)
from monitor.privacy_auditor.receipt import ReceiptBuilder
from monitor.privacy_auditor.socket_monitor import LiveSocketAuditor

__all__ = [
    "UIElement",
    "Precondition",
    "BatchStep",
    "BatchPlan",
    "NetworkFlow",
    "PrivacyReceipt",
    "MacOSAccessibilityScraper",
    "ElectronCDPClient",
    "NetworkCorrelator",
    "BatchPlanner",
    "SpeculativeExecutor",
    "ExecutionSummary",
    "ReceiptBuilder",
    "LiveSocketAuditor",
]
