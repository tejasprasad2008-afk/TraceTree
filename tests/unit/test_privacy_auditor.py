"""
Unit tests for the TraceTree Autonomous Privacy & Offline Verifier.
"""
import pytest
from monitor.privacy_auditor.schema import (
    UIElement,
    Precondition,
    BatchStep,
    BatchPlan,
    NetworkFlow,
    PrivacyReceipt,
)
from monitor.privacy_auditor.batch_planner import BatchPlanner
from monitor.privacy_auditor.speculative_executor import SpeculativeExecutor, ExecutionSummary
from monitor.privacy_auditor.network_correlator import NetworkCorrelator
from monitor.privacy_auditor.receipt import ReceiptBuilder
from monitor.privacy_auditor.ax_scraper import MacOSAccessibilityScraper
from monitor.privacy_auditor.cdp_client import ElectronCDPClient


def test_schema_models_and_precondition_matching():
    elem = UIElement(id="btn_settings", role="AXButton", title="Settings & Privacy")
    precond_valid = Precondition(expected_role="AXButton", expected_title="settings")
    precond_invalid = Precondition(expected_role="AXCheckBox", expected_title="settings")

    assert precond_valid.matches(elem) is True
    assert precond_invalid.matches(elem) is False

    step = BatchStep(
        step=1,
        action="click",
        target_id="btn_settings",
        precondition=precond_valid,
        expected_outcome="Settings panel opens",
    )
    plan = BatchPlan(thought_process="Testing settings flow", batch_plan=[step])
    plan_dict = plan.to_dict()

    restored = BatchPlan.from_dict(plan_dict)
    assert restored.thought_process == "Testing settings flow"
    assert len(restored.batch_plan) == 1
    assert restored.batch_plan[0].target_id == "btn_settings"


def test_batch_planner_json_parsing_with_markdown_fence():
    planner = BatchPlanner()
    raw_llm_output = """
Here is the predicted batch plan:
```json
{
  "thought_process": "Navigate to privacy toggles",
  "batch_plan": [
    {
      "step": 1,
      "action": "click",
      "target_id": "btn_pref",
      "precondition": {
        "expected_role": "AXButton",
        "expected_title": "Preferences"
      },
      "expected_outcome": "Preferences window appears"
    }
  ]
}
```
Let me know if you need more steps.
"""
    plan = planner.parse_json_response(raw_llm_output)
    assert plan.thought_process == "Navigate to privacy toggles"
    assert len(plan.batch_plan) == 1
    assert plan.batch_plan[0].step == 1
    assert plan.batch_plan[0].precondition.expected_title == "Preferences"


def test_batch_planner_malformed_fallback():
    planner = BatchPlanner()
    malformed_output = "I am not returning JSON here."
    plan = planner.parse_json_response(malformed_output)
    assert "Failed to parse" in plan.thought_process
    assert len(plan.batch_plan) == 0


def test_speculative_executor_success_chain():
    elements = [
        UIElement(id="btn_menu", role="AXButton", title="Menu"),
        UIElement(id="btn_export", role="AXButton", title="Export Data"),
    ]
    correlator = NetworkCorrelator()
    clicks_dispatched = []

    def mock_ui_provider():
        return elements

    def mock_action_dispatcher(elem_id, action, text):
        clicks_dispatched.append(elem_id)
        return True

    batch = BatchPlan(
        thought_process="Click menu then export",
        batch_plan=[
            BatchStep(
                step=1,
                action="click",
                target_id="btn_menu",
                precondition=Precondition(expected_role="AXButton", expected_title="Menu"),
                expected_outcome="Menu opens",
            ),
            BatchStep(
                step=2,
                action="click",
                target_id="btn_export",
                precondition=Precondition(expected_role="AXButton", expected_title="Export"),
                expected_outcome="Export dialog shows",
            ),
        ],
    )

    executor = SpeculativeExecutor(
        ui_provider=mock_ui_provider,
        action_dispatcher=mock_action_dispatcher,
        planner=BatchPlanner(),
        network_correlator=correlator,
        debounce_seconds=0.01,
    )
    summary = ExecutionSummary()
    success, failure = executor.execute_batch(batch, summary)

    assert success is True
    assert failure is None
    assert summary.total_steps_executed == 2
    assert summary.replans_triggered == 0
    assert clicks_dispatched == ["btn_menu", "btn_export"]


def test_speculative_executor_drift_and_immediate_halt():
    # Only step 1 element exists; step 2 element is missing
    elements = [
        UIElement(id="btn_settings", role="AXButton", title="Settings"),
    ]
    correlator = NetworkCorrelator()
    clicks_dispatched = []

    def mock_ui_provider():
        return elements

    def mock_action_dispatcher(elem_id, action, text):
        clicks_dispatched.append(elem_id)
        return True

    batch = BatchPlan(
        thought_process="Click settings then missing cloud toggle",
        batch_plan=[
            BatchStep(
                step=1,
                action="click",
                target_id="btn_settings",
                precondition=Precondition(expected_role="AXButton", expected_title="Settings"),
                expected_outcome="Settings panel opens",
            ),
            BatchStep(
                step=2,
                action="click",
                target_id="chk_cloud_sync",
                precondition=Precondition(expected_role="AXCheckBox", expected_title="Cloud Sync"),
                expected_outcome="Cloud sync toggled",
            ),
        ],
    )

    executor = SpeculativeExecutor(
        ui_provider=mock_ui_provider,
        action_dispatcher=mock_action_dispatcher,
        planner=BatchPlanner(),
        network_correlator=correlator,
        debounce_seconds=0.01,
    )
    summary = ExecutionSummary()
    success, failure = executor.execute_batch(batch, summary)

    # Step 1 was clicked, but step 2 halted immediately due to missing element
    assert success is False
    assert failure is not None
    assert "Step 2 halted" in failure
    assert summary.total_steps_executed == 1
    assert summary.replans_triggered == 1
    assert clicks_dispatched == ["btn_settings"]


def test_network_correlator_and_telemetry_detection():
    correlator = NetworkCorrelator()

    # Step 1: Click Settings
    correlator.set_active_action(step_id=1, description="CLICK Settings")
    flow1 = correlator.record_request("GET", "https://accounts.google.com/o/oauth2/auth", payload_size=120)
    assert flow1.associated_step_id == 1
    assert flow1.category == "whitelisted_auth"
    assert flow1.is_violation is False

    # Step 2: Click Local Processing
    correlator.set_active_action(step_id=2, description="CLICK Local Process")
    flow2 = correlator.record_request("POST", "https://api.segment.io/v1/t", payload_size=850)
    assert flow2.associated_step_id == 2
    assert flow2.category == "telemetry"
    assert flow2.is_violation is True

    violations = correlator.get_violations()
    assert len(violations) == 1
    assert violations[0].host == "api.segment.io"


def test_receipt_builder_verdicts():
    correlator = NetworkCorrelator()
    summary = ExecutionSummary(total_steps_executed=4, replans_triggered=1, duration_seconds=5.2)

    # Scenario A: Zero network requests -> OFFLINE_VERIFIED
    receipt_offline = ReceiptBuilder.build_receipt("LocalApp", "com.local.app", summary, correlator)
    assert receipt_offline.verdict == "OFFLINE_VERIFIED"
    assert receipt_offline.violation_count == 0

    # Scenario B: Auth only requests -> CONDITIONAL_AUTH_ONLY
    correlator.record_request("GET", "https://accounts.google.com/o/oauth2/token", payload_size=200)
    receipt_auth = ReceiptBuilder.build_receipt("LocalApp", "com.local.app", summary, correlator)
    assert receipt_auth.verdict == "CONDITIONAL_AUTH_ONLY"
    assert receipt_auth.violation_count == 0

    # Scenario C: Telemetry detected -> PRIVACY_VIOLATION
    correlator.record_request("POST", "https://telemetry.mixpanel.com/track", payload_size=300)
    receipt_violation = ReceiptBuilder.build_receipt("LocalApp", "com.local.app", summary, correlator)
    assert receipt_violation.verdict == "PRIVACY_VIOLATION"
    assert receipt_violation.violation_count == 1
    assert receipt_violation.target_app == "LocalApp"


def test_scrapers_mock_mode():
    ax_scraper = MacOSAccessibilityScraper()
    test_elems = [UIElement(id="1", role="AXButton", title="Save")]
    ax_scraper.set_mock_elements(test_elems)
    assert ax_scraper.get_ui_inventory() == test_elems
    assert ax_scraper.click_element("1") is True

    cdp_client = ElectronCDPClient()
    cdp_client.set_mock_elements(test_elems)
    assert cdp_client.get_ui_inventory() == test_elems
    assert cdp_client.click_element_by_id("1") is True


def test_dumb_monkey_mode_cycling():
    """Test that BatchPlanner systematically cycles through interactive controls in Dumb Monkey Mode."""
    elements = [
        UIElement(id="static_txt", role="AXStaticText", title="Welcome"),
        UIElement(id="btn_settings", role="AXButton", title="Settings"),
        UIElement(id="chk_offline", role="AXCheckBox", title="Offline Only"),
        UIElement(id="btn_icon_only", role="AXButton", title=""),
    ]

    planner = BatchPlanner(llm_fn=lambda prompt: "I cannot give JSON")

    # Step 1: Should pick first interactive button with title
    plan1 = planner.plan_next_batch(elements, goal="Explore")
    assert "Dumb Monkey Mode" in plan1.thought_process
    assert len(plan1.batch_plan) == 1
    assert plan1.batch_plan[0].target_id == "btn_settings"

    # Step 2: Should pick next unvisited control (the checkbox)
    plan2 = planner.plan_next_batch(elements, goal="Explore", step_history=["Step 1: click 'Settings'"])
    assert plan2.batch_plan[0].target_id == "chk_offline"

    # Step 3: Should pick button without title
    plan3 = planner.plan_next_batch(elements, goal="Explore", step_history=["Step 1: click 'Settings'", "Step 2: click 'Offline Only'"])
    assert plan3.batch_plan[0].target_id == "btn_icon_only"


def test_live_socket_auditor_records_flows():
    """Test that LiveSocketAuditor detects external sockets and feeds them into NetworkCorrelator."""
    from monitor.privacy_auditor.socket_monitor import LiveSocketAuditor
    correlator = NetworkCorrelator()
    correlator.set_active_action(step_id=1, description="CLICK 'Preferences'")

    auditor = LiveSocketAuditor(correlator=correlator, target_pid=1234)
    # Inject mock external socket connection
    auditor.set_mock_connections([
        {
            "local": "192.168.1.50.50000",
            "foreign": "142.250.190.46.443",
            "state": "ESTABLISHED",
            "rx": 500,
            "tx": 1200,
        },
        {
            "local": "127.0.0.1.8000",
            "foreign": "127.0.0.1.52000",
            "state": "ESTABLISHED",
            "rx": 100,
            "tx": 100,
        }
    ])

    new_events = auditor.audit_step()
    assert new_events == 1  # Localhost is filtered out, only 142.250.190.46 is recorded

    flows = correlator.get_all_flows()
    assert len(flows) == 1
    assert flows[0].associated_step_id == 1
    assert flows[0].payload_size == 1200
    assert ":443" in flows[0].url
    assert bool(flows[0].host) is True


def test_debug_response_peek():
    """Test that BatchPlanner persists and retrieves raw AI response for inspection."""
    from pathlib import Path
    planner = BatchPlanner()
    planner._save_debug_response(
        prompt="Test Prompt",
        raw_response="Random AI text",
        error=None,
    )
    debug_text = BatchPlanner.get_last_debug_response()
    assert debug_text is not None
    assert "Random AI text" in debug_text
    assert "Test Prompt" in debug_text


def test_receipt_builder_inconclusive_verdict():
    """Test that ReceiptBuilder yields INCONCLUSIVE if target was inaccessible or 0 steps ran."""
    correlator = NetworkCorrelator()
    summary = ExecutionSummary(total_steps_executed=0, stopped_reason="target_process_inaccessible")
    receipt = ReceiptBuilder.build_receipt(
        target_app="MissingApp",
        bundle_id=None,
        summary=summary,
        correlator=correlator,
        inconclusive_reason="Volume disconnected",
    )
    assert receipt.verdict == "INCONCLUSIVE"
    assert receipt.diagnostic_note == "Volume disconnected"
    assert receipt.steps_executed == 0


def test_ax_scraper_external_storage_detection(tmp_path):
    """Test that MacOSAccessibilityScraper detects real_app_path.txt pointing to missing volumes."""
    # Create mock AppPorts directory layout
    app_dir = tmp_path / "MockApp.app"
    res_dir = app_dir / "Contents" / "Resources"
    res_dir.mkdir(parents=True)
    real_path_file = res_dir / "real_app_path.txt"
    real_path_file.write_text("/Volumes/NonExistentDrive/AppPorts/MockApp.app", encoding="utf-8")

    scraper = MacOSAccessibilityScraper(target_bundle_id=str(app_dir))
    pid = scraper.find_target_pid()
    assert pid is None
    assert scraper.last_error is not None
    assert "external storage" in scraper.last_error
    assert "/Volumes/NonExistentDrive" in scraper.last_error

