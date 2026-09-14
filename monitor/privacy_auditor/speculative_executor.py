"""
Speculative Action Executor for macOS UI exploration.
Validates preconditions before each action, halts on UI drift, and triggers re-planning.
Continuously correlates outbound network sockets with active steps.
"""
import time
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Callable
from monitor.privacy_auditor.schema import UIElement, BatchPlan, BatchStep
from monitor.privacy_auditor.batch_planner import BatchPlanner
from monitor.privacy_auditor.network_correlator import NetworkCorrelator
from monitor.privacy_auditor.socket_monitor import LiveSocketAuditor

logger = logging.getLogger("tracetree.speculative_executor")


@dataclass
class ExecutionSummary:
    """Summary of the autonomous exploration session."""
    total_steps_executed: int = 0
    batches_attempted: int = 0
    replans_triggered: int = 0
    duration_seconds: float = 0.0
    action_log: List[str] = field(default_factory=list)
    stopped_reason: str = "completed"


class SpeculativeExecutor:
    """Executes batched UI actions with speculative verification and drift handling."""

    def __init__(
        self,
        ui_provider: Callable[[], List[UIElement]],
        action_dispatcher: Callable[[str, str, Optional[str]], bool],
        planner: BatchPlanner,
        network_correlator: NetworkCorrelator,
        debounce_seconds: float = 0.3,
        socket_auditor: Optional[LiveSocketAuditor] = None,
    ):
        self.ui_provider = ui_provider
        self.action_dispatcher = action_dispatcher
        self.planner = planner
        self.correlator = network_correlator
        self.debounce_seconds = debounce_seconds
        self.socket_auditor = socket_auditor

    def execute_batch(
        self,
        batch: BatchPlan,
        summary: ExecutionSummary,
        max_total_steps: int = 20,
    ) -> tuple[bool, Optional[str]]:
        """
        Execute actions in a batch sequentially.
        Returns (success: bool, failure_feedback: Optional[str]).
        """
        summary.batches_attempted += 1
        is_monkey = "monkey mode" in batch.thought_process.lower()

        for step in batch.batch_plan:
            if summary.total_steps_executed >= max_total_steps:
                return True, None

            # Sample network sockets before action
            if self.socket_auditor:
                self.socket_auditor.audit_step()

            current_elements = self.ui_provider()
            target = self._find_target_element(current_elements, step)

            if not target:
                if is_monkey:
                    # In Dumb Monkey Mode, do not abort; move directly to next candidate
                    logger.debug(f"[Monkey Mode] Target {step.target_id} not available, continuing.")
                    return True, None

                # Precondition violated or UI drifted! Halt immediately for AI replan
                feedback = (
                    f"Step {step.step} halted: Expected {step.precondition.expected_role} "
                    f"with title '{step.precondition.expected_title}' (target_id: {step.target_id}), "
                    f"but it was not present or enabled in the active window."
                )
                logger.warning(f"[Drift Detected] {feedback}")
                summary.replans_triggered += 1
                return False, feedback

            # Precondition passed: correlate network traffic with this step
            action_desc = f"{step.action.upper()} {target.title or target.role} -> {step.expected_outcome}"
            self.correlator.set_active_action(
                step_id=summary.total_steps_executed + 1,
                description=action_desc,
            )

            # Visual feedback on terminal
            try:
                from rich.console import Console
                badge = "🐒 [Monkey Mode]" if is_monkey else "🤖 [AI Plan]"
                display_name = target.title or target.id
                Console().print(
                    f"[dim]  {badge} Step {summary.total_steps_executed + 1}/{max_total_steps}: "
                    f"Clicked '{display_name}' ({target.role})[/dim]"
                )
            except Exception:
                pass

            # Dispatch action
            success = self.action_dispatcher(target.id, step.action, step.input_text)
            summary.total_steps_executed += 1
            summary.action_log.append(f"Step {summary.total_steps_executed}: {step.action} '{target.title or target.id}'")

            time.sleep(self.debounce_seconds)

            # Sample network sockets immediately after action
            if self.socket_auditor:
                self.socket_auditor.audit_step()

            if not success and not is_monkey:
                feedback = f"Step {step.step} execution failed during {step.action} on {target.id}."
                summary.replans_triggered += 1
                return False, feedback

        return True, None

    def _find_target_element(
        self, elements: List[UIElement], step: BatchStep
    ) -> Optional[UIElement]:
        """Locate element matching target_id and verifying precondition."""
        # 1. Direct ID match
        for el in elements:
            if el.id == step.target_id:
                if step.precondition.matches(el):
                    return el

        # 2. Fallback: match by precondition role and title
        for el in elements:
            if step.precondition.matches(el):
                return el

        return None

    def run_exploration(
        self,
        goal: str,
        max_total_steps: int = 20,
        max_rounds: int = 8,
    ) -> ExecutionSummary:
        """Run the continuous autonomous exploration and audit loop."""
        summary = ExecutionSummary()
        start_time = time.time()
        recent_feedback: Optional[str] = None

        # Allow sufficient rounds for single-step Dumb Monkey Mode exploration
        total_rounds_allowed = max(max_rounds, max_total_steps * 2)

        # Baseline network socket audit before any UI interaction
        if self.socket_auditor:
            self.socket_auditor.audit_step()

        for round_idx in range(total_rounds_allowed):
            if summary.total_steps_executed >= max_total_steps:
                summary.stopped_reason = "reached_max_steps"
                break

            current_elements = self.ui_provider()
            if not current_elements:
                summary.stopped_reason = "no_interactive_elements"
                break

            # Plan next speculative batch (or Dumb Monkey step)
            batch = self.planner.plan_next_batch(
                elements=current_elements,
                goal=goal,
                recent_feedback=recent_feedback,
                step_history=summary.action_log,
            )

            if not batch.batch_plan:
                summary.stopped_reason = "planner_finished"
                break

            # Execute batch
            success, failure_feedback = self.execute_batch(
                batch=batch,
                summary=summary,
                max_total_steps=max_total_steps,
            )
            if success:
                recent_feedback = None
            else:
                recent_feedback = failure_feedback

        # Final network socket audit after exploration finishes
        if self.socket_auditor:
            self.socket_auditor.audit_step()

        summary.duration_seconds = time.time() - start_time
        self.correlator.clear_active_action()
        return summary
