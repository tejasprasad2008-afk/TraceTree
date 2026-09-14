"""
Batch Action Planner for AI-driven autonomous UI exploration.
Formats state prompts and parses structured JSON action trajectories with preconditions.
"""
import os
import json
import re
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from monitor.privacy_auditor.schema import UIElement, BatchPlan, BatchStep, Precondition

logger = logging.getLogger("tracetree.batch_planner")

DEFAULT_PROMPT_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "prompts" / "ui_privacy_auditor.json"


def resolve_default_llm_fn() -> Optional[Callable[[str], str]]:
    """Automatically resolve an LLM completion function based on configured environment variables."""
    # 1. Load .env file from repo root if present
    repo_root = Path(__file__).resolve().parent.parent.parent
    env_file = repo_root / ".env"
    if env_file.exists():
        try:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        os.environ.setdefault(k.strip(), v.strip().strip("'\""))
        except Exception:
            pass

    # 2. Check OpenAI
    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key:
        import requests
        model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        def _call_openai(prompt: str) -> str:
            headers = {"Authorization": f"Bearer {openai_key}", "Content-Type": "application/json"}
            payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.2}
            r = requests.post(f"{base_url}/chat/completions", json=payload, headers=headers, timeout=45)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        return _call_openai

    # 3. Check Anthropic
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    if anthropic_key:
        import requests
        model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
        base_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")
        def _call_anthropic(prompt: str) -> str:
            headers = {"x-api-key": anthropic_key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
            payload = {"model": model, "max_tokens": 2048, "messages": [{"role": "user", "content": prompt}]}
            r = requests.post(f"{base_url}/v1/messages", json=payload, headers=headers, timeout=45)
            r.raise_for_status()
            return r.json()["content"][0]["text"]
        return _call_anthropic

    # 4. Check OpenRouter
    openrouter_key = os.getenv("OPENROUTER_API_KEY")
    if openrouter_key:
        import requests
        model = os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")
        base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/")
        def _call_openrouter(prompt: str) -> str:
            headers = {"Authorization": f"Bearer {openrouter_key}", "Content-Type": "application/json"}
            payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.2}
            r = requests.post(f"{base_url}/chat/completions", json=payload, headers=headers, timeout=45)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        return _call_openrouter

    # 5. Check local Ollama
    ollama_host = os.getenv("OLLAMA_HOST", os.getenv("OLLAMA_BASE_URL"))
    if ollama_host:
        import requests
        if not ollama_host.startswith("http"):
            ollama_host = f"http://{ollama_host}"
        model = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
        def _call_ollama(prompt: str) -> str:
            payload = {"model": model, "prompt": prompt, "stream": False, "format": "json"}
            r = requests.post(f"{ollama_host}/api/generate", json=payload, timeout=60)
            r.raise_for_status()
            return r.json().get("response", "")
        return _call_ollama

    return None


class BatchPlanner:
    """Manages prompt creation and validates speculative action batches from the AI."""

    def __init__(
        self,
        prompt_path: Optional[Path] = None,
        llm_fn: Optional[Callable[[str], str]] = None,
    ):
        self.prompt_path = prompt_path or DEFAULT_PROMPT_PATH
        self.llm_fn = llm_fn or resolve_default_llm_fn()
        self._system_prompt = self._load_system_prompt()
        self._fallback_notified = False
        self._in_monkey_mode = False
        self._visited_element_ids: set[str] = set()

    @classmethod
    def get_last_debug_response(cls) -> Optional[str]:
        """Read the raw AI debug log from .tracetree/last_llm_response.txt if present."""
        try:
            log_file = Path(".tracetree") / "last_llm_response.txt"
            if log_file.exists():
                return log_file.read_text(encoding="utf-8")
        except Exception:
            pass
        return None

    def _load_system_prompt(self) -> str:
        """Load the agreed-upon system prompt from disk."""
        if self.prompt_path.exists():
            try:
                with open(self.prompt_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("system_prompt", "")
            except Exception as e:
                logger.warning(f"Could not read prompt from {self.prompt_path}: {e}")
        return "You are the TraceTree Autonomous App Auditor. Respond with valid JSON."

    def build_user_prompt(
        self,
        elements: List[UIElement],
        goal: str,
        recent_feedback: Optional[str] = None,
        step_history: Optional[List[str]] = None,
    ) -> str:
        """Construct the dynamic context prompt representing the active UI state."""
        element_lines = []
        for el in elements:
            bounds_str = f"[{el.bounds[0]:.0f},{el.bounds[1]:.0f},{el.bounds[2]:.0f},{el.bounds[3]:.0f}]"
            title_str = f'"{el.title}"' if el.title else "None"
            element_lines.append(f"- ID: {el.id} | Role: {el.role} | Title: {title_str} | Bounds: {bounds_str}")

        inventory_text = "\n".join(element_lines) if element_lines else "No interactive elements detected."

        prompt = (
            f"### Current Exploration Goal:\n{goal}\n\n"
            f"### Active UI Element Inventory:\n{inventory_text}\n"
        )

        if step_history:
            history_text = "\n".join(f"- {h}" for h in step_history[-5:])
            prompt += f"\n### Recently Completed Actions:\n{history_text}\n"

        if recent_feedback:
            prompt += f"\n### Attention / Replanning Trigger:\n{recent_feedback}\n"

        prompt += "\nOutput your predicted batch of actions strictly in the specified JSON format."
        return prompt

    def plan_next_batch(
        self,
        elements: List[UIElement],
        goal: str,
        recent_feedback: Optional[str] = None,
        step_history: Optional[List[str]] = None,
    ) -> BatchPlan:
        """Prompt the AI and parse its structured action batch with automatic fallback."""
        user_prompt = self.build_user_prompt(elements, goal, recent_feedback, step_history)

        if not self.llm_fn or self._in_monkey_mode:
            if not self._in_monkey_mode and not self.llm_fn:
                self._notify_fallback("no_llm")
                self._in_monkey_mode = True
            return self._generate_fallback_plan(elements, step_history)

        full_prompt = f"{self._system_prompt}\n\n{user_prompt}"
        try:
            raw_response = self.llm_fn(full_prompt)
            self._save_debug_response(full_prompt, raw_response)
            plan = self.parse_json_response(raw_response)
            if plan.batch_plan:
                return plan
        except Exception as e:
            raw_response = f"Exception: {e}"
            self._save_debug_response(full_prompt, raw_response, error=str(e))
            logger.warning(f"LLM execution failed: {e}")

        # Gracefully switch to Dumb Monkey Mode for the remainder of this exploration
        self._in_monkey_mode = True
        self._notify_fallback("non_json")
        return self._generate_fallback_plan(elements, step_history)

    def _notify_fallback(self, reason: str = "non_json") -> None:
        """Inform the user that exploration is continuing in heuristic Dumb Monkey Mode."""
        if self._fallback_notified:
            return
        self._fallback_notified = True
        try:
            from rich.console import Console
            from rich.panel import Panel
            c = Console()
            if reason == "no_llm":
                c.print(Panel(
                    "[bold yellow]⚠️ No AI Model Configured — Switching to Dumb Monkey Mode[/]\n\n"
                    "Autonomous exploration will continue by systematically cycling through interactive UI controls\n"
                    "to ensure the live network and privacy audit still completes.\n\n"
                    "[bold cyan]For more accurate, goal-directed exploration, configure your LLM:[/]\n"
                    "  • Run [bold green]cascade-analyze setup[/] to launch the guided browser wizard\n"
                    "  • Or set [bold]OPENAI_API_KEY[/], [bold]ANTHROPIC_API_KEY[/], or [bold]OPENROUTER_API_KEY[/] in your [bold].env[/] file",
                    title="[bold yellow]TraceTree Explorer Mode[/]",
                    border_style="yellow",
                    expand=False,
                ))
            else:
                c.print(Panel(
                    "[bold yellow]⚠️ AI Planner Returned Invalid / Non-JSON — Switching to Dumb Monkey Mode[/]\n\n"
                    "The configured AI model did not output the required JSON action trajectory.\n"
                    "Automatically switching to [bold]Dumb Monkey Mode[/] so UI exploration continues and the network audit completes.\n\n"
                    "[bold cyan]Tips & Diagnostics:[/]\n"
                    "  • For more accurate results, configure a supported LLM via [bold green]cascade-analyze setup[/]\n"
                    "  • Or check your [bold].env[/] (OPENAI_API_KEY, ANTHROPIC_API_KEY, or OPENROUTER_API_KEY)\n"
                    "  • Peek at the raw AI response in: [bold].tracetree/last_llm_response.txt[/] (or run [bold]cascade-audit --peek[/])",
                    title="[bold yellow]TraceTree Fallback Mode[/]",
                    border_style="yellow",
                    expand=False,
                ))
        except Exception:
            pass

    def _save_debug_response(self, prompt: str, raw_response: str, error: Optional[str] = None) -> None:
        """Persist the prompt and raw LLM response to .tracetree for developer inspection."""
        import time
        try:
            log_dir = Path(".tracetree")
            log_dir.mkdir(parents=True, exist_ok=True)
            log_file = log_dir / "last_llm_response.txt"
            content = (
                f"--- TIMESTAMP ---\n{time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                f"--- ERROR ---\n{error or 'None'}\n\n"
                f"--- RAW LLM RESPONSE ---\n{raw_response}\n\n"
                f"--- PROMPT SENT ---\n{prompt}\n"
            )
            log_file.write_text(content, encoding="utf-8")
        except Exception:
            pass

    def parse_json_response(self, response_text: str) -> BatchPlan:
        """Extract and validate JSON from the raw LLM output string."""
        cleaned = self._extract_json_substring(response_text)
        try:
            data = json.loads(cleaned)
            if not isinstance(data, dict):
                raise ValueError("Parsed JSON root is not an object.")
            return BatchPlan.from_dict(data)
        except Exception as e:
            logger.error(f"Failed to parse LLM batch response: {e}\nRaw output:\n{response_text}")
            return BatchPlan(
                thought_process=f"Failed to parse AI response: {e}",
                batch_plan=[],
            )

    def _extract_json_substring(self, text: str) -> str:
        """Strip markdown fences (```json ... ```) and extract the raw JSON body."""
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
        if fence_match:
            return fence_match.group(1).strip()
        # Look for the outer-most curly braces
        first_brace = text.find("{")
        last_brace = text.rfind("}")
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            return text[first_brace : last_brace + 1].strip()
        return text.strip()

    def _generate_fallback_plan(
        self, elements: List[UIElement], step_history: Optional[List[str]] = None
    ) -> BatchPlan:
        """Generate a heuristic exploration step, cycling through unclicked interactive elements."""
        if not elements:
            return BatchPlan(thought_process="No elements visible to explore", batch_plan=[])

        # Interactive roles that can be clicked or toggled
        clickable_roles = {
            "axbutton", "axcheckbox", "axradiobutton", "axmenuitem",
            "axpopupbutton", "axmenubutton", "axtab", "axlink",
            "axdisclosuretriangle", "axsegmentedcontrol",
            "button", "link", "checkbox", "radio", "tab", "menuitem", "switch"
        }

        # Elements already clicked in this session or step_history
        clicked = set(self._visited_element_ids)
        if step_history:
            for h in step_history:
                clicked.add(h.lower())

        # Categorize available elements into prioritized pools
        tier1_controls_with_title = []
        tier2_controls_no_title = []
        tier3_other_with_title = []

        for el in elements:
            role_lower = el.role.lower()
            is_clickable = role_lower in clickable_roles
            has_title = bool(el.title and el.title.strip())

            if is_clickable and has_title:
                tier1_controls_with_title.append(el)
            elif is_clickable:
                tier2_controls_no_title.append(el)
            elif has_title:
                tier3_other_with_title.append(el)

        # Select target element prioritizing unvisited controls
        target_el = None
        for pool in (tier1_controls_with_title, tier2_controls_no_title, tier3_other_with_title, elements):
            for el in pool:
                label = (el.title or el.id).lower()
                el_id = el.id.lower()
                if el_id not in clicked and not any(label in h for h in clicked):
                    target_el = el
                    break
            if target_el:
                break

        # If all candidates have been clicked, cycle back to the first tier 1 control
        if not target_el:
            self._visited_element_ids.clear()
            target_el = (
                tier1_controls_with_title[0]
                if tier1_controls_with_title
                else (tier2_controls_no_title[0] if tier2_controls_no_title else elements[0])
            )

        self._visited_element_ids.add(target_el.id.lower())
        if target_el.title:
            self._visited_element_ids.add(target_el.title.lower())

        step = BatchStep(
            step=1,
            action="click",
            target_id=target_el.id,
            precondition=Precondition(expected_role=target_el.role, expected_title=target_el.title),
            expected_outcome=f"Dumb Monkey Mode click on '{target_el.title or target_el.role}'",
        )
        return BatchPlan(
            thought_process="Dumb Monkey Mode (cycling through interactive controls)",
            batch_plan=[step],
        )
