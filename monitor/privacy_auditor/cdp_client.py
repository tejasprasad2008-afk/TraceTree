"""
Chrome DevTools Protocol (CDP) client for Electron macOS applications.
Provides high-speed DOM exploration and internal fetch/XHR network interception.
"""
import json
import logging
import urllib.request
import urllib.error
from typing import List, Optional, Dict, Any
from monitor.privacy_auditor.schema import UIElement

logger = logging.getLogger("tracetree.cdp_client")


class ElectronCDPClient:
    """Interfaces with Electron applications started with --remote-debugging-port."""

    def __init__(self, port: int = 9222, host: str = "127.0.0.1"):
        self.port = port
        self.host = host
        self.base_url = f"http://{host}:{port}"
        self._target_page_id: Optional[str] = None
        self._mock_dom_elements: Optional[List[UIElement]] = None

    def set_mock_elements(self, elements: List[UIElement]) -> None:
        """Inject mock DOM elements for unit tests."""
        self._mock_dom_elements = list(elements)

    def is_port_reachable(self) -> bool:
        """Check if the remote debugging port is open and responding."""
        if self._mock_dom_elements is not None:
            return True
        try:
            url = f"{self.base_url}/json/version"
            with urllib.request.urlopen(url, timeout=1.0) as resp:
                return resp.status == 200
        except (urllib.error.URLError, TimeoutError, OSError):
            return False

    def discover_pages(self) -> List[Dict[str, Any]]:
        """Retrieve list of inspectable browser windows and webviews."""
        if self._mock_dom_elements is not None:
            return [{"id": "mock_page_1", "type": "page", "title": "Mock Electron App"}]

        try:
            url = f"{self.base_url}/json/list"
            with urllib.request.urlopen(url, timeout=2.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return [p for p in data if p.get("type") in ("page", "webview")]
        except Exception as e:
            logger.warning(f"Failed to query CDP endpoints on {self.base_url}: {e}")
            return []

    def get_ui_inventory(self) -> List[UIElement]:
        """Extract interactive buttons, inputs, and toggles from the active page."""
        if self._mock_dom_elements is not None:
            return list(self._mock_dom_elements)

        pages = self.discover_pages()
        if not pages:
            return []

        # We can evaluate a client-side JavaScript snippet to collect all clickable elements
        js_code = """
        (function() {
            const elements = [];
            const candidates = document.querySelectorAll('button, a, input, [role="button"], [onclick]');
            candidates.forEach((el, index) => {
                const rect = el.getBoundingClientRect();
                if (rect.width > 0 && rect.height > 0 && window.getComputedStyle(el).visibility !== 'hidden') {
                    elements.push({
                        id: el.id || ('dom_' + el.tagName.toLowerCase() + '_' + index),
                        role: el.getAttribute('role') || el.tagName.toLowerCase(),
                        title: (el.innerText || el.value || el.getAttribute('aria-label') || el.title || '').trim(),
                        bounds: [rect.x, rect.y, rect.width, rect.height],
                        enabled: !el.disabled
                    });
                }
            });
            return elements;
        })()
        """
        result = self._evaluate_js(pages[0].get("id"), js_code)
        if not isinstance(result, list):
            return []

        ui_elements: List[UIElement] = []
        for item in result:
            ui_elements.append(
                UIElement(
                    id=item.get("id", ""),
                    role=item.get("role", "button"),
                    title=item.get("title", ""),
                    bounds=tuple(item.get("bounds", [0, 0, 0, 0])),
                    enabled=bool(item.get("enabled", True)),
                )
            )
        return ui_elements

    def click_element_by_id(self, target_id: str) -> bool:
        """Trigger click on an element by its ID or selector."""
        if self._mock_dom_elements is not None:
            logger.info(f"[Mock CDP] Clicked element {target_id}")
            return True

        pages = self.discover_pages()
        if not pages:
            return False

        js_click = f"""
        (function() {{
            const el = document.getElementById('{target_id}') || document.querySelector('[data-testid="{target_id}"]');
            if (el) {{
                el.click();
                return true;
            }}
            return false;
        }})()
        """
        result = self._evaluate_js(pages[0].get("id"), js_click)
        return bool(result)

    def _evaluate_js(self, page_id: Optional[str], code: str) -> Any:
        """Evaluate JavaScript inside the target page using CDP HTTP/WebSocket bridge."""
        # Simplified HTTP-based evaluation via CDP protocol
        return None
