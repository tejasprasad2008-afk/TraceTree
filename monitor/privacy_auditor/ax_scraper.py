"""
macOS Accessibility API (AXUIElement) scraper and action dispatcher.
Extracts window hierarchy, roles, titles, and coordinates for UI inspection.
"""
import sys
import logging
from typing import List, Optional, Dict, Any, Tuple
from monitor.privacy_auditor.schema import UIElement

logger = logging.getLogger("tracetree.ax_scraper")

# Attempt dynamic PyObjC import for macOS runtime
_HAS_PYOBJC = False
if sys.platform == "darwin":
    try:
        from AppKit import NSWorkspace, NSRunningApplication
        from ApplicationServices import (
            AXUIElementCreateApplication,
            AXUIElementCopyAttributeValue,
            AXUIElementCopyAttributeNames,
            AXUIElementPerformAction,
            kAXWindowsAttribute,
            kAXChildrenAttribute,
            kAXRoleAttribute,
            kAXTitleAttribute,
            kAXDescriptionAttribute,
            kAXValueAttribute,
            kAXPositionAttribute,
            kAXSizeAttribute,
            kAXPressAction,
        )
        _HAS_PYOBJC = True
    except ImportError:
        logger.warning("pyobjc-framework-ApplicationServices not found. Running in mock/compatibility mode.")


class MacOSAccessibilityScraper:
    """Scrapes the macOS accessibility tree and executes OS-level UI actions."""

    def __init__(self, target_pid: Optional[int] = None, target_bundle_id: Optional[str] = None):
        self.target_pid = target_pid
        self.target_bundle_id = target_bundle_id
        self._mock_elements: Optional[List[UIElement]] = None
        self._element_ref_cache: Dict[str, Any] = {}
        self.last_error: Optional[str] = None
        self.external_storage_path: Optional[str] = None

    @classmethod
    def is_native_supported(cls) -> bool:
        """Check if native macOS AX APIs are available in the current environment."""
        return _HAS_PYOBJC and sys.platform == "darwin"

    def set_mock_elements(self, elements: List[UIElement]) -> None:
        """Set mock elements for automated testing or headless environments."""
        self._mock_elements = list(elements)

    def find_target_pid(self) -> Optional[int]:
        """Find the PID of the target application by app name, bundle ID, or path."""
        if self.target_pid:
            return self.target_pid
        if not self.is_native_supported() or not self.target_bundle_id:
            return None

        import os, re, subprocess, time

        workspace = NSWorkspace.sharedWorkspace()
        query = self.target_bundle_id.lower().removesuffix(".app")
        # Extract basename if path was provided
        if "/" in query:
            query = query.split("/")[-1].removesuffix(".app")

        # 1. Exact bundle identifier or localized app name match
        for app in workspace.runningApplications():
            bid = (app.bundleIdentifier() or "").lower()
            name = (app.localizedName() or "").lower()
            if query in (bid, name, name.replace(" ", "")):
                self.target_pid = app.processIdentifier()
                self.target_bundle_id = app.bundleIdentifier() or self.target_bundle_id
                return self.target_pid

        # 2. Substring match across running apps
        for app in workspace.runningApplications():
            bid = (app.bundleIdentifier() or "").lower()
            name = (app.localizedName() or "").lower()
            if query in bid or query in name:
                self.target_pid = app.processIdentifier()
                self.target_bundle_id = app.bundleIdentifier() or self.target_bundle_id
                return self.target_pid

        # 3. App is not currently running. Check if it lives on external storage (AppPorts / symlinks)
        app_path = None
        try:
            app_path = workspace.fullPathForApplication_(self.target_bundle_id)
        except Exception:
            pass

        if not app_path:
            # Check standard macOS Application folders
            for search_dir in ["/Applications", os.path.expanduser("~/Applications")]:
                for candidate_name in [f"{self.target_bundle_id}.app", f"{query.capitalize()}.app", f"{query}.app"]:
                    cand_path = os.path.join(search_dir, candidate_name)
                    if os.path.exists(cand_path):
                        app_path = cand_path
                        break
                if app_path:
                    break

        if app_path:
            # Check for AppPorts external relocation (real_app_path.txt)
            real_path_file = os.path.join(app_path, "Contents", "Resources", "real_app_path.txt")
            if os.path.isfile(real_path_file):
                try:
                    with open(real_path_file, "r", encoding="utf-8") as f:
                        real_target = f.read().strip()
                    if real_target and not os.path.exists(real_target):
                        vol_match = re.match(r"^(/Volumes/[^/]+)", real_target)
                        vol_name = vol_match.group(1) if vol_match else "external storage"
                        self.last_error = (
                            f"Application '{self.target_bundle_id}' is located on external storage ('{real_target}'), "
                            f"but volume '{vol_name}' is currently disconnected or unmounted."
                        )
                        self.external_storage_path = real_target
                        logger.debug(self.last_error)
                        return None
                except Exception as e:
                    logger.debug(f"Error checking real_app_path.txt: {e}")

            # Check if app_path is a broken symlink
            if os.path.islink(app_path) and not os.path.exists(app_path):
                link_dest = os.readlink(app_path)
                self.last_error = (
                    f"Application '{self.target_bundle_id}' is a symlink to '{link_dest}', "
                    f"which is missing or on a disconnected drive."
                )
                logger.debug(self.last_error)
                return None

        # 4. Attempt to launch the application
        try:
            launch_arg = app_path or self.target_bundle_id
            launch_proc = subprocess.run(
                ["open", "-a", launch_arg],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if launch_proc.returncode != 0:
                err_text = (launch_proc.stderr or launch_proc.stdout or "").strip()
                self.last_error = f"Failed to launch '{self.target_bundle_id}': {err_text or 'Command open -a returned non-zero'}"
                logger.debug(self.last_error)
                return None
        except Exception as e:
            self.last_error = f"Error launching application '{self.target_bundle_id}': {e}"
            logger.debug(self.last_error)
            return None

        # Give application time to launch and register in NSWorkspace
        time.sleep(1.5)
        for app in workspace.runningApplications():
            bid = (app.bundleIdentifier() or "").lower()
            name = (app.localizedName() or "").lower()
            if query in (bid, name) or query in bid or query in name:
                self.target_pid = app.processIdentifier()
                self.target_bundle_id = app.bundleIdentifier() or self.target_bundle_id
                return self.target_pid

        if not self.last_error:
            self.last_error = (
                f"Target application '{self.target_bundle_id}' was launched, but its process did not start "
                f"or closed immediately. If this application is on external storage, ensure the drive is connected."
            )
        return None

    def get_ui_inventory(self) -> List[UIElement]:
        """Returns a flat list of interactive elements in the target app window."""
        if self._mock_elements is not None:
            return list(self._mock_elements)

        if not self.is_native_supported():
            logger.warning("pyobjc-framework-ApplicationServices not installed. Cannot scrape macOS UI.")
            return []

        # Check if macOS Accessibility permissions are granted
        try:
            from ApplicationServices import AXIsProcessTrustedWithOptions, kAXTrustedCheckOptionPrompt
            if not AXIsProcessTrustedWithOptions({kAXTrustedCheckOptionPrompt: True}):
                print("\n[!] macOS Accessibility permission required.")
                print("    Please enable Terminal / Python in System Settings -> Privacy & Security -> Accessibility.\n")
                return []
        except Exception:
            pass

        pid = self.find_target_pid()
        if not pid:
            logger.error(f"Cannot scrape AX tree: target process not found (bundle: {self.target_bundle_id})")
            return []

        self._element_ref_cache.clear()
        app_ref = AXUIElementCreateApplication(pid)
        return self._scrape_app(app_ref)

    def _scrape_app(self, app_ref: Any) -> List[UIElement]:
        """Extract all windows, status items, and menu bars from the app reference."""
        elements: List[UIElement] = []

        # 1. Standard on-screen windows
        err, windows = AXUIElementCopyAttributeValue(app_ref, kAXWindowsAttribute, None)
        if err == -25211:
            print("\n[!] Accessibility error (-25211): Process not trusted by macOS.")
            print("    Enable Accessibility in System Settings -> Privacy & Security -> Accessibility.\n")
            return []

        if windows:
            for idx, win in enumerate(windows):
                elements.extend(self._crawl_element(win, prefix=f"win_{idx}"))

        # 2. Support Menu Bar / Status Bar apps (e.g. MacFace, Stats, utilities)
        if not elements:
            # Check AXExtrasMenuBar (top right menu bar icons)
            err_ex, extras = AXUIElementCopyAttributeValue(app_ref, "AXExtrasMenuBar", None)
            if err_ex == 0 and extras:
                err_ch, ex_children = AXUIElementCopyAttributeValue(extras, kAXChildrenAttribute, None)
                if err_ch == 0 and ex_children:
                    for ex_idx, item in enumerate(ex_children):
                        # Trigger item to expand menu
                        AXUIElementPerformAction(item, kAXPressAction)
                        import time
                        time.sleep(0.2)
                        elements.extend(self._crawl_element(item, prefix=f"menubar_extra_{ex_idx}"))

            # Check Application Menu Bar (File, Edit, Preferences, Settings)
            err_mb, menubar = AXUIElementCopyAttributeValue(app_ref, "AXMenuBar", None)
            if err_mb == 0 and menubar:
                err_mch, mb_children = AXUIElementCopyAttributeValue(menubar, kAXChildrenAttribute, None)
                if err_mch == 0 and mb_children:
                    for m_idx, m_item in enumerate(mb_children):
                        elements.extend(self._crawl_element(m_item, prefix=f"menu_{m_idx}"))

        return elements

    def _crawl_element(self, ax_elem: Any, prefix: str, depth: int = 0) -> List[UIElement]:
        """Recursively crawl AX elements up to depth 8 to prevent infinite loops."""
        if depth > 8:
            return []

        elements: List[UIElement] = []
        role = self._get_attribute_str(ax_elem, kAXRoleAttribute) or "AXUnknown"
        title = (
            self._get_attribute_str(ax_elem, kAXTitleAttribute)
            or self._get_attribute_str(ax_elem, kAXDescriptionAttribute)
            or self._get_attribute_str(ax_elem, kAXValueAttribute)
            or ""
        )

        elem_id = f"{prefix}_{role}_{len(elements)}"
        self._element_ref_cache[elem_id] = ax_elem

        # Only register elements that have a title or are actionable controls
        if title or role in ("AXButton", "AXCheckBox", "AXRadioButton", "AXMenuItem", "AXTextField"):
            elements.append(
                UIElement(
                    id=elem_id,
                    role=role,
                    title=title.strip(),
                    bounds=(0.0, 0.0, 0.0, 0.0),
                    enabled=True,
                )
            )

        # Traverse children
        err, children = AXUIElementCopyAttributeValue(ax_elem, kAXChildrenAttribute, None)
        if err == 0 and children:
            for c_idx, child in enumerate(children):
                elements.extend(self._crawl_element(child, prefix=f"{elem_id}_c{c_idx}", depth=depth + 1))

        return elements

    def _get_attribute_str(self, ax_elem: Any, attribute: str) -> Optional[str]:
        """Safely extract string attribute from an AXUIElement."""
        try:
            err, val = AXUIElementCopyAttributeValue(ax_elem, attribute, None)
            if err == 0 and val:
                return str(val)
        except Exception:
            pass
        return None

    def click_element(self, element_id: str) -> bool:
        """Trigger native AXPressAction on the cached element reference."""
        if self._mock_elements is not None:
            logger.info(f"[Mock] Clicked element {element_id}")
            return True

        if not self.is_native_supported():
            return False

        ax_ref = self._element_ref_cache.get(element_id)
        if not ax_ref:
            logger.error(f"Element ID {element_id} not found in AX cache")
            return False

        err = AXUIElementPerformAction(ax_ref, kAXPressAction)
        return err == 0
