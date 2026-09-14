"""
macOS App Sandbox Entitlements Auditor.
Inspects codesign entitlements to detect if an application requests network permissions from macOS.
"""
import os
import plistlib
import subprocess
import logging
from typing import Dict, Any, List, Optional
from monitor.privacy_auditor.schema import NetworkFlow

logger = logging.getLogger("tracetree.entitlements")

NETWORK_ENTITLEMENT_FLAGS = [
    ("com.apple.security.network.client", "Outgoing Network Access (client socket)"),
    ("com.apple.security.network.server", "Incoming Network Access (server listener)"),
    ("com.apple.developer.icloud-services", "iCloud CloudDocuments Synchronization"),
    ("aps-environment", "Apple Push Notification Cloud Service (APNS)"),
]


class EntitlementsAuditor:
    """Audits macOS app codesign entitlements for network and cloud permissions."""

    @staticmethod
    def get_app_path(bundle_or_name: str) -> Optional[str]:
        """Find the filesystem path of the target .app bundle."""
        if bundle_or_name.endswith(".app") and os.path.exists(bundle_or_name):
            return bundle_or_name

        try:
            from AppKit import NSWorkspace
            ws = NSWorkspace.sharedWorkspace()
            path = ws.fullPathForApplication_(bundle_or_name)
            if path and os.path.exists(path):
                return path
            url = ws.URLForApplicationWithBundleIdentifier_(bundle_or_name)
            if url and url.path() and os.path.exists(url.path()):
                return url.path()
        except Exception:
            pass

        # Standard check in /Applications
        std_path = f"/Applications/{bundle_or_name}.app"
        if os.path.exists(std_path):
            return std_path

        return None

    @classmethod
    def audit_app_entitlements(cls, app_target: str) -> List[Dict[str, Any]]:
        """
        Inspect codesign entitlements and return any permissions that violate offline claims.
        """
        app_path = cls.get_app_path(app_target)
        if not app_path:
            return []

        try:
            cmd = ["codesign", "-d", "--entitlements", ":-", app_path]
            proc = subprocess.run(cmd, capture_output=True, timeout=3)
            if proc.returncode != 0 or not proc.stdout:
                return []

            entitlements = plistlib.loads(proc.stdout)
            violations = []

            for key, desc in NETWORK_ENTITLEMENT_FLAGS:
                val = entitlements.get(key)
                if val:
                    violations.append({
                        "entitlement": key,
                        "description": desc,
                        "value": val,
                        "detail": f"Offline claim refuted: App is granted '{key}' by macOS ({desc}).",
                    })

            return violations
        except Exception as e:
            logger.warning(f"Failed to inspect entitlements for {app_target}: {e}")
            return []
