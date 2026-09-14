"""
Correlates active UI steps with outbound network traffic and classifies privacy violations.
"""
import time
import logging
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
from monitor.privacy_auditor.schema import NetworkFlow

logger = logging.getLogger("tracetree.network_correlator")

# Known telemetry and analytics domains
TELEMETRY_DOMAINS = {
    "segment.io",
    "mixpanel.com",
    "posthog.com",
    "datadoghq.com",
    "sentry.io",
    "amplitude.com",
    "telemetrydeck.com",
    "google-analytics.com",
    "analytics.google.com",
    "statsig.com",
    "launchdarkly.com",
    "split.io",
    "clarity.ms",
    "hotjar.com",
}

# Standard OAuth / authentication provider domains
OAUTH_AUTH_DOMAINS = {
    "accounts.google.com",
    "appleid.apple.com",
    "github.com",
    "auth0.com",
    "login.microsoftonline.com",
    "supabase.co",
    "firebaseapp.com",
}


class NetworkCorrelator:
    """Tracks active UI actions and tags outbound network requests with the responsible step."""

    def __init__(self):
        self._active_step_id: Optional[int] = None
        self._active_action_desc: Optional[str] = None
        self._flows: List[NetworkFlow] = []

    def set_active_action(self, step_id: Optional[int], description: Optional[str]) -> None:
        """Set the currently executing UI step to correlate subsequent network traffic."""
        self._active_step_id = step_id
        self._active_action_desc = description

    def clear_active_action(self) -> None:
        """Clear active step tagging."""
        self._active_step_id = None
        self._active_action_desc = None

    def record_request(
        self,
        method: str,
        url: str,
        payload_size: int = 0,
        payload_preview: Optional[str] = None,
        timestamp: Optional[float] = None,
    ) -> NetworkFlow:
        """Process and classify an outbound network request."""
        ts = timestamp or time.time()
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"

        category, is_violation, detail = self._classify_destination(host, path, payload_size, payload_preview)

        flow = NetworkFlow(
            timestamp=ts,
            method=method.upper(),
            url=url,
            host=host,
            path=path,
            payload_size=payload_size,
            associated_step_id=self._active_step_id,
            associated_action=self._active_action_desc,
            category=category,
            is_violation=is_violation,
            detail=detail,
        )

        self._flows.append(flow)
        return flow

    def _classify_destination(
        self, host: str, path: str, payload_size: int, payload_preview: Optional[str]
    ) -> tuple[str, bool, str]:
        """Classify network destination and assess privacy compliance."""
        # 1. Check if domain matches known telemetry services
        for t_domain in TELEMETRY_DOMAINS:
            if host == t_domain or host.endswith(f".{t_domain}"):
                return (
                    "telemetry",
                    True,
                    f"Outbound analytics beacon detected to {host} ({t_domain})",
                )

        # 2. Check if domain matches legitimate OAuth / SSO identity providers
        for auth_domain in OAUTH_AUTH_DOMAINS:
            if host == auth_domain or host.endswith(f".{auth_domain}"):
                return (
                    "whitelisted_auth",
                    False,
                    f"Authentication handshake to {host}",
                )

        # 3. Check for heavy data exfiltration (e.g. user prompts/files sent via POST)
        if payload_size > 5120:  # > 5 KB
            return (
                "data_exfiltration",
                True,
                f"High-volume payload ({payload_size} bytes) transmitted to unverified host {host}",
            )

        # 4. Fallback: unclassified external communication
        return (
            "unknown",
            True,
            f"External connection to unclassified endpoint: {host}",
        )

    def get_all_flows(self) -> List[NetworkFlow]:
        """Return all recorded network flows."""
        return list(self._flows)

    def get_violations(self) -> List[NetworkFlow]:
        """Return only flows that violate zero-telemetry / offline claims."""
        return [f for f in self._flows if f.is_violation]

    def reset(self) -> None:
        """Clear all recorded flows and active tags."""
        self._active_step_id = None
        self._active_action_desc = None
        self._flows.clear()
