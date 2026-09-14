"""
Real-time Process Socket Auditor.
Samples active TCP/UDP connections for a target PID via netstat/system tools,
tracks byte transfers, and correlates outbound traffic with UI actions.
"""
import sys
import time
import socket
import logging
import subprocess
import re
from typing import List, Dict, Any, Optional, Set, Tuple
from monitor.privacy_auditor.network_correlator import NetworkCorrelator

logger = logging.getLogger("tracetree.socket_monitor")


class LiveSocketAuditor:
    """Monitors live network sockets for a target PID and pipes flows to NetworkCorrelator."""

    def __init__(self, correlator: NetworkCorrelator, target_pid: Optional[int] = None):
        self.correlator = correlator
        self.target_pid = target_pid
        self._previous_sockets: Dict[str, Dict[str, Any]] = {}
        self._host_cache: Dict[str, str] = {}
        self._mock_connections: Optional[List[Dict[str, Any]]] = None

    def set_mock_connections(self, conns: List[Dict[str, Any]]) -> None:
        """Inject mock connections for automated testing."""
        self._mock_connections = list(conns)

    def resolve_host(self, ip: str) -> str:
        """Resolve IP address to hostname with in-memory caching."""
        if ip in self._host_cache:
            return self._host_cache[ip]
        if ip.startswith("127.") or ip == "::1" or ip == "localhost":
            return "localhost"
        try:
            name = socket.gethostbyaddr(ip)[0]
            self._host_cache[ip] = name
            return name
        except Exception:
            self._host_cache[ip] = ip
            return ip

    def poll_connections(self) -> List[Dict[str, Any]]:
        """Query operating system for active network sockets belonging to target_pid."""
        if self._mock_connections is not None:
            return list(self._mock_connections)

        if not self.target_pid:
            return []

        if sys.platform == "darwin":
            return self._poll_darwin_netstat(self.target_pid)
        elif sys.platform.startswith("linux"):
            return self._poll_linux_netstat(self.target_pid)
        return []

    def _poll_darwin_netstat(self, pid: int) -> List[Dict[str, Any]]:
        """Parse macOS netstat -anv -p tcp output for connections associated with pid."""
        try:
            cmd = ["netstat", "-anv", "-p", "tcp"]
            out = subprocess.check_output(cmd, text=True, timeout=3, stderr=subprocess.DEVNULL)
            pattern = re.compile(
                r"^\S+\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+.*?:(\d+)\b"
            )
            conns = []
            for line in out.splitlines():
                m = pattern.match(line.strip())
                if m:
                    local_addr, foreign_addr, state, rxbytes, txbytes, line_pid = m.groups()
                    if int(line_pid) == pid:
                        conns.append({
                            "local": local_addr,
                            "foreign": foreign_addr,
                            "state": state,
                            "rx": int(rxbytes),
                            "tx": int(txbytes),
                        })
            return conns
        except Exception as e:
            logger.debug(f"Could not poll Darwin netstat: {e}")
            return []

    def _poll_linux_netstat(self, pid: int) -> List[Dict[str, Any]]:
        """Linux fallback: parse ss -ntp for pid."""
        try:
            cmd = ["ss", "-ntp"]
            out = subprocess.check_output(cmd, text=True, timeout=3, stderr=subprocess.DEVNULL)
            conns = []
            for line in out.splitlines():
                if f"pid={pid}," in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        conns.append({
                            "local": parts[3],
                            "foreign": parts[4],
                            "state": parts[0],
                            "rx": 0,
                            "tx": 0,
                        })
            return conns
        except Exception:
            return []

    def audit_step(self) -> int:
        """
        Sample active connections, detect new/active flows, and record in correlator.
        Returns number of new or updated flows detected.
        """
        connections = self.poll_connections()
        new_events = 0

        for conn in connections:
            foreign = conn["foreign"]
            # Ignore listening ports or wildcard destinations
            if foreign in ("*.*", "*:*", "0.0.0.0:*", "[::]:*"):
                continue

            # Parse IP and port
            # Darwin format: 149.154.166.110.443 or 2a00:... .443
            if "." in foreign:
                parts = foreign.rsplit(".", 1)
                foreign_ip, port = parts[0], parts[1]
            elif ":" in foreign:
                parts = foreign.rsplit(":", 1)
                foreign_ip, port = parts[0], parts[1]
            else:
                foreign_ip, port = foreign, "0"

            # Filter out localhost
            if foreign_ip.startswith("127.") or foreign_ip in ("::1", "0.0.0.0", "localhost"):
                continue

            conn_key = f"{foreign_ip}:{port}"
            tx = conn.get("tx", 0)
            rx = conn.get("rx", 0)
            state = conn.get("state", "ESTABLISHED")

            prev = self._previous_sockets.get(conn_key)
            is_new = prev is None
            tx_delta = tx - (prev["tx"] if prev else 0)

            if is_new or tx_delta > 0:
                resolved_host = self.resolve_host(foreign_ip)
                scheme = "https" if port == "443" else ("http" if port == "80" else "tcp")
                url = f"{scheme}://{resolved_host}:{port}/"

                self.correlator.record_request(
                    method=f"SOCKET_{state}",
                    url=url,
                    payload_size=tx_delta if not is_new else (tx or 100),
                )
                new_events += 1

            self._previous_sockets[conn_key] = {"tx": tx, "rx": rx, "state": state}

        return new_events
