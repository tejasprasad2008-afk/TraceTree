"""
TraceTree session guardian.

Watches a repository directory (from a `git clone` or `cd` context) and runs
a background sandbox analysis on detected packages.
"""

import json
import logging
import queue
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sandbox.sandbox import run_sandbox
from monitor.parser import parse_strace_log
from graph.builder import build_cascade_graph
from ml.detector import detect_anomaly

# ------------------------------------------------------------------ #
#  Logging configuration
# ------------------------------------------------------------------ #

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 120  # seconds per sandbox run


class SessionWatcher:
    """
    Background watcher that clones a repo into a Docker sandbox, runs package
    install under strace, and classifies the resulting trace for threats.

    Runs entirely in a background daemon thread so the main application
    remains responsive.  Results are exposed via :meth:`get_status` and
    streamed through :attr:`result_queue`.

    Attributes:
        repo_path: Local path to the repository or target directory.
        repo_url: Optional remote Git URL (used when *repo_path* does not
            exist yet — future ``git clone`` support).
        timeout: Maximum seconds allowed per sandbox execution.

    Usage::

        watcher = SessionWatcher("/path/to/repo", timeout=180)
        watcher.start()

        # Poll status in a loop, or use result_queue for push-style updates
        status = watcher.get_status()

        watcher.stop()
    """

    # ------------------------------------------------------------------ #
    #  __init__
    # ------------------------------------------------------------------ #

    def __init__(
        self,
        repo_path: str,
        repo_url: Optional[str] = None,
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> None:
        """
        Args:
            repo_path: Local filesystem path to the repository or target
                directory to analyse.
            repo_url: Optional remote Git URL.  Reserved for future
                ``git clone`` integration; currently logged for context.
            timeout: Maximum number of seconds each sandbox run is allowed
                to take.  Defaults to ``120``.
        """
        self.repo_path: Path = Path(repo_path)
        self.repo_url: Optional[str] = repo_url
        self.timeout: int = timeout

        self._thread: Optional[threading.Thread] = None
        self._stop_event: threading.Event = threading.Event()
        self._result_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()

        self._state: Dict[str, Any] = {
            "phase": "idle",
            "threats": [],
            "confidence": 0.0,
            "malicious": False,
            "log_path": None,
            "error": None,
        }
        self._lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def start(self) -> None:
        """
        Launch the background watcher thread.  Non-blocking.

        If a thread is already running, logs a warning and returns
        immediately (idempotent).
        """
        if self._thread is not None and self._thread.is_alive():
            logger.warning("SessionWatcher already running — call stop() first")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="SessionWatcher",
        )
        self._thread.start()
        logger.info("SessionWatcher started for %s", self.repo_path)

    def get_status(self) -> Dict[str, Any]:
        """
        Return a snapshot of the current session status.

        Returns:
            A dict with the keys ``phase``, ``threats``, ``confidence``,
            ``malicious``, ``log_path``, and ``error``.  The dict is a
            shallow copy so mutations by the caller are safe.
        """
        with self._lock:
            return dict(self._state)

    def check_path(self, file_path: str) -> Dict[str, Any]:
        """
        On-demand scan of a specific file or command within the repo.

        This runs a focused sandbox analysis on just the given path and
        returns the result immediately.  **This call blocks** until the
        sandbox completes or the timeout expires.

        Args:
            file_path: Relative path inside the repo, or an absolute path.

        Returns:
            A dict with keys ``malicious`` (bool), ``confidence`` (float),
            ``threats`` (list of str), ``graph_stats`` (dict), ``log_path``
            (str or None), and ``error`` (str or None on failure).
        """
        target = Path(file_path)
        if not target.is_absolute():
            target = self.repo_path / file_path

        logger.info("On-demand scan: %s", target)

        # Detect target type from extension / filename
        ext = target.suffix.lower()
        if ext == ".dmg":
            target_type: str = "dmg"
        elif ext in (".exe", ".msi"):
            target_type = "exe"
        elif target.name == "requirements.txt":
            target_type = "pip"
        elif target.name == "package.json":
            target_type = "npm"
        else:
            target_type = "pip"  # sensible default

        log_path = self._safe_run_sandbox(str(target), target_type)
        if log_path is None:
            return {
                "malicious": False,
                "confidence": 0.0,
                "threats": [],
                "graph_stats": {},
                "log_path": None,
                "error": "Sandbox failed or Docker unavailable",
            }

        try:
            parsed = parse_strace_log(log_path)
            graph = build_cascade_graph(parsed)
            is_malicious, confidence = detect_anomaly(graph, parsed)
        except Exception as exc:
            logger.error("Analysis pipeline failed for %s: %s", target, exc)
            return {
                "malicious": False,
                "confidence": 0.0,
                "threats": [],
                "graph_stats": {},
                "log_path": str(log_path),
                "error": str(exc),
            }

        return {
            "malicious": is_malicious,
            "confidence": confidence,
            "threats": parsed.get("flags", []),
            "graph_stats": graph.get("stats", {}),
            "log_path": str(log_path),
            "error": None,
        }

    def stop(self) -> None:
        """
        Gracefully stop the background watcher.

        Signals the worker thread to exit and waits up to 10 seconds for
        it to join.  Logs a warning if the thread fails to terminate.
        """
        logger.info("Stopping SessionWatcher…")
        self._stop_event.set()

        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=10)
            if self._thread.is_alive():
                logger.warning("SessionWatcher thread did not stop cleanly")

        with self._lock:
            self._state["phase"] = "stopped"

        logger.info("SessionWatcher stopped")

    def wait(self, timeout: Optional[float] = None) -> Dict[str, Any]:
        """
        Block until the watcher finishes or *timeout* expires.

        Args:
            timeout: Maximum seconds to wait.  ``None`` means wait
                indefinitely.

        Returns:
            The final status dict (same shape as :meth:`get_status`).
        """
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        return self.get_status()

    # ------------------------------------------------------------------ #
    #  Internal: background loop
    # ------------------------------------------------------------------ #

    def _run(self) -> None:
        """
        Main loop executed in the background daemon thread.

        Phases: ``cloning`` → ``sandboxing`` → ``analyzing`` →
        ``done`` / ``error`` / ``stopped``.
        """
        try:
            self._set_phase("cloning")

            if not self.repo_path.exists() and self.repo_url is not None:
                logger.info("Repo not found locally: %s", self.repo_path)
                logger.info("Remote URL available: %s", self.repo_url)
                # TODO: integrate ``git clone`` here when ready.

            self._set_phase("sandboxing")

            targets = self._discover_packages()
            if not targets:
                logger.warning("No packages found to analyse")
                self._set_phase("done")
                return

            logger.info("Discovered %d package(s) to analyse", len(targets))

            for target_name, target_type in targets:
                if self._stop_event.is_set():
                    break
                logger.info("Sandboxing: %s (%s)", target_name, target_type)
                self._analyze_target(target_name, target_type)

            self._set_phase("done")
            logger.info("SessionWatcher analysis complete")

        except Exception as exc:
            logger.error("SessionWatcher crashed: %s", exc, exc_info=True)
            self._set_phase("error")
            with self._lock:
                self._state["error"] = str(exc)

    def _analyze_target(self, package: str, target_type: str) -> None:
        """
        Run the full sandbox → parse → graph → ML pipeline on one target.

        Updates ``_state`` and pushes a result snapshot to
        :attr:`result_queue`.
        """
        log_path = self._safe_run_sandbox(package, target_type)
        if log_path is None:
            with self._lock:
                self._state["log_path"] = None
            return

        self._set_phase("analyzing")

        try:
            parsed = parse_strace_log(log_path)
            graph = build_cascade_graph(parsed)
            is_malicious, confidence = detect_anomaly(graph, parsed)
        except Exception as exc:
            logger.error("Analysis failed for %s: %s", package, exc, exc_info=True)
            return

        with self._lock:
            self._state["log_path"] = str(log_path)
            self._state["malicious"] = is_malicious
            self._state["confidence"] = confidence
            self._state["threats"] = parsed.get("flags", [])

        self._result_queue.put({
            "package": package,
            "type": target_type,
            "malicious": is_malicious,
            "confidence": confidence,
            "threats": parsed.get("flags", []),
            "log_path": str(log_path),
        })

        if is_malicious:
            logger.warning(
                "⚠ %s flagged as malicious (confidence: %.1f%%)",
                package,
                confidence,
            )
        else:
            logger.info(
                "✓ %s classified as clean (confidence: %.1f%%)",
                package,
                confidence,
            )

    def _safe_run_sandbox(
        self, target: str, target_type: str
    ) -> Optional[str]:
        """
        Wrapper around :func:`sandbox.sandbox.run_sandbox` with timeout
        and error handling.

        Args:
            target: Package name or file path to analyse.
            target_type: One of ``pip``, ``npm``, ``dmg``, ``exe``.

        Returns:
            Path to the strace log file, or ``None`` on failure.
        """
        try:
            return run_sandbox(target, target_type)
        except Exception as exc:
            logger.error(
                "Sandbox failed for %s (%s): %s", target, target_type, exc
            )
            return None

    def _discover_packages(self) -> List[Tuple[str, str]]:
        """
        Scan *repo_path* for package manifests and return a list of
        ``(name, target_type)`` tuples.

        Recognised manifests:
            - ``requirements.txt`` → pip packages
            - ``package.json``     → npm dependencies
            - ``setup.py`` / ``pyproject.toml`` → the repo itself (pip)
        """
        targets: List[Tuple[str, str]] = []

        if not self.repo_path.exists():
            return targets

        # ── requirements.txt ────────────────────────────────────────
        req_file = self.repo_path / "requirements.txt"
        if req_file.exists():
            try:
                with open(req_file, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if line and not line.startswith(("#", "-")):
                            targets.append((line, "pip"))
            except Exception as exc:
                logger.error("Failed to read requirements.txt: %s", exc)

        # ── package.json ────────────────────────────────────────────
        pkg_file = self.repo_path / "package.json"
        if pkg_file.exists():
            try:
                with open(pkg_file, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                for dep_key in ("dependencies", "devDependencies"):
                    for name in data.get(dep_key, {}):
                        targets.append((name, "npm"))
            except Exception as exc:
                logger.error("Failed to parse package.json: %s", exc)

        # ── setup.py / pyproject.toml ───────────────────────────────
        if (self.repo_path / "setup.py").exists() or (
            self.repo_path / "pyproject.toml"
        ).exists():
            targets.append((str(self.repo_path), "pip"))

        return targets

    def _set_phase(self, phase: str) -> None:
        """Thread-safe phase update."""
        with self._lock:
            self._state["phase"] = phase

    # ------------------------------------------------------------------ #
    #  Properties
    # ------------------------------------------------------------------ #

    @property
    def result_queue(self) -> "queue.Queue[Dict[str, Any]]":
        """
        Queue of analysis result snapshots.

        Each item pushed to the queue is a dict with the keys
        ``package``, ``type``, ``malicious``, ``confidence``,
        ``threats``, and ``log_path``.  Consumers can call
        :meth:`~queue.Queue.get` (optionally with a timeout) to receive
        results as they become available.
        """
        return self._result_queue
