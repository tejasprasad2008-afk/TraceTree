from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AnalysisFinding:
    analyzer_name: str
    sample_id: str
    verdict: str        # "MALICIOUS" | "BENIGN" | "UNCERTAIN"
    confidence: float   # 0.0–1.0
    evidence: list[str]
    model_version: str
    tags: list[str] = field(default_factory=list)
    raw_output: Any = None


class AnalyzerActions:
    """Side-channel for emitting findings without mutating analyzer state.

    Accepts bus=None so wrappers work before EventBus (Priority 2) ships.
    Once EventBus exists, pass it here and findings flow automatically.
    """

    def __init__(self, bus: Any = None) -> None:
        self._bus = bus
        self._findings: list[AnalysisFinding] = []

    def raise_finding(self, finding: AnalysisFinding) -> None:
        self._findings.append(finding)
        if self._bus is not None:
            self._bus.publish(finding)

    @property
    def findings(self) -> list[AnalysisFinding]:
        return list(self._findings)


class SampleAnalyzer(ABC):
    """Base interface for all per-stage analysis wrappers.

    Ordering contract for SampleAnalysisController (Priority 3):
        SyscallAnalyzer must run BEFORE RandomForestAnalyzer.
        SyscallAnalyzer.raw_output["sig_matches"] must be passed to
        build_cascade_graph(parsed_data, sig_matches) to produce graph_data.
        RandomForestAnalyzer then receives that graph_data via inputs["graph_data"].
        Violating this order gives detect_anomaly an incomplete graph and
        silently produces wrong verdicts.
    """

    enabled: bool = True

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def analyze(self, sample_id: str, inputs: dict, actions: AnalyzerActions) -> None:
        """Observe inputs and emit findings via actions. Never mutate inputs."""

    def applies_to(self, sample_type: str) -> bool:
        return True
