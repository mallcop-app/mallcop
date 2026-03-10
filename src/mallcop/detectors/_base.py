"""DetectorBase ABC — all detectors must implement this interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from mallcop.schemas import Baseline, Event, Finding


class DetectorBase(ABC):
    @abstractmethod
    def detect(self, events: list[Event], baseline: Baseline) -> list[Finding]:
        """Analyze events against baseline, return findings."""

    @abstractmethod
    def relevant_sources(self) -> list[str] | None:
        """Which connectors' events this detector wants. None means all."""

    @abstractmethod
    def relevant_event_types(self) -> list[str] | None:
        """Which event types this detector analyzes. None means all."""
