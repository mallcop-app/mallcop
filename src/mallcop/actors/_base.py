"""ActorBase ABC — all actors must implement this interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from mallcop.schemas import Finding


class ActorBase(ABC):
    @abstractmethod
    def handle(self, findings: list[Finding]) -> list[Finding]:
        """Process findings. Returns updated findings (with annotations)."""
