"""ConnectorBase ABC — all connectors must implement this interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from mallcop.schemas import Checkpoint, DiscoveryResult, PollResult
from mallcop.secrets import SecretProvider


class ConnectorBase(ABC):
    @abstractmethod
    def discover(self) -> DiscoveryResult:
        """Probe the environment for available resources."""

    @abstractmethod
    def authenticate(self, secrets: SecretProvider) -> None:
        """Establish authentication using provided secret backend."""

    @abstractmethod
    def poll(self, checkpoint: Checkpoint | None) -> PollResult:
        """Fetch new events since last checkpoint."""

    @abstractmethod
    def event_types(self) -> list[str]:
        """Declare event types this connector emits."""

    def configure(self, config: dict) -> None:
        """Apply connector-specific configuration from mallcop.yaml.

        Override in subclasses that need config injection (e.g. subscription_id,
        resource_group, apps). Default is a no-op.
        """
