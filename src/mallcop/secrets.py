"""Secret resolution: ABC and environment-based provider."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod


class ConfigError(Exception):
    """Raised for configuration errors including missing secrets."""


class SecretProvider(ABC):
    @abstractmethod
    def resolve(self, name: str) -> str:
        """Resolve a secret by name. Raises ConfigError if not found."""


class EnvSecretProvider(SecretProvider):
    def resolve(self, name: str) -> str:
        value = os.environ.get(name)
        if value is None:
            raise ConfigError(
                f"Secret '{name}' not found in environment variables. "
                f"Set the {name} environment variable or use a .env file."
            )
        return value
