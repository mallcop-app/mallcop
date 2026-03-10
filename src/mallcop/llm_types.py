"""LLM type definitions: ABC, response types, and exceptions.

This module breaks the circular import risk between llm.py and actors/runtime.py
by providing shared types that both modules can import without depending on each other.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    tool_calls: list[ToolCall]
    resolution: Any  # ActorResolution | None — uses Any to avoid circular import
    tokens_used: int
    raw_resolution: Any = None  # Raw dict from LLM before validation


class LLMClient(ABC):
    @abstractmethod
    def chat(
        self,
        model: str,
        system_prompt: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> LLMResponse:
        ...


class LLMAPIError(Exception):
    """Raised when an LLM API returns an error."""
