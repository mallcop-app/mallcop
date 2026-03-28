"""Managed inference endpoint client."""

from __future__ import annotations

import logging
from typing import Any

import requests

from mallcop.llm_types import LLMAPIError, LLMClient, LLMResponse, ToolCall
from mallcop.llm.anthropic import _convert_messages, _convert_tools
from mallcop.llm.converters import _extract_resolution

_log = logging.getLogger(__name__)

from mallcop.llm.converters import DEFAULT_MAX_TOKENS as _MAX_TOKENS_DEFAULT

# Lane names recognised by mallcop-pro. When use_lanes=True the client sends
# these names as the model field instead of concrete model identifiers.
LANE_NAMES = frozenset({"patrol", "detective", "forensic"})

# Model alias → lane name mapping used when the caller passes a model alias
# (e.g. "haiku") to a lane-mode client. Maps inference-tier intent to lane:
#   haiku-class (fast/cheap)  → patrol  (high-volume triage)
#   sonnet-class (medium)     → detective (single-finding investigation)
#   opus-class (deep/slow)    → forensic  (deep investigation)
_ALIAS_TO_LANE: dict[str, str] = {
    "haiku": "patrol",
    "sonnet": "detective",
    "opus": "forensic",
    # Full model IDs: map by prefix so new versions auto-route correctly.
}

# Prefix-based fallback mapping for full model IDs (checked after exact alias).
_PREFIX_TO_LANE: list[tuple[str, str]] = [
    ("claude-haiku", "patrol"),
    ("claude-sonnet", "detective"),
    ("claude-opus", "forensic"),
    ("claude-3-haiku", "patrol"),
    ("claude-3-5-haiku", "patrol"),
    ("claude-3-sonnet", "detective"),
    ("claude-3-5-sonnet", "detective"),
    ("claude-3-opus", "forensic"),
]


def _resolve_lane(model: str) -> str:
    """Map a model name or alias to a lane name.

    Returns the model unchanged if it is already a lane name.
    Falls back to "patrol" for unrecognised models.
    """
    if model in LANE_NAMES:
        return model
    if model in _ALIAS_TO_LANE:
        return _ALIAS_TO_LANE[model]
    lower = model.lower()
    for prefix, lane in _PREFIX_TO_LANE:
        if lower.startswith(prefix):
            return lane
    _log.debug("ManagedClient: unrecognised model %r, defaulting to 'patrol' lane", model)
    return "patrol"


class ManagedClient(LLMClient):
    """LLM client that calls the mallcop managed inference endpoint.

    When ``use_lanes=True`` the client is in *lane mode*: it translates model
    names/aliases to lane names (patrol/detective/forensic) before sending
    requests.  mallcop-pro then picks the concrete model for that lane.  This
    is the correct mode when talking to mallcop.app as a backend.

    When ``use_lanes=False`` (default) the client resolves model aliases to
    full Anthropic model IDs, which is appropriate when talking to a raw Forge
    inference endpoint.
    """

    def __init__(
        self,
        endpoint: str,
        service_token: str,
        default_model: str = "claude-haiku-4-5-20251001",
        use_lanes: bool = False,
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._service_token = service_token
        self._default_model = default_model
        self._use_lanes = use_lanes

    def chat(
        self,
        model: str,
        system_prompt: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> LLMResponse:
        if self._use_lanes:
            resolved_model = _resolve_lane(model)
        else:
            from mallcop.llm import resolve_model_id
            resolved_model = resolve_model_id(model)
        anthropic_messages = _convert_messages(messages)
        anthropic_tools = _convert_tools(tools)

        body: dict[str, Any] = {
            "model": resolved_model,
            "max_tokens": _MAX_TOKENS_DEFAULT,
            "system": system_prompt,
            "messages": anthropic_messages,
        }
        if anthropic_tools:
            body["tools"] = anthropic_tools

        headers = {
            "Authorization": f"Bearer {self._service_token}",
            "content-type": "application/json",
        }

        resp = requests.post(
            f"{self._endpoint}/v1/messages", headers=headers, json=body, timeout=120
        )

        if resp.status_code != 200:
            _log.debug("Managed inference error %d: %s", resp.status_code, resp.text)
            raise LLMAPIError(
                f"Managed inference error {resp.status_code}"
            )

        data = resp.json()
        usage = data.get("usage", {})
        tokens_used = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)

        tool_calls: list[ToolCall] = []
        raw_resolution: dict[str, Any] | None = None
        text_content = ""

        for block in data.get("content", []):
            if block["type"] == "tool_use":
                tool_calls.append(
                    ToolCall(name=block["name"], arguments=block.get("input", {}))
                )
            elif block["type"] == "text":
                text_content += block.get("text", "")

        if not tool_calls and text_content:
            raw_resolution = _extract_resolution(text_content)

        return LLMResponse(
            tool_calls=tool_calls,
            resolution=None,
            tokens_used=tokens_used,
            raw_resolution=raw_resolution,
        )
