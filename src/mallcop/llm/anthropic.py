"""Anthropic Messages API client."""

from __future__ import annotations

import logging
from typing import Any

import requests

from mallcop.llm_types import LLMAPIError, LLMClient, LLMResponse, ToolCall
from mallcop.llm.converters import _normalize_tool_schema, _extract_resolution

_log = logging.getLogger(__name__)

_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"
from mallcop.llm.converters import DEFAULT_MAX_TOKENS as _MAX_TOKENS_DEFAULT


def _convert_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert internal message format to Anthropic API format."""
    converted: list[dict[str, Any]] = []
    tool_use_counter = 0

    i = 0
    while i < len(messages):
        msg = messages[i]

        if msg["role"] == "tool":
            tool_use_counter += 1
            tool_use_id = f"toolu_{tool_use_counter:04d}"

            if converted and converted[-1]["role"] == "assistant":
                prev = converted.pop()
                converted.append({
                    "role": "assistant",
                    "content": [{
                        "type": "tool_use",
                        "id": tool_use_id,
                        "name": msg["name"],
                        "input": {},
                    }],
                })

            converted.append({
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": msg["content"],
                }],
            })
        elif msg["role"] == "assistant":
            converted.append({
                "role": "assistant",
                "content": [{"type": "text", "text": msg.get("content", "")}],
            })
        elif msg["role"] == "user":
            content = msg.get("content", "")
            if isinstance(content, str):
                converted.append({"role": "user", "content": content})
            else:
                converted.append({"role": "user", "content": content})
        else:
            converted.append(msg)
        i += 1

    return converted


def _convert_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert internal tool schema format to Anthropic API format."""
    anthropic_tools = []
    for tool in tools:
        schema = _normalize_tool_schema(tool.get("parameters", {}))
        anthropic_tools.append({
            "name": tool["name"],
            "description": tool.get("description", ""),
            "input_schema": schema,
        })
    return anthropic_tools


class AnthropicClient(LLMClient):
    """LLM client that calls the Anthropic Messages API using requests."""

    def __init__(self, api_key: str, default_model: str = "claude-haiku-4-5-20251001") -> None:
        self._api_key = api_key
        self._default_model = default_model

    def chat(
        self,
        model: str,
        system_prompt: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> LLMResponse:
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
            "x-api-key": self._api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "content-type": "application/json",
        }

        resp = requests.post(_ANTHROPIC_URL, headers=headers, json=body, timeout=120)

        if resp.status_code != 200:
            _log.debug("Anthropic API error %d: %s", resp.status_code, resp.text)
            raise LLMAPIError(
                f"Anthropic API error {resp.status_code}"
            )

        data = resp.json()
        usage = data.get("usage", {})
        tokens_used = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)

        tool_calls: list[ToolCall] = []
        raw_resolution: dict[str, Any] | None = None
        text_content = ""

        for block in data.get("content", []):
            if block["type"] == "tool_use":
                tool_calls.append(ToolCall(
                    name=block["name"],
                    arguments=block.get("input", {}),
                ))
            elif block["type"] == "text":
                text_content += block.get("text", "")

        if not tool_calls and text_content:
            raw_resolution = _extract_resolution(text_content)

        return LLMResponse(
            tool_calls=tool_calls,
            resolution=None,
            tokens_used=tokens_used,
            raw_resolution=raw_resolution,
            text=text_content,
        )
