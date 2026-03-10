"""Managed inference endpoint client."""

from __future__ import annotations

import logging
from typing import Any

import requests

from mallcop.llm_types import LLMAPIError, LLMClient, LLMResponse, ToolCall
from mallcop.llm.anthropic import _convert_messages, _convert_tools
from mallcop.llm.converters import _extract_resolution

_log = logging.getLogger(__name__)

_MAX_TOKENS_DEFAULT = 4096


class ManagedClient(LLMClient):
    """LLM client that calls the mallcop managed inference endpoint."""

    def __init__(
        self,
        endpoint: str,
        service_token: str,
        default_model: str = "claude-haiku-4-5-20251001",
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._service_token = service_token
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
