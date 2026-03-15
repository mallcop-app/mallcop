"""OpenAI-compatible API client."""

from __future__ import annotations

import json
import logging
from typing import Any

import requests

from mallcop.llm_types import LLMAPIError, LLMClient, LLMResponse, ToolCall
from mallcop.llm.converters import _normalize_tool_schema, _extract_resolution

_log = logging.getLogger(__name__)

from mallcop.llm.converters import DEFAULT_MAX_TOKENS as _MAX_TOKENS_DEFAULT


def _convert_messages_openai(
    system_prompt: str,
    messages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Convert internal message format to OpenAI chat completions format."""
    converted: list[dict[str, Any]] = []

    if system_prompt:
        converted.append({"role": "system", "content": system_prompt})

    tool_use_counter = 0

    i = 0
    while i < len(messages):
        msg = messages[i]

        if msg["role"] == "tool":
            tool_use_counter += 1
            tool_call_id = f"call_{tool_use_counter:04d}"

            if converted and converted[-1]["role"] == "assistant":
                prev = converted.pop()
                converted.append({
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": tool_call_id,
                        "type": "function",
                        "function": {
                            "name": msg["name"],
                            "arguments": "{}",
                        },
                    }],
                })

            converted.append({
                "role": "tool",
                "tool_call_id": tool_call_id,
                "content": str(msg["content"]),
            })
        elif msg["role"] == "assistant":
            converted.append({
                "role": "assistant",
                "content": msg.get("content", ""),
            })
        elif msg["role"] == "user":
            converted.append({
                "role": "user",
                "content": msg.get("content", ""),
            })
        else:
            converted.append(msg)
        i += 1

    return converted


def _convert_tools_openai(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert internal tool schema format to OpenAI function calling format."""
    openai_tools = []
    for tool in tools:
        schema = _normalize_tool_schema(tool.get("parameters", {}))
        openai_tools.append({
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "parameters": schema,
            },
        })
    return openai_tools


class OpenAICompatClient(LLMClient):
    """LLM client for any OpenAI-compatible API endpoint."""

    def __init__(
        self,
        endpoint: str,
        api_key: str = "",
        model: str = "",
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._api_key = api_key
        self._model = model

    def chat(
        self,
        model: str,
        system_prompt: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> LLMResponse:
        url = f"{self._endpoint}/chat/completions"
        resolved_model = self._model or model

        openai_messages = _convert_messages_openai(system_prompt, messages)

        body: dict[str, Any] = {
            "model": resolved_model,
            "messages": openai_messages,
            "max_tokens": _MAX_TOKENS_DEFAULT,
        }

        openai_tools = _convert_tools_openai(tools)
        if openai_tools:
            body["tools"] = openai_tools

        headers: dict[str, str] = {"content-type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        resp = requests.post(url, headers=headers, json=body, timeout=120)

        if resp.status_code != 200:
            _log.debug("OpenAI-compat API error %d: %s", resp.status_code, resp.text)
            raise LLMAPIError(
                f"OpenAI-compat API error {resp.status_code}"
            )

        data = resp.json()
        usage = data.get("usage", {})
        tokens_used = usage.get("prompt_tokens", 0) + usage.get("completion_tokens", 0)

        tool_calls: list[ToolCall] = []
        raw_resolution: dict[str, Any] | None = None
        text_content = ""

        choices = data.get("choices", [])
        if choices:
            msg = choices[0].get("message", {})
            content = msg.get("content")
            if content:
                text_content = content

            for tc in msg.get("tool_calls", []):
                if tc.get("type") == "function":
                    fn = tc.get("function", {})
                    args_str = fn.get("arguments", "{}")
                    try:
                        args = json.loads(args_str)
                    except (json.JSONDecodeError, ValueError):
                        args = {}
                    tool_calls.append(ToolCall(
                        name=fn.get("name", ""),
                        arguments=args,
                    ))

        if not tool_calls and text_content:
            raw_resolution = _extract_resolution(text_content)

        return LLMResponse(
            tool_calls=tool_calls,
            resolution=None,
            tokens_used=tokens_used,
            raw_resolution=raw_resolution,
        )
