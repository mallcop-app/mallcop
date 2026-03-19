"""AWS Bedrock Converse API client."""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

import requests

from mallcop.aws_sigv4 import sign_v4_request
from mallcop.llm_types import LLMAPIError, LLMClient, LLMResponse, ToolCall
from mallcop.llm.converters import _normalize_tool_schema, _extract_resolution

_log = logging.getLogger(__name__)

from mallcop.llm.converters import DEFAULT_MAX_TOKENS as _MAX_TOKENS_DEFAULT


def _convert_messages_bedrock(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert internal message format to Bedrock Converse API format."""
    converted: list[dict[str, Any]] = []

    i = 0
    while i < len(messages):
        msg = messages[i]

        if msg["role"] == "tool":
            tool_use_id = f"toolu_{uuid.uuid4().hex[:12]}"

            if converted and converted[-1]["role"] == "assistant":
                prev = converted.pop()
                # Preserve any text content from the previous assistant message
                prev_content = prev.get("content", [])
                preserved_text = []
                if isinstance(prev_content, list):
                    preserved_text = [
                        block for block in prev_content
                        if isinstance(block, dict) and "text" in block
                    ]
                new_content = preserved_text + [{
                    "toolUse": {
                        "toolUseId": tool_use_id,
                        "name": msg["name"],
                        "input": {},
                    }
                }]
                converted.append({
                    "role": "assistant",
                    "content": new_content,
                })

            converted.append({
                "role": "user",
                "content": [{
                    "toolResult": {
                        "toolUseId": tool_use_id,
                        "content": [{"text": str(msg["content"])}],
                    }
                }],
            })
        elif msg["role"] == "assistant":
            content = msg.get("content", "")
            converted.append({
                "role": "assistant",
                "content": [{"text": content}] if isinstance(content, str) else content,
            })
        elif msg["role"] == "user":
            content = msg.get("content", "")
            if isinstance(content, str):
                converted.append({"role": "user", "content": [{"text": content}]})
            else:
                converted.append({"role": "user", "content": content})
        else:
            converted.append(msg)
        i += 1

    return converted


def _convert_tools_bedrock(tools: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Convert internal tool schema format to Bedrock toolConfig format."""
    if not tools:
        return None

    bedrock_tools = []
    for tool in tools:
        schema = _normalize_tool_schema(tool.get("parameters", {}))
        bedrock_tools.append({
            "toolSpec": {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "inputSchema": {"json": schema},
            }
        })

    return {"tools": bedrock_tools}


class BedrockClient(LLMClient):
    """LLM client that calls AWS Bedrock Converse API with SigV4 signing."""

    def __init__(
        self,
        model: str,
        region: str = "us-east-1",
        access_key: str = "",
        secret_key: str = "",
        session_token: str = "",
    ) -> None:
        self._model = model
        self._region = region
        self._access_key = access_key
        self._secret_key = secret_key
        self._session_token = session_token

    @classmethod
    def from_profile(
        cls,
        model: str,
        region: str = "us-east-1",
        profile: str | None = None,
    ) -> "BedrockClient":
        """Create a BedrockClient using boto3 credential resolution.

        Supports SSO, env vars, instance profiles, config profiles — anything
        boto3 understands.  Requires ``boto3`` (``pip install mallcop[aws]``).
        """
        try:
            import boto3
        except ImportError:
            raise ImportError(
                "boto3 is required for profile-based credentials. "
                "Install with: pip install mallcop[aws]"
            ) from None
        session = boto3.Session(profile_name=profile, region_name=region)
        creds = session.get_credentials()
        if creds is None:
            raise RuntimeError(
                f"No AWS credentials found for profile={profile!r}. "
                "Run 'aws sso login --profile <name>' first."
            )
        frozen = creds.get_frozen_credentials()
        return cls(
            model=model,
            region=region,
            access_key=frozen.access_key,
            secret_key=frozen.secret_key,
            session_token=frozen.token or "",
        )

    def chat(
        self,
        model: str,
        system_prompt: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> LLMResponse:
        model_id = self._model
        url = (
            f"https://bedrock-runtime.{self._region}.amazonaws.com"
            f"/model/{model_id}/converse"
        )

        bedrock_messages = _convert_messages_bedrock(messages)

        body: dict[str, Any] = {
            "modelId": model_id,
            "messages": bedrock_messages,
            "inferenceConfig": {"maxTokens": _MAX_TOKENS_DEFAULT},
        }
        if system_prompt:
            body["system"] = [{"text": system_prompt}]

        tool_config = _convert_tools_bedrock(tools)
        if tool_config:
            body["toolConfig"] = tool_config

        body_bytes = json.dumps(body).encode("utf-8")

        headers = {"content-type": "application/json"}
        signed_headers = sign_v4_request(
            "POST", url, headers, body_bytes,
            self._region, "bedrock", self._access_key, self._secret_key,
            session_token=self._session_token,
        )

        resp = requests.post(url, headers=signed_headers, data=body_bytes, timeout=120)

        if resp.status_code != 200:
            _log.debug("Bedrock API error %d: %s", resp.status_code, resp.text)
            raise LLMAPIError(
                f"Bedrock API error {resp.status_code}"
            )

        data = resp.json()
        usage = data.get("usage", {})
        tokens_used = usage.get("inputTokens", 0) + usage.get("outputTokens", 0)

        tool_calls: list[ToolCall] = []
        raw_resolution: dict[str, Any] | None = None
        text_content = ""

        output_msg = data.get("output", {}).get("message", {})
        for block in output_msg.get("content", []):
            if "toolUse" in block:
                tu = block["toolUse"]
                tool_calls.append(ToolCall(
                    name=tu["name"],
                    arguments=tu.get("input", {}),
                ))
            elif "text" in block:
                text_content += block["text"]

        if not tool_calls and text_content:
            raw_resolution = _extract_resolution(text_content)

        return LLMResponse(
            tool_calls=tool_calls,
            resolution=None,
            tokens_used=tokens_used,
            raw_resolution=raw_resolution,
        )
