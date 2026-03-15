"""AWS Bedrock Mantle client — OpenAI-compatible endpoint with SigV4 auth.

Used for models that support tool calling through the Chat Completions API
but NOT through the Converse API's toolResult mechanism (e.g. GLM 4.7,
Mistral Large 3).

The bedrock-mantle endpoint speaks OpenAI Chat Completions format.
Auth is SigV4 (same as Converse API), not API key.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import requests

from mallcop.aws_sigv4 import sign_v4_request
from mallcop.llm.openai_compat import (
    OpenAICompatClient,
    _convert_messages_openai,
    _convert_tools_openai,
)
from mallcop.llm_types import LLMAPIError, LLMClient, LLMResponse, ToolCall
from mallcop.llm.converters import _extract_resolution

_log = logging.getLogger(__name__)

from mallcop.llm.converters import DEFAULT_MAX_TOKENS as _MAX_TOKENS_DEFAULT


def _parse_tool_arguments(raw: str) -> dict[str, Any]:
    """Parse tool call arguments, handling malformed JSON from some models.

    Some models (e.g. GLM 4.7 via bedrock-mantle) produce doubled or
    concatenated JSON in the arguments field like:
        '{"a":"1","b":"2"{"a": "1", "b": "2"}'
    Strategy: try the full string first, then look for embedded valid
    JSON objects at every '{' position.
    """
    raw = raw.strip()
    if not raw:
        return {}

    # Fast path: valid JSON
    try:
        result = json.loads(raw)
        if isinstance(result, dict):
            return result
        return {}
    except (json.JSONDecodeError, ValueError):
        pass

    # Slow path: try raw_decode at every '{' to find the first valid object
    decoder = json.JSONDecoder()
    for i, ch in enumerate(raw):
        if ch == "{":
            try:
                obj, end = decoder.raw_decode(raw, i)
                if isinstance(obj, dict) and obj:
                    return obj
            except json.JSONDecodeError:
                continue

    _log.warning("Could not parse tool arguments: %s", raw[:200])
    return {}


class BedrockMantleClient(LLMClient):
    """LLM client for Bedrock's OpenAI-compatible (mantle) endpoint.

    Uses the same message format as OpenAICompatClient but authenticates
    with SigV4 instead of an API key.  Required for models like GLM 4.7
    and Mistral Large 3 whose Bedrock integrations support tool calling
    only through the Chat Completions API, not via Converse API toolResult.
    """

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
        self._endpoint = f"https://bedrock-mantle.{region}.api.aws/v1"

    @classmethod
    def from_profile(
        cls,
        model: str,
        region: str = "us-east-1",
        profile: str | None = None,
    ) -> "BedrockMantleClient":
        """Create client using boto3 credential resolution (SSO, env, etc.)."""
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
        url = f"{self._endpoint}/chat/completions"

        openai_messages = _convert_messages_openai(system_prompt, messages)

        body: dict[str, Any] = {
            "model": self._model,
            "messages": openai_messages,
            "max_tokens": _MAX_TOKENS_DEFAULT,
        }

        openai_tools = _convert_tools_openai(tools)
        if openai_tools:
            body["tools"] = openai_tools

        body_bytes = json.dumps(body).encode("utf-8")
        headers = {"content-type": "application/json"}

        signed_headers = sign_v4_request(
            "POST", url, headers, body_bytes,
            self._region, "bedrock", self._access_key, self._secret_key,
            session_token=self._session_token,
        )

        resp = requests.post(url, headers=signed_headers, data=body_bytes, timeout=120)

        if resp.status_code != 200:
            _log.debug("Bedrock Mantle API error %d: %s", resp.status_code, resp.text)
            raise LLMAPIError(
                f"Bedrock Mantle API error {resp.status_code}"
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
                    args = _parse_tool_arguments(args_str)
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
