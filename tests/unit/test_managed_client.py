"""Tests for ManagedClient: managed inference endpoint LLM client."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mallcop.actors.runtime import LLMClient, LLMResponse, ToolCall


class TestManagedClientType:
    """ManagedClient implements LLMClient."""

    def test_is_llm_client(self) -> None:
        from mallcop.llm import ManagedClient

        assert issubclass(ManagedClient, LLMClient)

    def test_constructor(self) -> None:
        from mallcop.llm import ManagedClient

        client = ManagedClient(
            endpoint="https://api.mallcop.app",
            service_token="tok-123",
            default_model="haiku",
        )
        assert client._endpoint == "https://api.mallcop.app"
        assert client._service_token == "tok-123"

    def test_endpoint_trailing_slash_stripped(self) -> None:
        from mallcop.llm import ManagedClient

        client = ManagedClient(
            endpoint="https://api.mallcop.app/",
            service_token="tok-123",
        )
        assert client._endpoint == "https://api.mallcop.app"


class TestManagedClientChat:
    """ManagedClient.chat sends correct requests and parses responses."""

    def _make_client(self):
        from mallcop.llm import ManagedClient

        return ManagedClient(
            endpoint="https://api.mallcop.app",
            service_token="tok-test",
        )

    def _mock_response(self, content_blocks, usage=None, status_code=200):
        mock = MagicMock()
        mock.status_code = status_code
        mock.json.return_value = {
            "id": "msg_abc123",
            "type": "message",
            "role": "assistant",
            "content": content_blocks,
            "model": "claude-haiku-4-5-20251001",
            "usage": usage or {"input_tokens": 100, "output_tokens": 50},
            "stop_reason": "end_turn",
        }
        mock.text = "error text"
        return mock

    def test_chat_sends_bearer_token(self) -> None:
        client = self._make_client()
        mock_resp = self._mock_response([{"type": "text", "text": "Hello"}])

        with patch("mallcop.llm.managed.requests.post", return_value=mock_resp) as mock_post:
            client.chat(
                model="haiku",
                system_prompt="System",
                messages=[{"role": "user", "content": "Hi"}],
                tools=[],
            )

        call_kwargs = mock_post.call_args
        assert call_kwargs[0][0] == "https://api.mallcop.app/v1/messages"
        headers = call_kwargs[1]["headers"]
        assert headers["Authorization"] == "Bearer tok-test"
        assert "x-api-key" not in headers

    def test_chat_sends_correct_body(self) -> None:
        client = self._make_client()
        mock_resp = self._mock_response([{"type": "text", "text": "Done"}])

        with patch("mallcop.llm.managed.requests.post", return_value=mock_resp) as mock_post:
            client.chat(
                model="haiku",
                system_prompt="You are a triage agent.",
                messages=[{"role": "user", "content": "Investigate finding."}],
                tools=[{
                    "name": "get-events",
                    "description": "Get events",
                    "parameters": {"type": "object", "properties": {}},
                }],
            )

        body = mock_post.call_args[1]["json"]
        assert body["model"] == "claude-haiku-4-5-20251001"
        assert body["system"] == "You are a triage agent."
        assert len(body["messages"]) == 1
        assert len(body["tools"]) == 1

    def test_chat_returns_llm_response(self) -> None:
        client = self._make_client()
        mock_resp = self._mock_response(
            [{"type": "text", "text": "Done."}],
            usage={"input_tokens": 100, "output_tokens": 50},
        )

        with patch("mallcop.llm.managed.requests.post", return_value=mock_resp):
            result = client.chat(
                model="haiku",
                system_prompt="Test",
                messages=[{"role": "user", "content": "Hi"}],
                tools=[],
            )

        assert isinstance(result, LLMResponse)
        assert result.tokens_used == 150
        assert result.tool_calls == []

    def test_chat_parses_tool_use(self) -> None:
        client = self._make_client()
        mock_resp = self._mock_response([
            {"type": "tool_use", "id": "tu_1", "name": "get-events", "input": {"limit": 10}},
        ])

        with patch("mallcop.llm.managed.requests.post", return_value=mock_resp):
            result = client.chat(
                model="haiku",
                system_prompt="Test",
                messages=[{"role": "user", "content": "Hi"}],
                tools=[{"name": "get-events", "description": "Get events", "parameters": {}}],
            )

        assert len(result.tool_calls) == 1
        assert result.tool_calls[0].name == "get-events"
        assert result.tool_calls[0].arguments == {"limit": 10}

    def test_chat_parses_resolution_json(self) -> None:
        client = self._make_client()
        resolution = {
            "finding_id": "f-123",
            "action": "dismiss",
            "reason": "Known benign",
        }
        mock_resp = self._mock_response([
            {"type": "text", "text": json.dumps(resolution)},
        ])

        with patch("mallcop.llm.managed.requests.post", return_value=mock_resp):
            result = client.chat(
                model="haiku",
                system_prompt="Test",
                messages=[{"role": "user", "content": "Hi"}],
                tools=[{"name": "resolve", "description": "Resolve", "parameters": {}}],
            )

        assert result.raw_resolution == resolution

    def test_chat_api_error_raises(self) -> None:
        from mallcop.llm import LLMAPIError

        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 502
        mock_resp.text = "Bad Gateway"

        with patch("mallcop.llm.managed.requests.post", return_value=mock_resp):
            with pytest.raises(LLMAPIError, match="502"):
                client.chat(
                    model="haiku",
                    system_prompt="Test",
                    messages=[{"role": "user", "content": "Hi"}],
                    tools=[],
                )


class TestBuildLLMClientManaged:
    """build_llm_client routes to ManagedClient for managed provider and pro_config."""

    def test_managed_provider_explicit(self) -> None:
        from mallcop.config import LLMConfig
        from mallcop.llm import ManagedClient, build_llm_client

        llm_config = LLMConfig(
            provider="managed",
            api_key="svc-token-123",
            default_model="haiku",
        )
        client = build_llm_client(llm_config)
        assert isinstance(client, ManagedClient)
        assert client._service_token == "svc-token-123"

    def test_managed_provider_no_api_key_returns_none(self) -> None:
        from mallcop.config import LLMConfig
        from mallcop.llm import build_llm_client

        llm_config = LLMConfig(provider="managed", api_key="", default_model="haiku")
        assert build_llm_client(llm_config) is None

    def test_pro_config_auto_routes_to_managed(self) -> None:
        from mallcop.llm import ManagedClient, build_llm_client

        pro = MagicMock()
        pro.service_token = "svc-tok"
        pro.inference_url = "https://custom.endpoint.dev"

        client = build_llm_client(None, pro_config=pro)
        assert isinstance(client, ManagedClient)
        assert client._endpoint == "https://custom.endpoint.dev"
        assert client._service_token == "svc-tok"

    def test_pro_config_with_anthropic_llm_config_auto_routes(self) -> None:
        from mallcop.config import LLMConfig
        from mallcop.llm import ManagedClient, build_llm_client

        llm_config = LLMConfig(provider="anthropic", api_key="sk-test")
        pro = MagicMock()
        pro.service_token = "svc-tok"
        pro.inference_url = None

        client = build_llm_client(llm_config, pro_config=pro)
        assert isinstance(client, ManagedClient)
        from mallcop.config import DEFAULT_INFERENCE_URL
        assert client._endpoint == DEFAULT_INFERENCE_URL

    def test_pro_config_without_service_token_falls_through(self) -> None:
        from mallcop.config import LLMConfig
        from mallcop.llm import AnthropicClient, build_llm_client

        llm_config = LLMConfig(provider="anthropic", api_key="sk-test")
        pro = MagicMock()
        pro.service_token = ""
        pro.inference_url = None

        client = build_llm_client(llm_config, pro_config=pro)
        assert isinstance(client, AnthropicClient)
