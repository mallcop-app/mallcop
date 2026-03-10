"""Tests for services/inference/router.py: format translation between providers."""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from services.inference.router import (
    _bedrock_to_anthropic,
    _map_finish_reason,
    _openai_to_anthropic,
    _sign_bedrock,
    route_request,
)


class TestModelMapping:
    """Model alias resolution in router."""

    def test_unknown_provider_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown provider"):
            route_request(
                {"model": "haiku", "messages": []},
                {"provider": "gcp-vertex"},
            )


class TestAnthropicToBedrockConversion:
    """Anthropic Messages API -> Bedrock Converse format."""

    def test_simple_text_message(self) -> None:
        """Simple text messages convert to Bedrock content format."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "output": {"message": {"content": [{"text": "Hello"}]}},
            "usage": {"inputTokens": 10, "outputTokens": 5},
            "stopReason": "end_turn",
        }

        with patch("services.inference.router.requests.post", return_value=mock_resp) as mock_post:
            result = route_request(
                {
                    "model": "haiku",
                    "messages": [{"role": "user", "content": "Hi"}],
                    "max_tokens": 1024,
                },
                {"provider": "bedrock", "region": "us-east-1", "access_key": "AK", "secret_key": "SK"},
            )

        # Verify the bedrock request body
        call_data = json.loads(mock_post.call_args[1]["data"])
        assert call_data["messages"][0]["role"] == "user"
        assert call_data["messages"][0]["content"] == [{"text": "Hi"}]
        assert call_data["inferenceConfig"]["maxTokens"] == 1024

    def test_system_prompt_conversion(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "output": {"message": {"content": [{"text": "OK"}]}},
            "usage": {"inputTokens": 10, "outputTokens": 5},
            "stopReason": "end_turn",
        }

        with patch("services.inference.router.requests.post", return_value=mock_resp) as mock_post:
            route_request(
                {
                    "model": "haiku",
                    "system": "You are a security analyst.",
                    "messages": [{"role": "user", "content": "Hi"}],
                },
                {"provider": "bedrock", "region": "us-east-1", "access_key": "AK", "secret_key": "SK"},
            )

        call_data = json.loads(mock_post.call_args[1]["data"])
        assert call_data["system"] == [{"text": "You are a security analyst."}]

    def test_tool_use_message_conversion(self) -> None:
        """Content blocks with tool_use convert to Bedrock toolUse format."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "output": {"message": {"content": [{"text": "Done"}]}},
            "usage": {"inputTokens": 10, "outputTokens": 5},
            "stopReason": "end_turn",
        }

        messages = [
            {
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": "tu_1", "name": "get-events", "input": {"limit": 5}},
                ],
            },
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "tu_1", "content": "[]"},
                ],
            },
        ]

        with patch("services.inference.router.requests.post", return_value=mock_resp) as mock_post:
            route_request(
                {"model": "haiku", "messages": messages},
                {"provider": "bedrock", "region": "us-east-1", "access_key": "AK", "secret_key": "SK"},
            )

        call_data = json.loads(mock_post.call_args[1]["data"])
        # Assistant message should have toolUse
        assistant_msg = call_data["messages"][0]
        assert "toolUse" in assistant_msg["content"][0]
        assert assistant_msg["content"][0]["toolUse"]["name"] == "get-events"

        # User message should have toolResult
        user_msg = call_data["messages"][1]
        assert "toolResult" in user_msg["content"][0]
        assert user_msg["content"][0]["toolResult"]["toolUseId"] == "tu_1"

    def test_tools_convert_to_toolconfig(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "output": {"message": {"content": [{"text": "OK"}]}},
            "usage": {"inputTokens": 10, "outputTokens": 5},
            "stopReason": "end_turn",
        }

        with patch("services.inference.router.requests.post", return_value=mock_resp) as mock_post:
            route_request(
                {
                    "model": "haiku",
                    "messages": [{"role": "user", "content": "Hi"}],
                    "tools": [
                        {
                            "name": "get-events",
                            "description": "Get events",
                            "input_schema": {"type": "object", "properties": {"limit": {"type": "integer"}}},
                        }
                    ],
                },
                {"provider": "bedrock", "region": "us-east-1", "access_key": "AK", "secret_key": "SK"},
            )

        call_data = json.loads(mock_post.call_args[1]["data"])
        assert "toolConfig" in call_data
        tool_spec = call_data["toolConfig"]["tools"][0]["toolSpec"]
        assert tool_spec["name"] == "get-events"
        assert tool_spec["inputSchema"]["json"]["type"] == "object"

    def test_temperature_passed_through(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "output": {"message": {"content": [{"text": "OK"}]}},
            "usage": {"inputTokens": 10, "outputTokens": 5},
            "stopReason": "end_turn",
        }

        with patch("services.inference.router.requests.post", return_value=mock_resp) as mock_post:
            route_request(
                {
                    "model": "haiku",
                    "messages": [{"role": "user", "content": "Hi"}],
                    "temperature": 0.5,
                },
                {"provider": "bedrock", "region": "us-east-1", "access_key": "AK", "secret_key": "SK"},
            )

        call_data = json.loads(mock_post.call_args[1]["data"])
        assert call_data["inferenceConfig"]["temperature"] == 0.5

    def test_bedrock_error_raises(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "Bad Request"

        with patch("services.inference.router.requests.post", return_value=mock_resp):
            with pytest.raises(RuntimeError, match="Bedrock error 400"):
                route_request(
                    {"model": "haiku", "messages": [{"role": "user", "content": "Hi"}]},
                    {"provider": "bedrock", "region": "us-east-1", "access_key": "AK", "secret_key": "SK"},
                )


class TestBedrockToAnthropicConversion:
    """Bedrock Converse response -> Anthropic Messages API format."""

    def test_text_response(self) -> None:
        bedrock_resp = {
            "output": {"message": {"content": [{"text": "Hello world"}]}},
            "usage": {"inputTokens": 100, "outputTokens": 50},
            "stopReason": "end_turn",
        }
        result = _bedrock_to_anthropic(bedrock_resp, "haiku")

        assert result["type"] == "message"
        assert result["role"] == "assistant"
        assert result["model"] == "haiku"
        assert len(result["content"]) == 1
        assert result["content"][0]["type"] == "text"
        assert result["content"][0]["text"] == "Hello world"
        assert result["usage"]["input_tokens"] == 100
        assert result["usage"]["output_tokens"] == 50
        assert result["stop_reason"] == "end_turn"
        assert result["id"].startswith("msg_")

    def test_tool_use_response(self) -> None:
        bedrock_resp = {
            "output": {
                "message": {
                    "content": [
                        {
                            "toolUse": {
                                "toolUseId": "tu_abc",
                                "name": "get-events",
                                "input": {"limit": 10},
                            }
                        }
                    ]
                }
            },
            "usage": {"inputTokens": 50, "outputTokens": 25},
            "stopReason": "tool_use",
        }
        result = _bedrock_to_anthropic(bedrock_resp, "sonnet")

        assert len(result["content"]) == 1
        assert result["content"][0]["type"] == "tool_use"
        assert result["content"][0]["name"] == "get-events"
        assert result["content"][0]["id"] == "tu_abc"
        assert result["content"][0]["input"] == {"limit": 10}
        assert result["stop_reason"] == "tool_use"

    def test_empty_content(self) -> None:
        bedrock_resp = {
            "output": {"message": {"content": []}},
            "usage": {"inputTokens": 10, "outputTokens": 0},
            "stopReason": "end_turn",
        }
        result = _bedrock_to_anthropic(bedrock_resp, "haiku")
        assert result["content"] == []


class TestAnthropicToOpenAIConversion:
    """Anthropic Messages API -> OpenAI chat completions format."""

    def test_simple_text_message(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "Hello"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }

        with patch("services.inference.router.requests.post", return_value=mock_resp) as mock_post:
            result = route_request(
                {
                    "model": "gpt-4",
                    "system": "You are helpful.",
                    "messages": [{"role": "user", "content": "Hi"}],
                },
                {"provider": "openai-compat", "endpoint": "https://api.example.com", "api_key": "sk-test"},
            )

        call_body = mock_post.call_args[1]["json"]
        # System prompt becomes system message
        assert call_body["messages"][0] == {"role": "system", "content": "You are helpful."}
        assert call_body["messages"][1] == {"role": "user", "content": "Hi"}

    def test_openai_tools_conversion(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "OK"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }

        with patch("services.inference.router.requests.post", return_value=mock_resp) as mock_post:
            route_request(
                {
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": "Hi"}],
                    "tools": [
                        {
                            "name": "get-events",
                            "description": "Get events",
                            "input_schema": {"type": "object", "properties": {}},
                        }
                    ],
                },
                {"provider": "openai-compat", "endpoint": "https://api.example.com", "api_key": "sk-test"},
            )

        call_body = mock_post.call_args[1]["json"]
        assert len(call_body["tools"]) == 1
        assert call_body["tools"][0]["type"] == "function"
        assert call_body["tools"][0]["function"]["name"] == "get-events"

    def test_openai_error_raises(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"

        with patch("services.inference.router.requests.post", return_value=mock_resp):
            with pytest.raises(RuntimeError, match="OpenAI-compat error 500"):
                route_request(
                    {"model": "gpt-4", "messages": [{"role": "user", "content": "Hi"}]},
                    {"provider": "openai-compat", "endpoint": "https://api.example.com", "api_key": "sk-test"},
                )


class TestOpenAIToAnthropicConversion:
    """OpenAI chat completion response -> Anthropic Messages API format."""

    def test_text_response(self) -> None:
        openai_resp = {
            "choices": [{"message": {"content": "Hello world"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50},
        }
        result = _openai_to_anthropic(openai_resp, "gpt-4")

        assert result["type"] == "message"
        assert result["role"] == "assistant"
        assert result["model"] == "gpt-4"
        assert result["content"][-1]["type"] == "text"
        assert result["content"][-1]["text"] == "Hello world"
        assert result["usage"]["input_tokens"] == 100
        assert result["usage"]["output_tokens"] == 50
        assert result["stop_reason"] == "end_turn"

    def test_tool_call_response(self) -> None:
        openai_resp = {
            "choices": [{
                "message": {
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_abc",
                            "type": "function",
                            "function": {
                                "name": "get-events",
                                "arguments": '{"limit": 10}',
                            },
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }],
            "usage": {"prompt_tokens": 50, "completion_tokens": 25},
        }
        result = _openai_to_anthropic(openai_resp, "gpt-4")

        assert len(result["content"]) == 1
        assert result["content"][0]["type"] == "tool_use"
        assert result["content"][0]["name"] == "get-events"
        assert result["content"][0]["id"] == "call_abc"
        assert result["content"][0]["input"] == {"limit": 10}
        assert result["stop_reason"] == "tool_use"

    def test_invalid_json_arguments_handled(self) -> None:
        openai_resp = {
            "choices": [{
                "message": {
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_abc",
                            "type": "function",
                            "function": {"name": "test", "arguments": "not json"},
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }
        result = _openai_to_anthropic(openai_resp, "gpt-4")
        assert result["content"][0]["input"] == {}

    def test_empty_response(self) -> None:
        openai_resp = {
            "choices": [{"message": {}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 0},
        }
        result = _openai_to_anthropic(openai_resp, "gpt-4")
        # Should have a fallback empty text block
        assert len(result["content"]) == 1
        assert result["content"][0]["text"] == ""


class TestInferenceAppErrorSanitization:
    """Inference endpoint must not leak upstream error details."""

    def test_route_error_does_not_leak_in_http_detail(self) -> None:
        """When routing raises, the /v1/messages endpoint must not include exception str in detail."""
        import services.inference.app as _app
        from fastapi.testclient import TestClient
        import jwt as _jwt
        import time

        # Create a valid JWT for the test
        secret = os.environ.get("ACCOUNT_SECRET", "test-secret")
        token = _jwt.encode(
            {"sub": "acct_test", "plan": "free", "iat": int(time.time()), "exp": int(time.time()) + 3600},
            secret,
            algorithm="HS256",
        )

        # Disable metering to avoid SQLite cross-thread issues with TestClient
        from services.inference.dependencies import get_meter, set_meter
        original_meter = get_meter()
        set_meter(None)
        try:
            client = TestClient(_app.app)
            with patch("services.inference.router.route_request", side_effect=RuntimeError("SENSITIVE_UPSTREAM_ERROR_xyz")):
                resp = client.post(
                    "/v1/messages",
                    json={"model": "haiku", "messages": [{"role": "user", "content": "hi"}]},
                    headers={"Authorization": f"Bearer {token}"},
                )
            assert resp.status_code == 502
            assert "SENSITIVE_UPSTREAM_ERROR_xyz" not in resp.text
        finally:
            set_meter(original_meter)

    def test_jwt_error_does_not_leak_details(self) -> None:
        """Invalid JWT error message must not include exception details."""
        from services.inference.app import app
        from fastapi.testclient import TestClient

        client = TestClient(app)
        resp = client.post(
            "/v1/messages",
            json={"model": "haiku", "messages": []},
            headers={"Authorization": "Bearer invalid-jwt-token"},
        )
        assert resp.status_code == 401
        # Should say "Invalid service token" but not include PyJWT internals
        body = resp.json()
        assert "detail" in body
        assert "Invalid service token" in body["detail"]
        # Must not contain internal exception message
        assert "Not enough segments" not in body["detail"]


class TestFinishReasonMapping:
    """OpenAI finish_reason -> Anthropic stop_reason mapping."""

    def test_stop_maps_to_end_turn(self) -> None:
        assert _map_finish_reason("stop") == "end_turn"

    def test_length_maps_to_max_tokens(self) -> None:
        assert _map_finish_reason("length") == "max_tokens"

    def test_tool_calls_maps_to_tool_use(self) -> None:
        assert _map_finish_reason("tool_calls") == "tool_use"

    def test_unknown_maps_to_end_turn(self) -> None:
        assert _map_finish_reason("content_filter") == "end_turn"


class TestRouterEdgeCases:
    """Edge cases in request routing and format conversion."""

    def test_null_model_uses_default(self) -> None:
        """Request with no model field should use default (haiku for bedrock)."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "output": {"message": {"content": [{"text": "OK"}]}},
            "usage": {"inputTokens": 10, "outputTokens": 5},
            "stopReason": "end_turn",
        }

        with patch("services.inference.router.requests.post", return_value=mock_resp) as mock_post:
            result = route_request(
                {"messages": [{"role": "user", "content": "Hi"}]},
                {"provider": "bedrock", "region": "us-east-1", "access_key": "AK", "secret_key": "SK"},
            )
        assert result["type"] == "message"
        # Should have called bedrock with the default haiku model
        call_url = mock_post.call_args[0][0]
        assert "claude" in call_url.lower() or "haiku" in call_url.lower() or "anthropic" in call_url.lower()

    def test_empty_messages_sends_empty_list(self) -> None:
        """Request with empty messages list should still call the provider."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "output": {"message": {"content": [{"text": ""}]}},
            "usage": {"inputTokens": 0, "outputTokens": 0},
            "stopReason": "end_turn",
        }

        with patch("services.inference.router.requests.post", return_value=mock_resp) as mock_post:
            result = route_request(
                {"model": "haiku", "messages": []},
                {"provider": "bedrock", "region": "us-east-1", "access_key": "AK", "secret_key": "SK"},
            )
        call_data = json.loads(mock_post.call_args[1]["data"])
        assert call_data["messages"] == []
        assert result["type"] == "message"

    def test_malformed_bedrock_response_missing_usage(self) -> None:
        """Bedrock response missing usage field should use zeros."""
        bedrock_resp = {
            "output": {"message": {"content": [{"text": "hi"}]}},
            "stopReason": "end_turn",
        }
        result = _bedrock_to_anthropic(bedrock_resp, "haiku")
        assert result["usage"]["input_tokens"] == 0
        assert result["usage"]["output_tokens"] == 0

    def test_malformed_bedrock_response_missing_output(self) -> None:
        """Bedrock response missing output should produce empty content."""
        bedrock_resp = {
            "usage": {"inputTokens": 10, "outputTokens": 5},
            "stopReason": "end_turn",
        }
        result = _bedrock_to_anthropic(bedrock_resp, "haiku")
        assert result["content"] == []

    def test_malformed_bedrock_response_missing_stop_reason(self) -> None:
        """Missing stopReason defaults to end_turn."""
        bedrock_resp = {
            "output": {"message": {"content": [{"text": "hi"}]}},
            "usage": {"inputTokens": 10, "outputTokens": 5},
        }
        result = _bedrock_to_anthropic(bedrock_resp, "haiku")
        assert result["stop_reason"] == "end_turn"

    def test_openai_response_with_null_content_and_no_tool_calls(self) -> None:
        """OpenAI response with null content and no tool_calls produces empty text."""
        openai_resp = {
            "choices": [{"message": {"content": None}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 0},
        }
        result = _openai_to_anthropic(openai_resp, "gpt-4")
        assert len(result["content"]) == 1
        assert result["content"][0]["text"] == ""

    def test_openai_response_missing_choices(self) -> None:
        """OpenAI response with empty choices should still produce valid output."""
        openai_resp = {
            "choices": [],
            "usage": {"prompt_tokens": 10, "completion_tokens": 0},
        }
        # choices[0] would be {} from the default [{}][0]
        result = _openai_to_anthropic(openai_resp, "gpt-4")
        assert result["type"] == "message"

    def test_openai_malformed_tool_json_returns_empty_dict(self) -> None:
        """Tool call with truncated/malformed JSON arguments returns empty dict."""
        openai_resp = {
            "choices": [{
                "message": {
                    "content": None,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "test", "arguments": '{"key": "val'},  # truncated JSON
                    }],
                },
                "finish_reason": "tool_calls",
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }
        result = _openai_to_anthropic(openai_resp, "gpt-4")
        assert result["content"][0]["input"] == {}

    def test_openai_tool_with_empty_arguments_string(self) -> None:
        """Tool call with empty string arguments returns empty dict."""
        openai_resp = {
            "choices": [{
                "message": {
                    "content": None,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "test", "arguments": ""},
                    }],
                },
                "finish_reason": "tool_calls",
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }
        result = _openai_to_anthropic(openai_resp, "gpt-4")
        # Empty string -> json.loads fails -> {} OR json.loads("") fails -> {}
        assert result["content"][0]["input"] == {}

    def test_bedrock_unknown_content_block_type_ignored(self) -> None:
        """Unknown content block types in bedrock response are silently ignored."""
        bedrock_resp = {
            "output": {"message": {"content": [
                {"text": "hello"},
                {"unknownType": {"data": "stuff"}},  # unknown block
                {"toolUse": {"toolUseId": "tu_1", "name": "test", "input": {}}},
            ]}},
            "usage": {"inputTokens": 10, "outputTokens": 5},
            "stopReason": "end_turn",
        }
        result = _bedrock_to_anthropic(bedrock_resp, "haiku")
        # Should have text + tool_use, unknown block skipped
        assert len(result["content"]) == 2
        assert result["content"][0]["type"] == "text"
        assert result["content"][1]["type"] == "tool_use"

    def test_openai_missing_usage_field(self) -> None:
        """OpenAI response missing usage entirely defaults to zeros."""
        openai_resp = {
            "choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}],
        }
        result = _openai_to_anthropic(openai_resp, "gpt-4")
        assert result["usage"]["input_tokens"] == 0
        assert result["usage"]["output_tokens"] == 0


class TestSigV4Signing:
    """AWS SigV4 signing produces valid headers."""

    def test_sign_produces_required_headers(self) -> None:
        headers = _sign_bedrock(
            url="https://bedrock-runtime.us-east-1.amazonaws.com/model/test/converse",
            body=b'{"test": true}',
            region="us-east-1",
            access_key="AKIATEST",
            secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        )
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("AWS4-HMAC-SHA256")
        assert "x-amz-date" in headers
        assert "x-amz-content-sha256" in headers
        assert "Host" in headers
        assert headers["Host"] == "bedrock-runtime.us-east-1.amazonaws.com"

    def test_sign_contains_credential_and_signature(self) -> None:
        headers = _sign_bedrock(
            url="https://bedrock-runtime.us-west-2.amazonaws.com/model/test/converse",
            body=b"{}",
            region="us-west-2",
            access_key="AKIATEST",
            secret_key="secret123",
        )
        auth = headers["Authorization"]
        assert "Credential=AKIATEST/" in auth
        assert "Signature=" in auth
        assert "SignedHeaders=host;x-amz-date" in auth
