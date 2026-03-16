"""Tests for LLM client: AnthropicClient + config parsing + CLI wiring."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mallcop.actors.runtime import LLMClient, LLMResponse, ToolCall


# ---------------------------------------------------------------------------
# 1. LLMConfig dataclass + config parsing
# ---------------------------------------------------------------------------

class TestLLMConfig:
    """LLM config section in mallcop.yaml."""

    def test_parse_llm_section(self, tmp_path: Path) -> None:
        """llm section parsed into LLMConfig dataclass."""
        from mallcop.config import LLMConfig, load_config

        cfg = tmp_path / "mallcop.yaml"
        cfg.write_text(
            "secrets:\n  backend: env\nconnectors: {}\n"
            "llm:\n  provider: anthropic\n"
            "  api_key: ${ANTHROPIC_API_KEY}\n"
            "  default_model: claude-haiku-4-5-20251001\n"
        )
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test-key"}):
            config = load_config(tmp_path)
        assert config.llm is not None
        assert config.llm.provider == "anthropic"
        assert config.llm.api_key == "sk-test-key"
        assert config.llm.default_model == "claude-haiku-4-5-20251001"

    def test_missing_llm_section_gives_none(self, tmp_path: Path) -> None:
        """No llm section -> config.llm is None."""
        from mallcop.config import load_config

        cfg = tmp_path / "mallcop.yaml"
        cfg.write_text("secrets:\n  backend: env\nconnectors: {}\n")
        config = load_config(tmp_path)
        assert config.llm is None

    def test_llm_defaults(self, tmp_path: Path) -> None:
        """Missing fields in llm section get defaults."""
        from mallcop.config import LLMConfig, load_config

        cfg = tmp_path / "mallcop.yaml"
        cfg.write_text(
            "secrets:\n  backend: env\nconnectors: {}\n"
            "llm:\n  provider: anthropic\n"
            "  api_key: ${ANTHROPIC_API_KEY}\n"
        )
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test"}):
            config = load_config(tmp_path)
        assert config.llm is not None
        assert config.llm.default_model == "claude-haiku-4-5-20251001"

    def test_llm_api_key_not_resolved_gives_none(self, tmp_path: Path) -> None:
        """If api_key uses ${VAR} and VAR is unset, llm is None (graceful)."""
        from mallcop.config import load_config

        cfg = tmp_path / "mallcop.yaml"
        cfg.write_text(
            "secrets:\n  backend: env\nconnectors: {}\n"
            "llm:\n  provider: anthropic\n"
            "  api_key: ${ANTHROPIC_API_KEY}\n"
        )
        with patch.dict("os.environ", {}, clear=True):
            # Remove the var if it exists
            import os
            os.environ.pop("ANTHROPIC_API_KEY", None)
            config = load_config(tmp_path)
        assert config.llm is None

    def test_llm_literal_api_key(self, tmp_path: Path) -> None:
        """Literal api_key (not ${VAR}) is used directly."""
        from mallcop.config import load_config

        cfg = tmp_path / "mallcop.yaml"
        cfg.write_text(
            "secrets:\n  backend: env\nconnectors: {}\n"
            "llm:\n  provider: anthropic\n"
            "  api_key: sk-literal-key\n"
        )
        config = load_config(tmp_path)
        assert config.llm is not None
        assert config.llm.api_key == "sk-literal-key"


# ---------------------------------------------------------------------------
# 2. Model alias mapping
# ---------------------------------------------------------------------------

class TestModelMapping:
    """Actor manifest model field maps to real Anthropic model ID."""

    def test_haiku_alias(self) -> None:
        from mallcop.llm import resolve_model_id
        assert resolve_model_id("haiku") == "claude-haiku-4-5-20251001"

    def test_sonnet_alias(self) -> None:
        from mallcop.llm import resolve_model_id
        assert resolve_model_id("sonnet") == "claude-sonnet-4-6"

    def test_opus_alias(self) -> None:
        from mallcop.llm import resolve_model_id
        assert resolve_model_id("opus") == "claude-opus-4-6"

    def test_full_model_id_passthrough(self) -> None:
        from mallcop.llm import resolve_model_id
        assert resolve_model_id("claude-haiku-4-5-20251001") == "claude-haiku-4-5-20251001"

    def test_default_model_used(self) -> None:
        from mallcop.llm import resolve_model_id
        assert resolve_model_id("haiku", default="claude-sonnet-4-5-20250514") == "claude-haiku-4-5-20251001"


# ---------------------------------------------------------------------------
# 3. AnthropicClient implements LLMClient
# ---------------------------------------------------------------------------

class TestAnthropicClient:
    """AnthropicClient calls the Anthropic Messages API via requests."""

    def test_is_llm_client(self) -> None:
        from mallcop.llm import AnthropicClient
        assert issubclass(AnthropicClient, LLMClient)

    def test_chat_sends_correct_request(self) -> None:
        """Verify the HTTP request structure sent to Anthropic."""
        from mallcop.llm import AnthropicClient

        client = AnthropicClient(api_key="sk-test", default_model="claude-haiku-4-5-20251001")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "I'll investigate this."}],
            "usage": {"input_tokens": 100, "output_tokens": 50},
        }

        with patch("mallcop.llm.anthropic.requests.post", return_value=mock_response) as mock_post:
            result = client.chat(
                model="haiku",
                system_prompt="You are a triage agent.",
                messages=[{"role": "user", "content": "Investigate finding."}],
                tools=[{
                    "name": "get-events",
                    "description": "Get events",
                    "parameters": {"type": "object", "properties": {}},
                }],
            )

        # Verify the request
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert call_kwargs[0][0] == "https://api.anthropic.com/v1/messages"
        headers = call_kwargs[1]["headers"]
        assert headers["x-api-key"] == "sk-test"
        assert headers["anthropic-version"] == "2023-06-01"

        body = call_kwargs[1]["json"]
        assert body["model"] == "claude-haiku-4-5-20251001"
        assert body["system"] == "You are a triage agent."
        assert len(body["messages"]) == 1
        assert len(body["tools"]) == 1

    def test_chat_returns_llm_response(self) -> None:
        """Verify LLMResponse is correctly constructed from API response."""
        from mallcop.llm import AnthropicClient

        client = AnthropicClient(api_key="sk-test", default_model="claude-haiku-4-5-20251001")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Done."}],
            "usage": {"input_tokens": 100, "output_tokens": 50},
        }

        with patch("mallcop.llm.anthropic.requests.post", return_value=mock_response):
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
        """Tool use blocks in response become ToolCall objects."""
        from mallcop.llm import AnthropicClient

        client = AnthropicClient(api_key="sk-test", default_model="claude-haiku-4-5-20251001")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "tool_use", "id": "tu_1", "name": "get-events", "input": {"limit": 10}},
            ],
            "usage": {"input_tokens": 100, "output_tokens": 50},
        }

        with patch("mallcop.llm.anthropic.requests.post", return_value=mock_response):
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
        """Text content containing valid JSON resolution is extracted."""
        from mallcop.llm import AnthropicClient

        client = AnthropicClient(api_key="sk-test", default_model="claude-haiku-4-5-20251001")

        resolution = {
            "finding_id": "f-123",
            "action": "dismiss",
            "reason": "Known benign activity",
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "text", "text": json.dumps(resolution)},
            ],
            "usage": {"input_tokens": 100, "output_tokens": 50},
            "stop_reason": "end_turn",
        }

        with patch("mallcop.llm.anthropic.requests.post", return_value=mock_response):
            result = client.chat(
                model="haiku",
                system_prompt="Test",
                messages=[{"role": "user", "content": "Hi"}],
                tools=[{"name": "resolve", "description": "Resolve", "parameters": {}}],
            )

        assert result.raw_resolution == resolution

    def test_chat_api_error_raises(self) -> None:
        """Non-200 response raises an error."""
        from mallcop.llm import AnthropicClient, LLMAPIError

        client = AnthropicClient(api_key="sk-test", default_model="claude-haiku-4-5-20251001")

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Invalid API key"
        mock_response.raise_for_status.side_effect = Exception("401 Unauthorized")

        with patch("mallcop.llm.anthropic.requests.post", return_value=mock_response):
            with pytest.raises(LLMAPIError, match="401"):
                client.chat(
                    model="haiku",
                    system_prompt="Test",
                    messages=[{"role": "user", "content": "Hi"}],
                    tools=[],
                )

    def test_tool_message_format(self) -> None:
        """Tool results in messages are formatted correctly for Anthropic API."""
        from mallcop.llm import AnthropicClient

        client = AnthropicClient(api_key="sk-test", default_model="claude-haiku-4-5-20251001")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "OK"}],
            "usage": {"input_tokens": 50, "output_tokens": 20},
        }

        messages = [
            {"role": "user", "content": "Investigate."},
            {"role": "assistant", "content": "Calling tool: get-events"},
            {"role": "tool", "name": "get-events", "content": '{"events": []}'},
        ]

        with patch("mallcop.llm.anthropic.requests.post", return_value=mock_response) as mock_post:
            client.chat(
                model="haiku",
                system_prompt="Test",
                messages=messages,
                tools=[{"name": "get-events", "description": "Get", "parameters": {}}],
            )

        body = mock_post.call_args[1]["json"]
        # Tool results become tool_result content blocks for Anthropic
        tool_msg = body["messages"][2]
        assert tool_msg["role"] == "user"
        assert tool_msg["content"][0]["type"] == "tool_result"


# ---------------------------------------------------------------------------
# 3b. Tool schema conversion (_convert_tools)
# ---------------------------------------------------------------------------

class TestConvertTools:
    """_convert_tools produces valid Anthropic API tool definitions."""

    def test_input_schema_has_type_object_when_already_proper(self) -> None:
        """A tool with proper JSON Schema passes through with type: object."""
        from mallcop.llm.anthropic import _convert_tools

        tools = [{
            "name": "read-events",
            "description": "Read events from store",
            "parameters": {
                "type": "object",
                "properties": {"limit": {"type": "integer"}},
                "required": ["limit"],
            },
        }]
        result = _convert_tools(tools)
        assert len(result) == 1
        assert result[0]["input_schema"]["type"] == "object"
        assert "properties" in result[0]["input_schema"]

    def test_input_schema_has_type_object_when_flat_derive_schema(self) -> None:
        """A tool with flat _derive_schema output gets wrapped with type: object.

        This is the actual bug: _build_tool_schemas passes meta.parameter_schema
        which is {param_name: {type, required}} — missing the JSON Schema wrapper.
        """
        from mallcop.llm.anthropic import _convert_tools

        # This is what _derive_schema / _build_tool_schemas actually produces
        tools = [{
            "name": "read-events",
            "description": "Read events from store",
            "parameters": {
                "limit": {"type": "int", "required": True},
                "offset": {"type": "int", "required": False, "default": 0},
            },
        }]
        result = _convert_tools(tools)
        schema = result[0]["input_schema"]
        assert schema["type"] == "object"
        assert "properties" in schema
        assert "limit" in schema["properties"]
        assert schema["properties"]["limit"]["type"] == "integer"
        assert schema["required"] == ["limit"]

    def test_input_schema_has_type_object_when_empty(self) -> None:
        """A tool with no parameters still gets type: object."""
        from mallcop.llm.anthropic import _convert_tools

        tools = [{
            "name": "get-status",
            "description": "Get status",
            "parameters": {},
        }]
        result = _convert_tools(tools)
        assert result[0]["input_schema"]["type"] == "object"

    def test_input_schema_has_type_object_when_parameters_missing(self) -> None:
        """A tool with no parameters key at all still gets type: object."""
        from mallcop.llm.anthropic import _convert_tools

        tools = [{"name": "noop", "description": "No-op"}]
        result = _convert_tools(tools)
        assert result[0]["input_schema"]["type"] == "object"

    def test_python_type_mapping(self) -> None:
        """Python type names from _derive_schema map to JSON Schema types."""
        from mallcop.llm.anthropic import _convert_tools

        tools = [{
            "name": "test-tool",
            "description": "Test",
            "parameters": {
                "name": {"type": "str", "required": True},
                "count": {"type": "int", "required": False},
                "score": {"type": "float", "required": False},
                "active": {"type": "bool", "required": False},
            },
        }]
        result = _convert_tools(tools)
        props = result[0]["input_schema"]["properties"]
        assert props["name"]["type"] == "string"
        assert props["count"]["type"] == "integer"
        assert props["score"]["type"] == "number"
        assert props["active"]["type"] == "boolean"


# ---------------------------------------------------------------------------
# 4. CLI wiring: build_llm_client helper
# ---------------------------------------------------------------------------

class TestBuildLLMClient:
    """CLI helper that builds LLMClient from config."""

    def test_build_from_config(self) -> None:
        """With valid LLMConfig, returns AnthropicClient."""
        from mallcop.config import LLMConfig
        from mallcop.llm import AnthropicClient, build_llm_client

        llm_config = LLMConfig(
            provider="anthropic",
            api_key="sk-test",
            default_model="claude-haiku-4-5-20251001",
        )
        client = build_llm_client(llm_config)
        assert isinstance(client, AnthropicClient)

    def test_build_none_config_returns_none(self) -> None:
        """None config returns None (graceful degradation)."""
        from mallcop.llm import build_llm_client

        assert build_llm_client(None) is None

    def test_unsupported_provider_returns_none(self) -> None:
        """Unknown provider returns None."""
        from mallcop.config import LLMConfig
        from mallcop.llm import build_llm_client

        llm_config = LLMConfig(provider="openai", api_key="sk-test")
        assert build_llm_client(llm_config) is None


# ---------------------------------------------------------------------------
# 5. Graceful degradation in CLI
# ---------------------------------------------------------------------------

class TestGracefulDegradation:
    """When no LLM config or API key, actors are skipped gracefully."""

    def test_no_llm_config_actor_runner_is_none(self, tmp_path: Path) -> None:
        """build_actor_runner returns None when llm is None."""
        from mallcop.actors.runtime import build_actor_runner
        from mallcop.config import MallcopConfig, BudgetConfig

        config = MallcopConfig(
            secrets_backend="env",
            connectors={},
            routing={},
            actor_chain={},
            budget=BudgetConfig(),
            llm=None,
        )
        runner = build_actor_runner(
            root=tmp_path, store=MagicMock(), config=config, llm=None
        )
        assert runner is None
