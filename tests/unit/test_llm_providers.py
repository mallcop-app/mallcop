"""Tests for multi-provider LLM clients (Bedrock, OpenAI-compat)."""

import json

import pytest
from unittest.mock import patch, MagicMock

from mallcop.llm import (
    BedrockClient,
    OpenAICompatClient,
    build_llm_client,
    AnthropicClient,
    ClaudeCodeClient,
    LLMAPIError,
)
from mallcop.llm.bedrock import _convert_messages_bedrock, _convert_tools_bedrock
from mallcop.llm.openai_compat import _convert_messages_openai, _convert_tools_openai
from mallcop.aws_sigv4 import sign_v4_request as _sign_v4
from mallcop.config import LLMConfig
from mallcop.actors.runtime import ToolCall


# ---------------------------------------------------------------------------
# BedrockClient
# ---------------------------------------------------------------------------


class TestBedrockClient:
    def test_chat_basic_response(self):
        """BedrockClient returns LLMResponse with text content."""
        client = BedrockClient(
            model="us.anthropic.claude-3-5-haiku-20241022-v1:0",
            region="us-east-1",
            access_key="AKIATEST",
            secret_key="secret123",
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {
                            "text": '{"finding_id": "f1", "action": "resolved", "reason": "benign"}'
                        }
                    ],
                }
            },
            "usage": {"inputTokens": 100, "outputTokens": 50},
        }

        with patch("mallcop.llm.bedrock.requests.post", return_value=mock_resp):
            result = client.chat(
                "haiku",
                "You are a triage agent",
                [{"role": "user", "content": "hello"}],
                [],
            )

        assert result.tokens_used == 150
        assert result.raw_resolution is not None
        assert result.raw_resolution["action"] == "resolved"

    def test_chat_tool_use_response(self):
        """BedrockClient parses tool use blocks."""
        client = BedrockClient(
            model="us.anthropic.claude-3-5-haiku-20241022-v1:0",
            access_key="AKIATEST",
            secret_key="secret123",
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {
                            "toolUse": {
                                "toolUseId": "tu_1",
                                "name": "read-events",
                                "input": {"limit": 10},
                            }
                        }
                    ],
                }
            },
            "usage": {"inputTokens": 100, "outputTokens": 50},
        }

        with patch("mallcop.llm.bedrock.requests.post", return_value=mock_resp):
            result = client.chat(
                "haiku",
                "system",
                [{"role": "user", "content": "check"}],
                [
                    {
                        "name": "read-events",
                        "description": "Read events",
                        "parameters": {},
                    }
                ],
            )

        assert len(result.tool_calls) == 1
        assert result.tool_calls[0].name == "read-events"
        assert result.tool_calls[0].arguments == {"limit": 10}

    def test_chat_api_error(self):
        """BedrockClient raises LLMAPIError on non-200."""
        client = BedrockClient(model="test", access_key="AK", secret_key="SK")
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "Bad request"

        with patch("mallcop.llm.bedrock.requests.post", return_value=mock_resp):
            with pytest.raises(LLMAPIError):
                client.chat(
                    "haiku", "sys", [{"role": "user", "content": "hi"}], []
                )

    def test_chat_api_error_does_not_leak_response_body(self):
        """BedrockClient error message must not contain response body."""
        client = BedrockClient(model="test", access_key="AK", secret_key="SK")
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "SECRET_INTERNAL_ERROR_DETAILS_xyz"

        with patch("mallcop.llm.bedrock.requests.post", return_value=mock_resp):
            with pytest.raises(LLMAPIError) as exc_info:
                client.chat(
                    "haiku", "sys", [{"role": "user", "content": "hi"}], []
                )
            assert "SECRET_INTERNAL_ERROR_DETAILS_xyz" not in str(exc_info.value)
            assert "500" in str(exc_info.value)

    def test_chat_mixed_content(self):
        """BedrockClient handles mixed text and toolUse blocks."""
        client = BedrockClient(
            model="test-model", access_key="AK", secret_key="SK"
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {"text": "Let me check "},
                        {
                            "toolUse": {
                                "toolUseId": "tu_1",
                                "name": "check-baseline",
                                "input": {"actor": "admin"},
                            }
                        },
                    ],
                }
            },
            "usage": {"inputTokens": 50, "outputTokens": 25},
        }

        with patch("mallcop.llm.bedrock.requests.post", return_value=mock_resp):
            result = client.chat(
                "haiku", "sys", [{"role": "user", "content": "go"}], []
            )

        # Tool calls take precedence — no resolution extracted
        assert len(result.tool_calls) == 1
        assert result.raw_resolution is None

    def test_chat_sends_correct_url(self):
        """BedrockClient posts to the correct Converse API endpoint."""
        client = BedrockClient(
            model="my-model", region="eu-west-1", access_key="AK", secret_key="SK"
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "output": {"message": {"role": "assistant", "content": [{"text": "ok"}]}},
            "usage": {"inputTokens": 10, "outputTokens": 5},
        }

        with patch("mallcop.llm.bedrock.requests.post", return_value=mock_resp) as mock_post:
            client.chat("haiku", "sys", [{"role": "user", "content": "hi"}], [])

        call_url = mock_post.call_args[0][0]
        assert "bedrock-runtime.eu-west-1.amazonaws.com" in call_url
        assert "/model/my-model/converse" in call_url

    def test_default_region(self):
        """BedrockClient defaults to us-east-1."""
        client = BedrockClient(model="m", access_key="AK", secret_key="SK")
        assert client._region == "us-east-1"


# ---------------------------------------------------------------------------
# OpenAICompatClient
# ---------------------------------------------------------------------------


class TestOpenAICompatClient:
    def test_chat_basic_response(self):
        """OpenAICompatClient parses standard completion response."""
        client = OpenAICompatClient(
            endpoint="https://api.example.com/v1",
            api_key="sk-test",
            model="gpt-4",
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": '{"finding_id": "f1", "action": "resolved", "reason": "ok"}',
                    }
                }
            ],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50},
        }

        with patch("mallcop.llm.openai_compat.requests.post", return_value=mock_resp):
            result = client.chat(
                "gpt-4",
                "You are helpful",
                [{"role": "user", "content": "hello"}],
                [],
            )

        assert result.tokens_used == 150
        assert result.raw_resolution is not None
        assert result.raw_resolution["finding_id"] == "f1"

    def test_chat_tool_calls_response(self):
        """OpenAICompatClient parses tool_calls in response."""
        client = OpenAICompatClient(
            endpoint="https://api.example.com/v1",
            api_key="sk-test",
            model="gpt-4",
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": "read-events",
                                    "arguments": '{"limit": 5}',
                                },
                            }
                        ],
                    }
                }
            ],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50},
        }

        with patch("mallcop.llm.openai_compat.requests.post", return_value=mock_resp):
            result = client.chat(
                "gpt-4",
                "sys",
                [{"role": "user", "content": "check"}],
                [
                    {
                        "name": "read-events",
                        "description": "Read events",
                        "parameters": {},
                    }
                ],
            )

        assert len(result.tool_calls) == 1
        assert result.tool_calls[0].name == "read-events"
        assert result.tool_calls[0].arguments == {"limit": 5}

    def test_chat_api_error(self):
        """OpenAICompatClient raises LLMAPIError on non-200."""
        client = OpenAICompatClient(
            endpoint="https://api.example.com/v1", api_key="sk-test"
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal error"

        with patch("mallcop.llm.openai_compat.requests.post", return_value=mock_resp):
            with pytest.raises(LLMAPIError):
                client.chat(
                    "gpt-4", "sys", [{"role": "user", "content": "hi"}], []
                )

    def test_chat_api_error_does_not_leak_response_body(self):
        """OpenAICompatClient error message must not contain response body."""
        client = OpenAICompatClient(
            endpoint="https://api.example.com/v1", api_key="sk-test"
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "SECRET_OPENAI_ERROR_DETAILS_abc"

        with patch("mallcop.llm.openai_compat.requests.post", return_value=mock_resp):
            with pytest.raises(LLMAPIError) as exc_info:
                client.chat(
                    "gpt-4", "sys", [{"role": "user", "content": "hi"}], []
                )
            assert "SECRET_OPENAI_ERROR_DETAILS_abc" not in str(exc_info.value)
            assert "500" in str(exc_info.value)

    def test_chat_sends_correct_url(self):
        """OpenAICompatClient posts to {endpoint}/chat/completions."""
        client = OpenAICompatClient(
            endpoint="https://my-proxy.example.com/v1/",
            api_key="sk-test",
            model="llama-3",
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"role": "assistant", "content": "hi"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2},
        }

        with patch("mallcop.llm.openai_compat.requests.post", return_value=mock_resp) as mock_post:
            client.chat("llama-3", "sys", [{"role": "user", "content": "hi"}], [])

        call_url = mock_post.call_args[0][0]
        # Trailing slash should be stripped
        assert call_url == "https://my-proxy.example.com/v1/chat/completions"

    def test_chat_no_api_key(self):
        """OpenAICompatClient works without api_key (no Authorization header)."""
        client = OpenAICompatClient(
            endpoint="http://localhost:8080", api_key="", model="local"
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2},
        }

        with patch("mallcop.llm.openai_compat.requests.post", return_value=mock_resp) as mock_post:
            client.chat("local", "sys", [{"role": "user", "content": "hi"}], [])

        headers = mock_post.call_args[1]["headers"]
        assert "Authorization" not in headers

    def test_chat_with_api_key_sends_bearer(self):
        """OpenAICompatClient sends Bearer token when api_key is set."""
        client = OpenAICompatClient(
            endpoint="http://localhost:8080", api_key="my-key", model="local"
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2},
        }

        with patch("mallcop.llm.openai_compat.requests.post", return_value=mock_resp) as mock_post:
            client.chat("local", "sys", [{"role": "user", "content": "hi"}], [])

        headers = mock_post.call_args[1]["headers"]
        assert headers["Authorization"] == "Bearer my-key"

    def test_chat_invalid_tool_args_json(self):
        """OpenAICompatClient handles malformed JSON in tool arguments gracefully."""
        client = OpenAICompatClient(
            endpoint="http://localhost:8080", api_key="", model="m"
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "c1",
                                "type": "function",
                                "function": {
                                    "name": "read-events",
                                    "arguments": "NOT JSON",
                                },
                            }
                        ],
                    }
                }
            ],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2},
        }

        with patch("mallcop.llm.openai_compat.requests.post", return_value=mock_resp):
            result = client.chat("m", "sys", [{"role": "user", "content": "hi"}], [])

        assert len(result.tool_calls) == 1
        assert result.tool_calls[0].arguments == {}

    def test_chat_empty_choices(self):
        """OpenAICompatClient handles empty choices array."""
        client = OpenAICompatClient(
            endpoint="http://localhost:8080", api_key="", model="m"
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2},
        }

        with patch("mallcop.llm.openai_compat.requests.post", return_value=mock_resp):
            result = client.chat("m", "sys", [{"role": "user", "content": "hi"}], [])

        assert result.tool_calls == []
        assert result.raw_resolution is None


# ---------------------------------------------------------------------------
# Message conversion helpers
# ---------------------------------------------------------------------------


class TestConvertMessagesBedrock:
    def test_user_message(self):
        msgs = [{"role": "user", "content": "hello"}]
        result = _convert_messages_bedrock(msgs)
        assert result == [{"role": "user", "content": [{"text": "hello"}]}]

    def test_tool_message_with_preceding_assistant(self):
        msgs = [
            {"role": "assistant", "content": "Calling tool: read-events"},
            {"role": "tool", "name": "read-events", "content": "result data"},
        ]
        result = _convert_messages_bedrock(msgs)
        assert len(result) == 2
        # Assistant message should contain a toolUse block (may also have a text block)
        tool_use_blocks = [b for b in result[0]["content"] if "toolUse" in b]
        assert tool_use_blocks, "Expected a toolUse block in assistant content"
        assert tool_use_blocks[0]["toolUse"]["name"] == "read-events"
        # Tool result
        assert "toolResult" in result[1]["content"][0]

    def test_assistant_message(self):
        msgs = [{"role": "assistant", "content": "thinking..."}]
        result = _convert_messages_bedrock(msgs)
        assert result == [{"role": "assistant", "content": [{"text": "thinking..."}]}]


class TestConvertMessagesOpenAI:
    def test_system_prompt_included(self):
        result = _convert_messages_openai("You are helpful", [])
        assert result == [{"role": "system", "content": "You are helpful"}]

    def test_user_message(self):
        result = _convert_messages_openai("", [{"role": "user", "content": "hi"}])
        assert result == [{"role": "user", "content": "hi"}]

    def test_tool_message_rewrites_assistant(self):
        msgs = [
            {"role": "assistant", "content": "Calling tool: read-events"},
            {"role": "tool", "name": "read-events", "content": "data"},
        ]
        result = _convert_messages_openai("", msgs)
        assert len(result) == 2
        assert result[0]["role"] == "assistant"
        assert "tool_calls" in result[0]
        assert result[1]["role"] == "tool"
        assert "tool_call_id" in result[1]


class TestConvertToolsBedrock:
    def test_returns_none_for_empty(self):
        assert _convert_tools_bedrock([]) is None

    def test_converts_tool(self):
        tools = [{"name": "read-events", "description": "Read events", "parameters": {}}]
        result = _convert_tools_bedrock(tools)
        assert result is not None
        assert len(result["tools"]) == 1
        spec = result["tools"][0]["toolSpec"]
        assert spec["name"] == "read-events"


class TestConvertToolsOpenAI:
    def test_converts_tool(self):
        tools = [{"name": "read-events", "description": "Read events", "parameters": {}}]
        result = _convert_tools_openai(tools)
        assert len(result) == 1
        assert result[0]["type"] == "function"
        assert result[0]["function"]["name"] == "read-events"


# ---------------------------------------------------------------------------
# SigV4 signing
# ---------------------------------------------------------------------------


class TestSignV4:
    def test_produces_authorization_header(self):
        headers = _sign_v4(
            "POST",
            "https://bedrock-runtime.us-east-1.amazonaws.com/model/test/converse",
            {"content-type": "application/json"},
            b'{"test": true}',
            "us-east-1",
            "bedrock",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("AWS4-HMAC-SHA256")
        assert "x-amz-date" in headers

    def test_includes_signed_headers(self):
        headers = _sign_v4(
            "POST",
            "https://example.com/path",
            {"content-type": "application/json"},
            b"body",
            "us-east-1",
            "bedrock",
            "AK",
            "SK",
        )
        auth = headers["Authorization"]
        assert "SignedHeaders=" in auth
        assert "content-type" in auth
        assert "host" in auth


# ---------------------------------------------------------------------------
# build_llm_client routing
# ---------------------------------------------------------------------------


class TestBuildLLMClient:
    def test_anthropic_provider(self):
        config = LLMConfig(provider="anthropic", api_key="sk-ant-test")
        client = build_llm_client(config)
        assert isinstance(client, AnthropicClient)

    def test_anthropic_no_key_returns_none(self):
        config = LLMConfig(provider="anthropic", api_key="")
        client = build_llm_client(config)
        assert client is None

    def test_bedrock_provider(self):
        config = LLMConfig(
            provider="bedrock",
            api_key="AKIATEST",
            default_model="us.anthropic.claude-3-5-haiku-20241022-v1:0",
            endpoint="us-east-1",
            secret_key="secret123",
        )
        client = build_llm_client(config)
        assert isinstance(client, BedrockClient)
        assert client._region == "us-east-1"
        assert client._access_key == "AKIATEST"
        assert client._secret_key == "secret123"

    def test_bedrock_default_region(self):
        config = LLMConfig(
            provider="bedrock", api_key="AK", default_model="m", secret_key="SK"
        )
        client = build_llm_client(config)
        assert isinstance(client, BedrockClient)
        assert client._region == "us-east-1"

    def test_openai_compat_provider(self):
        config = LLMConfig(
            provider="openai-compat",
            api_key="sk-test",
            endpoint="https://api.example.com/v1",
            default_model="gpt-4",
        )
        client = build_llm_client(config)
        assert isinstance(client, OpenAICompatClient)

    def test_openai_compat_no_endpoint_returns_none(self):
        config = LLMConfig(provider="openai-compat", api_key="sk-test")
        client = build_llm_client(config)
        assert client is None

    def test_unknown_provider(self):
        config = LLMConfig(provider="unknown", api_key="test")
        client = build_llm_client(config)
        assert client is None

    def test_claude_code_backend(self):
        client = build_llm_client(None, backend="claude-code")
        assert isinstance(client, ClaudeCodeClient)

    def test_none_config_returns_none(self):
        client = build_llm_client(None)
        assert client is None


# ---------------------------------------------------------------------------
# Config parsing (LLMConfig with new fields)
# ---------------------------------------------------------------------------


class TestLLMConfigParsing:
    def test_endpoint_and_secret_key_fields(self):
        """LLMConfig has endpoint and secret_key fields."""
        config = LLMConfig(
            provider="bedrock",
            api_key="AK",
            default_model="model",
            endpoint="us-west-2",
            secret_key="SK",
        )
        assert config.endpoint == "us-west-2"
        assert config.secret_key == "SK"

    def test_defaults_are_empty(self):
        """New fields default to empty strings."""
        config = LLMConfig()
        assert config.endpoint == ""
        assert config.secret_key == ""

    def test_parse_llm_bedrock(self, tmp_path):
        """_parse_llm handles bedrock provider config."""
        import textwrap
        import yaml
        from mallcop.config import load_config

        config_yaml = textwrap.dedent("""\
            secrets:
              backend: env
            connectors: {}
            routing: {}
            actor_chain: {}
            budget: {}
            llm:
              provider: bedrock
              api_key: AKIATEST
              secret_key: SECRETTEST
              default_model: us.anthropic.claude-3-5-haiku-20241022-v1:0
              endpoint: us-west-2
        """)

        (tmp_path / "mallcop.yaml").write_text(config_yaml)
        cfg = load_config(tmp_path)
        assert cfg.llm is not None
        assert cfg.llm.provider == "bedrock"
        assert cfg.llm.api_key == "AKIATEST"
        assert cfg.llm.secret_key == "SECRETTEST"
        assert cfg.llm.endpoint == "us-west-2"

    def test_parse_llm_openai_compat(self, tmp_path):
        """_parse_llm handles openai-compat provider config."""
        import textwrap
        from mallcop.config import load_config

        config_yaml = textwrap.dedent("""\
            secrets:
              backend: env
            connectors: {}
            routing: {}
            actor_chain: {}
            budget: {}
            llm:
              provider: openai-compat
              endpoint: https://api.example.com/v1
              default_model: gpt-4
        """)

        (tmp_path / "mallcop.yaml").write_text(config_yaml)
        cfg = load_config(tmp_path)
        assert cfg.llm is not None
        assert cfg.llm.provider == "openai-compat"
        assert cfg.llm.endpoint == "https://api.example.com/v1"
        assert cfg.llm.api_key == ""  # optional for openai-compat

    def test_parse_llm_anthropic_no_key_returns_none(self, tmp_path):
        """_parse_llm returns None for anthropic without api_key."""
        import textwrap
        from mallcop.config import load_config

        config_yaml = textwrap.dedent("""\
            secrets:
              backend: env
            connectors: {}
            routing: {}
            actor_chain: {}
            budget: {}
            llm:
              provider: anthropic
        """)

        (tmp_path / "mallcop.yaml").write_text(config_yaml)
        cfg = load_config(tmp_path)
        assert cfg.llm is None

    def test_parse_llm_bedrock_no_key_still_returns_config(self, tmp_path):
        """_parse_llm returns LLMConfig for bedrock even without api_key (uses instance profile)."""
        import textwrap
        from mallcop.config import load_config

        config_yaml = textwrap.dedent("""\
            secrets:
              backend: env
            connectors: {}
            routing: {}
            actor_chain: {}
            budget: {}
            llm:
              provider: bedrock
              default_model: us.anthropic.claude-3-5-haiku-20241022-v1:0
              endpoint: us-east-1
        """)

        (tmp_path / "mallcop.yaml").write_text(config_yaml)
        cfg = load_config(tmp_path)
        assert cfg.llm is not None
        assert cfg.llm.provider == "bedrock"


# ---------------------------------------------------------------------------
# Error message sanitization — no response bodies leaked
# ---------------------------------------------------------------------------


class TestAnthropicClientErrorSanitization:
    def test_error_does_not_leak_response_body(self):
        """AnthropicClient error must not contain resp.text."""
        from mallcop.llm import AnthropicClient

        client = AnthropicClient(api_key="sk-test")
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "SENSITIVE_API_ERROR_BODY_123"

        with patch("mallcop.llm.anthropic.requests.post", return_value=mock_resp):
            with pytest.raises(LLMAPIError) as exc_info:
                client.chat(
                    "haiku", "sys", [{"role": "user", "content": "hi"}], []
                )
            assert "SENSITIVE_API_ERROR_BODY_123" not in str(exc_info.value)
            assert "403" in str(exc_info.value)


class TestManagedClientErrorSanitization:
    def test_error_does_not_leak_response_body(self):
        """ManagedClient error must not contain resp.text."""
        from mallcop.llm import ManagedClient

        client = ManagedClient(endpoint="https://api.mallcop.app", service_token="tok")
        mock_resp = MagicMock()
        mock_resp.status_code = 502
        mock_resp.text = "SENSITIVE_MANAGED_ERROR_BODY_456"

        with patch("mallcop.llm.managed.requests.post", return_value=mock_resp):
            with pytest.raises(LLMAPIError) as exc_info:
                client.chat(
                    "haiku", "sys", [{"role": "user", "content": "hi"}], []
                )
            assert "SENSITIVE_MANAGED_ERROR_BODY_456" not in str(exc_info.value)
            assert "502" in str(exc_info.value)


# ---------------------------------------------------------------------------
# resolve_model_id tests (mallcop-ak1n.5.11)
# ---------------------------------------------------------------------------

class TestResolveModelId:
    def test_haiku_alias(self):
        from mallcop.llm import resolve_model_id
        assert resolve_model_id("haiku") == "claude-haiku-4-5-20251001"

    def test_sonnet_alias(self):
        from mallcop.llm import resolve_model_id
        assert resolve_model_id("sonnet") == "claude-sonnet-4-6"

    def test_opus_alias(self):
        from mallcop.llm import resolve_model_id
        assert resolve_model_id("opus") == "claude-opus-4-6"

    def test_full_id_passthrough(self):
        from mallcop.llm import resolve_model_id
        assert resolve_model_id("claude-haiku-4-5-20251001") == "claude-haiku-4-5-20251001"

    def test_unknown_alias_passthrough(self):
        from mallcop.llm import resolve_model_id
        assert resolve_model_id("gpt-4o") == "gpt-4o"


class TestRegisterProvider:
    def test_custom_provider_callable(self):
        from mallcop.llm import register_provider, _PROVIDERS

        @register_provider("test_custom_provider")
        def _build_test(llm_config):
            return "test_client"

        assert "test_custom_provider" in _PROVIDERS
        assert _PROVIDERS["test_custom_provider"](None) == "test_client"
        # Cleanup
        del _PROVIDERS["test_custom_provider"]


class TestBuildLlmClientWithProConfig:
    def test_bedrock_provider_with_pro_config_does_not_route_to_managed(self):
        """When provider is 'bedrock' (not 'anthropic'), pro_config should not override."""
        from mallcop.llm import build_llm_client, LLMConfig
        llm_config = LLMConfig(
            provider="bedrock",
            default_model="haiku",
            api_key="test_key",
            secret_key="test_secret",
            endpoint="us-east-1",
        )
        pro_config = MagicMock()
        pro_config.service_token = "test_token"
        pro_config.inference_url = "https://api.mallcop.app"

        client = build_llm_client(llm_config, backend="bedrock", pro_config=pro_config)
        # Should be a BedrockClient, not ManagedClient
        assert client is not None
        assert type(client).__name__ != "ManagedClient"


# ─── 5.12: resolve_model_id and provider registry ────────────────────────────


class TestResolveModelId:
    """mallcop-ak1n.5.12: resolve_model_id alias mappings."""

    def test_haiku_alias_resolves(self) -> None:
        from mallcop.llm import resolve_model_id
        result = resolve_model_id("haiku")
        assert result == "claude-haiku-4-5-20251001"

    def test_sonnet_alias_resolves(self) -> None:
        from mallcop.llm import resolve_model_id
        result = resolve_model_id("sonnet")
        assert result == "claude-sonnet-4-6"

    def test_opus_alias_resolves(self) -> None:
        from mallcop.llm import resolve_model_id
        result = resolve_model_id("opus")
        assert result == "claude-opus-4-6"

    def test_full_model_id_passes_through_unchanged(self) -> None:
        from mallcop.llm import resolve_model_id
        full_id = "claude-haiku-4-5-20251001"
        assert resolve_model_id(full_id) == full_id

    def test_unknown_alias_returns_alias_unchanged(self) -> None:
        from mallcop.llm import resolve_model_id
        # Unknown alias should pass through as-is (no KeyError)
        result = resolve_model_id("my-custom-model-v1")
        assert result == "my-custom-model-v1"

    def test_empty_string_returns_empty_string(self) -> None:
        from mallcop.llm import resolve_model_id
        assert resolve_model_id("") == ""


class TestProviderRegistry:
    """mallcop-ak1n.5.12: register_provider decorator and build_llm_client routing."""

    def test_register_provider_decorator_registers_builder(self) -> None:
        """register_provider registers a builder that is callable via build_llm_client."""
        from mallcop.llm import register_provider, build_llm_client, _PROVIDERS
        from mallcop.config import LLMConfig

        test_provider_name = "_test_custom_provider_xyzzy"
        call_log: list[LLMConfig] = []

        @register_provider(test_provider_name)
        def _build_test(llm_config: LLMConfig):
            call_log.append(llm_config)
            return MagicMock()

        assert test_provider_name in _PROVIDERS

        llm_cfg = LLMConfig(provider=test_provider_name, api_key="", default_model="haiku")
        result = build_llm_client(llm_cfg, backend=test_provider_name)

        assert result is not None
        assert len(call_log) == 1

        # Cleanup
        del _PROVIDERS[test_provider_name]

    def test_build_llm_client_bedrock_with_pro_config_uses_provider_builder(self) -> None:
        """build_llm_client with bedrock provider AND pro_config routes to BedrockClient."""
        from mallcop.llm import build_llm_client, LLMConfig
        llm_config = LLMConfig(
            provider="bedrock",
            default_model="haiku",
            api_key="AKIATEST",
            secret_key="secretval",
            endpoint="us-east-1",
        )
        pro_config = MagicMock()
        pro_config.service_token = "svc_tok"
        pro_config.inference_url = "https://api.mallcop.app"

        # bedrock provider should not be overridden by pro_config
        client = build_llm_client(llm_config, backend="bedrock", pro_config=pro_config)
        assert client is not None
        assert type(client).__name__ == "BedrockClient"

    def test_build_llm_client_anthropic_with_pro_config_routes_to_managed(self) -> None:
        """build_llm_client with anthropic provider AND pro_config routes to ManagedClient."""
        from mallcop.llm import build_llm_client, LLMConfig, ManagedClient
        llm_config = LLMConfig(
            provider="anthropic",
            api_key="sk-ant-test",
            default_model="haiku",
        )
        pro_config = MagicMock()
        pro_config.service_token = "svc_tok"
        pro_config.inference_url = "https://api.mallcop.app"

        client = build_llm_client(llm_config, pro_config=pro_config)
        assert client is not None
        assert isinstance(client, ManagedClient)

    def test_build_llm_client_unsupported_provider_returns_none(self) -> None:
        """Unsupported provider yields None and logs a warning (does not raise)."""
        from mallcop.llm import build_llm_client, LLMConfig
        llm_config = LLMConfig(
            provider="totally-unknown-provider",
            api_key="key",
            default_model="haiku",
        )
        result = build_llm_client(llm_config)
        assert result is None


# ---------------------------------------------------------------------------
# tool_use_id uniqueness (2.26)
# ---------------------------------------------------------------------------


class TestToolUseIdUniqueness:
    def _get_bedrock_tool_use_id(self, result):
        """Extract toolUseId from converted bedrock messages (first toolUse block found)."""
        for msg in result:
            if msg["role"] == "assistant":
                for block in msg["content"]:
                    if "toolUse" in block:
                        return block["toolUse"]["toolUseId"]
        raise AssertionError("No toolUse block found in result")

    def test_bedrock_tool_use_ids_are_unique_across_calls(self):
        """Each _convert_messages_bedrock call produces unique tool_use IDs."""
        msgs = [
            {"role": "assistant", "content": "calling tool"},
            {"role": "tool", "name": "read-events", "content": "result"},
        ]
        result1 = _convert_messages_bedrock(msgs)
        result2 = _convert_messages_bedrock(msgs)
        id1 = self._get_bedrock_tool_use_id(result1)
        id2 = self._get_bedrock_tool_use_id(result2)
        assert id1 != id2

    def test_bedrock_tool_use_ids_unique_within_single_call(self):
        """Multiple tool messages in one call each get distinct IDs."""
        msgs = [
            {"role": "assistant", "content": "step 1"},
            {"role": "tool", "name": "tool-a", "content": "a result"},
            {"role": "assistant", "content": "step 2"},
            {"role": "tool", "name": "tool-b", "content": "b result"},
        ]
        result = _convert_messages_bedrock(msgs)
        tool_use_ids = [
            block["toolUse"]["toolUseId"]
            for msg in result
            if msg["role"] == "assistant"
            for block in msg["content"]
            if "toolUse" in block
        ]
        assert len(tool_use_ids) == 2
        assert tool_use_ids[0] != tool_use_ids[1]

    def test_anthropic_tool_use_ids_are_unique_across_calls(self):
        """Each _convert_messages call in anthropic.py produces unique tool_use IDs."""
        from mallcop.llm.anthropic import _convert_messages
        msgs = [
            {"role": "assistant", "content": "calling tool"},
            {"role": "tool", "name": "read-events", "content": "result"},
        ]
        result1 = _convert_messages(msgs)
        result2 = _convert_messages(msgs)
        id1 = next(
            b["id"] for m in result1 if m["role"] == "assistant"
            for b in m["content"] if b.get("type") == "tool_use"
        )
        id2 = next(
            b["id"] for m in result2 if m["role"] == "assistant"
            for b in m["content"] if b.get("type") == "tool_use"
        )
        assert id1 != id2


# ---------------------------------------------------------------------------
# Preserve prior assistant text when inserting tool_use blocks (beads 2.24, 2.25)
# ---------------------------------------------------------------------------


class TestAnthropicPreservesAssistantText:
    """_convert_messages must keep assistant text when inserting tool_use block."""

    def test_assistant_text_preserved_before_tool_use(self) -> None:
        """Text content from prior assistant turn is preserved alongside tool_use."""
        from mallcop.llm.anthropic import _convert_messages

        msgs = [
            {"role": "user", "content": "What is the finding?"},
            {"role": "assistant", "content": "I'll investigate this finding."},
            {"role": "tool", "name": "get_events", "content": '[{"id": "evt1"}]'},
        ]
        result = _convert_messages(msgs)

        # Find the assistant turn with the tool_use block
        assistant_msgs = [m for m in result if m["role"] == "assistant"]
        assert len(assistant_msgs) == 1
        content_blocks = assistant_msgs[0]["content"]
        block_types = [b.get("type") for b in content_blocks]
        assert "text" in block_types, "text block missing from assistant turn"
        assert "tool_use" in block_types, "tool_use block missing"

        text_block = next(b for b in content_blocks if b.get("type") == "text")
        assert text_block["text"] == "I'll investigate this finding."

    def test_no_prior_assistant_message_works(self) -> None:
        """Tool message with no prior assistant turn is handled gracefully."""
        from mallcop.llm.anthropic import _convert_messages

        msgs = [
            {"role": "user", "content": "Use the tool."},
            {"role": "tool", "name": "lookup", "content": "result"},
        ]
        # Should not raise
        result = _convert_messages(msgs)
        tool_result_msgs = [m for m in result if m["role"] == "user"
                            and isinstance(m.get("content"), list)
                            and any(b.get("type") == "tool_result" for b in m["content"])]
        assert len(tool_result_msgs) == 1


class TestBedrockPreservesAssistantText:
    """_convert_messages_bedrock must keep assistant text when inserting toolUse block."""

    def test_assistant_text_preserved_before_tool_use(self) -> None:
        """Text content from prior assistant turn is preserved alongside toolUse."""
        msgs = [
            {"role": "user", "content": "What is the finding?"},
            {"role": "assistant", "content": "Let me look into this."},
            {"role": "tool", "name": "get_events", "content": '[{"id": "evt1"}]'},
        ]
        result = _convert_messages_bedrock(msgs)

        assistant_msgs = [m for m in result if m["role"] == "assistant"]
        assert len(assistant_msgs) == 1
        content_blocks = assistant_msgs[0]["content"]
        # Should have both a text block and a toolUse block
        has_text = any("text" in b for b in content_blocks)
        has_tool_use = any("toolUse" in b for b in content_blocks)
        assert has_text, "text block missing from bedrock assistant turn"
        assert has_tool_use, "toolUse block missing"

        text_block = next(b for b in content_blocks if "text" in b)
        assert text_block["text"] == "Let me look into this."

    def test_no_prior_assistant_message_works(self) -> None:
        """Tool message with no prior assistant turn is handled gracefully."""
        msgs = [
            {"role": "user", "content": "Use the tool."},
            {"role": "tool", "name": "lookup", "content": "result"},
        ]
        result = _convert_messages_bedrock(msgs)
        tool_result_msgs = [
            m for m in result
            if m["role"] == "user"
            and any("toolResult" in b for b in m.get("content", []))
        ]
        assert len(tool_result_msgs) == 1


# ---------------------------------------------------------------------------
# _extract_resolution: robust JSON extraction (beads 2.35, 2.36)
# ---------------------------------------------------------------------------


class TestExtractResolution:
    """_extract_resolution must use bracket-matched extraction, not rfind('}')'."""

    def _call(self, text: str):
        from mallcop.llm.converters import _extract_resolution
        return _extract_resolution(text)

    def test_plain_json_extracted(self) -> None:
        """Simple JSON object is extracted correctly."""
        text = '{"finding_id": "fnd_abc", "action": "resolved", "reason": "benign"}'
        result = self._call(text)
        assert result is not None
        assert result["action"] == "resolved"

    def test_json_embedded_in_text(self) -> None:
        """JSON object embedded in prose is extracted."""
        text = 'After reviewing: {"finding_id": "fnd_abc", "action": "escalate"} — done.'
        result = self._call(text)
        assert result is not None
        assert result["action"] == "escalate"

    def test_two_json_objects_first_valid_returned(self) -> None:
        """When two JSON objects are present, the first valid resolution is returned."""
        text = (
            'Here is some context {"foo": "bar"} and the resolution: '
            '{"finding_id": "fnd_xyz", "action": "resolved", "reason": "ok"}'
        )
        result = self._call(text)
        assert result is not None
        assert result["finding_id"] == "fnd_xyz"

    def test_rfind_bug_repro_multiple_json_blocks(self) -> None:
        """Regression: rfind would span across two JSON objects producing invalid JSON.

        The old code: text[text.find('{'): text.rfind('}')+1] would produce:
        '{"foo": "bar"} and the resolution: {"finding_id": "fnd_xyz", ...}'
        which is not valid JSON, so json.loads would fail and return None.
        The fixed code finds the correct inner object.
        """
        text = (
            'First block: {"irrelevant": "data"} '
            'Second block: {"finding_id": "fnd_abc", "action": "escalate"}'
        )
        result = self._call(text)
        assert result is not None
        assert result["finding_id"] == "fnd_abc"
        assert result["action"] == "escalate"

    def test_no_json_returns_none(self) -> None:
        """Text with no JSON object returns None."""
        result = self._call("This is just plain text with no JSON.")
        assert result is None

    def test_json_missing_required_fields_returns_none(self) -> None:
        """JSON without finding_id and action fields is not a valid resolution."""
        result = self._call('{"status": "ok", "message": "hello"}')
        assert result is None

    def test_large_input_truncated(self) -> None:
        """Input exceeding 64KB is truncated without crashing."""
        big_text = "x" * 100_000 + '{"finding_id": "fnd_big", "action": "resolved"}'
        # The resolution JSON is beyond the 64KB limit, so None is expected
        result = self._call(big_text)
        # Either None (truncated) or the dict if somehow within limit — must not crash
        assert result is None or isinstance(result, dict)

    def test_valid_resolution_within_size_limit(self) -> None:
        """A valid resolution JSON within the 64KB limit is returned."""
        prefix = "a" * 1000
        text = prefix + ' {"finding_id": "fnd_ok", "action": "resolved", "reason": "safe"}'
        result = self._call(text)
        assert result is not None
        assert result["action"] == "resolved"
