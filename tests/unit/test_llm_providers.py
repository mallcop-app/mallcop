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
    _convert_messages_bedrock,
    _convert_messages_openai,
    _convert_tools_bedrock,
    _convert_tools_openai,
    _sign_v4,
)
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
        # Assistant rewritten as toolUse
        assert "toolUse" in result[0]["content"][0]
        assert result[0]["content"][0]["toolUse"]["name"] == "read-events"
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

        client = ManagedClient(endpoint="https://api.mallcop.dev", service_token="tok")
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
