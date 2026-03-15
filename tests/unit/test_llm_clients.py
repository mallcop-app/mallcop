"""Unit tests for LLM client error paths in mallcop.llm."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest
import requests

from mallcop.llm import AnthropicClient, ClaudeCodeClient, LLMAPIError, _PROVIDERS, register_provider


# ===========================================================================
# Provider registry
# ===========================================================================

class TestProviderRegistry:
    """Verify that all expected providers self-register via @register_provider."""

    EXPECTED_PROVIDERS = {"anthropic", "managed", "bedrock", "bedrock-mantle", "openai-compat"}

    def test_all_expected_providers_registered(self) -> None:
        assert set(_PROVIDERS.keys()) == self.EXPECTED_PROVIDERS

    def test_providers_are_callable(self) -> None:
        for name, builder in _PROVIDERS.items():
            assert callable(builder), f"Provider {name!r} is not callable"

    def test_register_provider_decorator_adds_to_dict(self) -> None:
        """Verify the decorator mechanism works for a new provider."""
        @register_provider("test-provider")
        def _build_test(llm_config):
            return None

        assert "test-provider" in _PROVIDERS
        assert _PROVIDERS["test-provider"] is _build_test
        # Clean up
        del _PROVIDERS["test-provider"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_error_response(status_code: int, text: str = "") -> MagicMock:
    """Build a mock requests.Response with a non-200 status."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.text = text or f"error {status_code}"
    return resp


def _make_success_response(data: dict) -> MagicMock:
    """Build a mock 200 response with JSON payload."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = 200
    resp.json.return_value = data
    resp.text = ""
    return resp


CHAT_ARGS = (
    "haiku",
    "You are a security analyst.",
    [{"role": "user", "content": "Hello"}],
    [],
)


# ===========================================================================
# AnthropicClient error paths
# ===========================================================================

class TestAnthropicClientErrors:
    """AnthropicClient.chat() error handling."""

    def _client(self) -> AnthropicClient:
        return AnthropicClient(api_key="sk-test-key")

    # -- HTTP error codes ---------------------------------------------------

    @patch("mallcop.llm.anthropic.requests.post")
    def test_http_400_raises_llm_api_error(self, mock_post: MagicMock) -> None:
        mock_post.return_value = _make_error_response(400, "invalid request body")
        with pytest.raises(LLMAPIError, match="400"):
            self._client().chat(*CHAT_ARGS)

    @patch("mallcop.llm.anthropic.requests.post")
    def test_http_429_raises_llm_api_error(self, mock_post: MagicMock) -> None:
        mock_post.return_value = _make_error_response(429, "rate limited")
        with pytest.raises(LLMAPIError, match="429"):
            self._client().chat(*CHAT_ARGS)

    @patch("mallcop.llm.anthropic.requests.post")
    def test_http_500_raises_llm_api_error(self, mock_post: MagicMock) -> None:
        mock_post.return_value = _make_error_response(500, "internal server error")
        with pytest.raises(LLMAPIError, match="500"):
            self._client().chat(*CHAT_ARGS)

    @patch("mallcop.llm.anthropic.requests.post")
    def test_http_401_raises_llm_api_error(self, mock_post: MagicMock) -> None:
        mock_post.return_value = _make_error_response(401, "invalid x-api-key")
        with pytest.raises(LLMAPIError, match="401"):
            self._client().chat(*CHAT_ARGS)

    @patch("mallcop.llm.anthropic.requests.post")
    def test_http_403_raises_llm_api_error(self, mock_post: MagicMock) -> None:
        mock_post.return_value = _make_error_response(403, "forbidden")
        with pytest.raises(LLMAPIError, match="403"):
            self._client().chat(*CHAT_ARGS)

    @patch("mallcop.llm.anthropic.requests.post")
    def test_http_503_raises_llm_api_error(self, mock_post: MagicMock) -> None:
        mock_post.return_value = _make_error_response(503, "service unavailable")
        with pytest.raises(LLMAPIError, match="503"):
            self._client().chat(*CHAT_ARGS)

    # -- Error message content ----------------------------------------------

    @patch("mallcop.llm.anthropic.requests.post")
    def test_error_message_includes_status_code(self, mock_post: MagicMock) -> None:
        mock_post.return_value = _make_error_response(400, "model_not_found")
        with pytest.raises(LLMAPIError, match="400"):
            self._client().chat(*CHAT_ARGS)

    # -- Timeout ------------------------------------------------------------

    @patch("mallcop.llm.anthropic.requests.post")
    def test_timeout_propagates(self, mock_post: MagicMock) -> None:
        mock_post.side_effect = requests.exceptions.Timeout("Connection timed out")
        with pytest.raises(requests.exceptions.Timeout):
            self._client().chat(*CHAT_ARGS)

    @patch("mallcop.llm.anthropic.requests.post")
    def test_connection_error_propagates(self, mock_post: MagicMock) -> None:
        mock_post.side_effect = requests.exceptions.ConnectionError("DNS failure")
        with pytest.raises(requests.exceptions.ConnectionError):
            self._client().chat(*CHAT_ARGS)

    # -- Success path (minimal, to confirm mocking works) -------------------

    @patch("mallcop.llm.anthropic.requests.post")
    def test_success_returns_llm_response(self, mock_post: MagicMock) -> None:
        mock_post.return_value = _make_success_response({
            "content": [{"type": "text", "text": "All clear."}],
            "usage": {"input_tokens": 10, "output_tokens": 5},
        })
        resp = self._client().chat(*CHAT_ARGS)
        assert resp.tokens_used == 15
        assert resp.tool_calls == []


# ===========================================================================
# ClaudeCodeClient error paths
# ===========================================================================

class TestClaudeCodeClientErrors:
    """ClaudeCodeClient.chat() error handling."""

    def _client(self) -> ClaudeCodeClient:
        return ClaudeCodeClient(model="sonnet", claude_bin="/usr/bin/false")

    # -- Non-zero exit code -------------------------------------------------

    @patch("mallcop.llm.claude_code.subprocess.run")
    def test_nonzero_exit_raises_llm_api_error(self, mock_call: MagicMock) -> None:
        mock_call.return_value = subprocess.CompletedProcess(args=[], returncode=1)
        with pytest.raises(LLMAPIError, match="exited with code 1"):
            self._client().chat(*CHAT_ARGS)

    @patch("mallcop.llm.claude_code.subprocess.run")
    def test_exit_code_2_raises_llm_api_error(self, mock_call: MagicMock) -> None:
        mock_call.return_value = subprocess.CompletedProcess(args=[], returncode=2)
        with pytest.raises(LLMAPIError, match="exited with code 2"):
            self._client().chat(*CHAT_ARGS)

    # -- Timeout ------------------------------------------------------------

    @patch("mallcop.llm.claude_code.subprocess.run")
    def test_timeout_raises_llm_api_error(self, mock_call: MagicMock) -> None:
        mock_call.side_effect = subprocess.TimeoutExpired(cmd="claude", timeout=300)
        with pytest.raises(LLMAPIError, match="timed out"):
            self._client().chat(*CHAT_ARGS)

    # -- Empty output -------------------------------------------------------

    @patch("mallcop.llm.claude_code.subprocess.run")
    def test_empty_output_raises_llm_api_error(self, mock_call: MagicMock) -> None:
        mock_call.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        # subprocess.call writes to a temp file; with rc=0, the file is empty
        with pytest.raises(LLMAPIError, match="empty output"):
            self._client().chat(*CHAT_ARGS)

    # -- Unparseable JSON output (rc=0, non-empty but not JSON) -------------

    @patch("mallcop.llm.claude_code.subprocess.run")
    def test_unparseable_output_returns_empty_response(
        self, mock_call: MagicMock, tmp_path
    ) -> None:
        """When claude CLI returns non-JSON text, _parse_response returns an
        empty LLMResponse (no exception, just empty)."""

        def fake_run(cmd, stdout=None, stderr=None, stdin=None, env=None, timeout=None):
            if stdout is not None:
                stdout.write("not json at all")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stderr=b"")

        mock_call.side_effect = fake_run
        resp = self._client().chat(*CHAT_ARGS)
        assert resp.tool_calls == []
        assert resp.raw_resolution is None

    # -- Malformed JSON (valid JSON, but wrong shape) -----------------------

    @patch("mallcop.llm.claude_code.subprocess.run")
    def test_unknown_action_returns_empty_response(self, mock_call: MagicMock) -> None:
        """JSON with unknown 'action' field yields empty LLMResponse."""
        import json

        def fake_run(cmd, stdout=None, stderr=None, stdin=None, env=None, timeout=None):
            if stdout is not None:
                stdout.write(json.dumps({"action": "unknown", "data": 42}))
            return subprocess.CompletedProcess(args=cmd, returncode=0, stderr=b"")

        mock_call.side_effect = fake_run
        resp = self._client().chat(*CHAT_ARGS)
        assert resp.tool_calls == []
        assert resp.raw_resolution is None

    @patch("mallcop.llm.claude_code.subprocess.run")
    def test_resolution_without_action_wrapper(self, mock_call: MagicMock) -> None:
        """JSON with finding_id + action but no 'action: resolution' wrapper."""
        import json

        def fake_run(cmd, stdout=None, stderr=None, stdin=None, env=None, timeout=None):
            if stdout is not None:
                stdout.write(json.dumps({
                    "finding_id": "f-001",
                    "action": "resolved",
                    "reason": "false positive",
                }))
            return subprocess.CompletedProcess(args=cmd, returncode=0, stderr=b"")

        mock_call.side_effect = fake_run
        resp = self._client().chat(*CHAT_ARGS)
        assert resp.raw_resolution is not None
        assert resp.raw_resolution["finding_id"] == "f-001"

    @patch("mallcop.llm.claude_code.subprocess.run")
    def test_tool_call_response_parsed(self, mock_call: MagicMock) -> None:
        """Verify tool_call action is parsed correctly."""
        import json

        def fake_run(cmd, stdout=None, stderr=None, stdin=None, env=None, timeout=None):
            if stdout is not None:
                stdout.write(json.dumps({
                    "action": "tool_call",
                    "tool_calls": [{"name": "get-events", "arguments": {"limit": 10}}],
                }))
            return subprocess.CompletedProcess(args=cmd, returncode=0, stderr=b"")

        mock_call.side_effect = fake_run
        resp = self._client().chat(*CHAT_ARGS)
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].name == "get-events"
        assert resp.tool_calls[0].arguments == {"limit": 10}
