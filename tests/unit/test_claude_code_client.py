"""Tests for ClaudeCodeClient LLM backend."""

import json
import subprocess
from unittest.mock import patch, MagicMock

import pytest

from mallcop.llm import ClaudeCodeClient, LLMAPIError, build_llm_client
from mallcop.actors.runtime import ToolCall


class TestClaudeCodeClientParseResponse:
    """Test _parse_response with various claude CLI outputs."""

    def setup_method(self):
        self.client = ClaudeCodeClient(model="sonnet")

    def test_tool_call_response(self):
        text = json.dumps({
            "action": "tool_call",
            "tool_calls": [{"name": "check-baseline", "arguments": {"actor": "foo"}}],
        })
        resp = self.client._parse_response(text)
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].name == "check-baseline"
        assert resp.tool_calls[0].arguments == {"actor": "foo"}
        assert resp.raw_resolution is None

    def test_resolution_response(self):
        text = json.dumps({
            "action": "resolution",
            "finding_id": "fnd_abc",
            "action": "ack",
            "reason": "Known actor",
        })
        resp = self.client._parse_response(text)
        assert resp.tool_calls == []
        assert resp.raw_resolution is not None
        assert resp.raw_resolution["finding_id"] == "fnd_abc"

    def test_bare_resolution(self):
        text = json.dumps({
            "finding_id": "fnd_abc",
            "action": "ack",
            "reason": "Known actor",
        })
        resp = self.client._parse_response(text)
        assert resp.raw_resolution is not None
        assert resp.raw_resolution["action"] == "ack"

    def test_json_embedded_in_text(self):
        text = 'Here is my response:\n{"action": "tool_call", "tool_calls": [{"name": "list-events", "arguments": {}}]}\n'
        resp = self.client._parse_response(text)
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].name == "list-events"

    def test_unparseable_text(self):
        resp = self.client._parse_response("I don't know what to do")
        assert resp.tool_calls == []
        assert resp.raw_resolution is None

    def test_multiple_tool_calls(self):
        text = json.dumps({
            "action": "tool_call",
            "tool_calls": [
                {"name": "list-events", "arguments": {"hours": 24}},
                {"name": "check-baseline", "arguments": {"actor": "x"}},
            ],
        })
        resp = self.client._parse_response(text)
        assert len(resp.tool_calls) == 2
        assert resp.tool_calls[0].name == "list-events"
        assert resp.tool_calls[1].name == "check-baseline"

    def test_nested_braces_in_arguments(self):
        """Tool call with newlines and braces in argument text."""
        text = json.dumps({
            "action": "tool_call",
            "tool_calls": [{
                "name": "annotate-finding",
                "arguments": {
                    "finding_id": "fnd_56876bf5",
                    "text": "INVESTIGATION SUMMARY\n\nWhat was found:\n- Actor {unknown} performed actions\n- Baseline check: {\"known\": false}\n- Conclusion: escalate"
                }
            }],
        })
        resp = self.client._parse_response(text)
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].name == "annotate-finding"
        assert "INVESTIGATION SUMMARY" in resp.tool_calls[0].arguments["text"]

    def test_json_with_surrounding_markdown(self):
        """Claude sometimes wraps JSON in markdown code blocks."""
        text = 'Here is my analysis:\n\n```json\n{"action": "tool_call", "tool_calls": [{"name": "check-baseline", "arguments": {"actor": "foo"}}]}\n```\n'
        resp = self.client._parse_response(text)
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].name == "check-baseline"

    def test_tokens_always_zero(self):
        text = json.dumps({"finding_id": "f1", "action": "ack", "reason": "ok"})
        resp = self.client._parse_response(text)
        assert resp.tokens_used == 0


def _mock_call(stdout_text, returncode=0):
    """Set up mocks for subprocess.call + temp file reading."""
    def _side_effect(cmd, **kwargs):
        # Write stdout_text to the file that was opened for stdout
        stdout_file = kwargs.get("stdout")
        if stdout_file and hasattr(stdout_file, "write"):
            stdout_file.write(stdout_text)
        return returncode
    return _side_effect


def _mock_run(stdout_text, returncode=0):
    """Set up mocks for subprocess.run + temp file reading."""
    def _side_effect(cmd, **kwargs):
        stdout_file = kwargs.get("stdout")
        if stdout_file and hasattr(stdout_file, "write"):
            stdout_file.write(stdout_text)
        return MagicMock(returncode=returncode)
    return _side_effect


class TestClaudeCodeClientChat:
    """Test chat() subprocess invocation."""

    def test_successful_invocation(self):
        client = ClaudeCodeClient(model="sonnet")
        response_json = json.dumps({
            "finding_id": "fnd_123",
            "action": "resolved",
            "reason": "Known actor",
        })

        with patch("mallcop.llm.claude_code.subprocess.run", side_effect=_mock_run(response_json)) as mock_call:
            resp = client.chat(
                model="sonnet",
                system_prompt="You are a triage agent.",
                messages=[{"role": "user", "content": "Investigate this."}],
                tools=[{"name": "list-events", "description": "List events", "parameters": {}}],
            )

        assert resp.raw_resolution is not None
        assert resp.raw_resolution["action"] == "resolved"
        # Verify subprocess was called with correct args
        call_args = mock_call.call_args
        cmd = call_args[0][0]
        # When systemd-run is available, command is wrapped:
        # ["systemd-run", "--user", "--scope", "--quiet", "--", "claude", ...]
        if cmd[0] == "systemd-run":
            assert cmd[1:5] == ["--user", "--scope", "--quiet", "--"]
            claude_cmd = cmd[5:]
        else:
            claude_cmd = cmd
        assert claude_cmd[0] == client._claude_bin
        assert "-p" in claude_cmd
        assert "--model" in claude_cmd
        # Verify env uses whitelist (CLAUDECODE excluded)
        env = call_args[1]["env"]
        assert "CLAUDECODE" not in env

    def test_nonzero_exit_raises(self):
        client = ClaudeCodeClient()

        with patch("mallcop.llm.claude_code.subprocess.run", side_effect=_mock_run("", returncode=1)):
            with pytest.raises(LLMAPIError, match="exited with code 1"):
                client.chat("sonnet", "sys", [{"role": "user", "content": "hi"}], [])

    def test_timeout_raises(self):
        client = ClaudeCodeClient()

        with patch("mallcop.llm.claude_code.subprocess.run", side_effect=subprocess.TimeoutExpired("claude", 300)):
            with pytest.raises(LLMAPIError, match="timed out"):
                client.chat("sonnet", "sys", [{"role": "user", "content": "hi"}], [])

    def test_empty_output_raises(self):
        client = ClaudeCodeClient()

        with patch("mallcop.llm.claude_code.subprocess.run", side_effect=_mock_run("")):
            with pytest.raises(LLMAPIError, match="empty output"):
                client.chat("sonnet", "sys", [{"role": "user", "content": "hi"}], [])

    def test_system_prompt_passed_as_append(self):
        client = ClaudeCodeClient()
        response_json = '{"finding_id": "f1", "action": "resolved", "reason": "ok"}'

        with patch("mallcop.llm.claude_code.subprocess.run", side_effect=_mock_run(response_json)) as mock_call:
            client.chat("sonnet", "You are a security analyst.", [{"role": "user", "content": "hi"}], [])

        cmd = mock_call.call_args[0][0]
        assert "--append-system-prompt" in cmd
        idx = cmd.index("--append-system-prompt")
        assert cmd[idx + 1] == "You are a security analyst."


class TestClaudeCodeEnvWhitelist:
    """Verify env filtering uses a whitelist, not a blacklist."""

    def _get_env_from_chat(self, fake_env):
        """Run chat() with a mocked environment and return the env dict passed to subprocess."""
        client = ClaudeCodeClient(model="sonnet")
        response_json = json.dumps({
            "finding_id": "f1", "action": "resolved", "reason": "ok",
        })

        with patch.dict("os.environ", fake_env, clear=True), \
             patch("mallcop.llm.claude_code.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            # We need the file write to work, so also patch the temp file read
            with patch("builtins.open", create=True):
                pass
            # Simpler: just catch the call args before file handling
            mock_run.side_effect = _mock_run(response_json)
            client.chat("sonnet", "sys", [{"role": "user", "content": "hi"}], [])
            return mock_run.call_args[1]["env"]

    def test_whitelisted_vars_passed(self):
        """Whitelisted env vars are forwarded to subprocess."""
        fake_env = {
            "PATH": "/usr/bin",
            "HOME": "/home/test",
            "ANTHROPIC_API_KEY": "sk-ant-test",
            "AZURE_CLIENT_ID": "abc",
            "AWS_ACCESS_KEY_ID": "AKIA123",
            "GITHUB_TOKEN": "ghp_xxx",
            "VERCEL_TOKEN": "vt_xxx",
            "OPENAI_API_KEY": "sk-xxx",
        }
        env = self._get_env_from_chat(fake_env)
        for key in fake_env:
            assert key in env, f"Whitelisted var {key} missing from env"
            assert env[key] == fake_env[key]

    def test_dangerous_vars_excluded(self):
        """Dangerous env vars like PYTHONPATH, LD_PRELOAD, LD_LIBRARY_PATH are excluded."""
        fake_env = {
            "PATH": "/usr/bin",
            "HOME": "/home/test",
            "PYTHONPATH": "/evil/path",
            "LD_PRELOAD": "/evil/lib.so",
            "LD_LIBRARY_PATH": "/evil/libs",
            "CLAUDECODE": "1",
            "CLAUDE_CODE_ENTRYPOINT": "/bad",
            "HTTP_PROXY": "http://evil:8080",
            "NODE_OPTIONS": "--evil",
        }
        env = self._get_env_from_chat(fake_env)
        for dangerous in ("PYTHONPATH", "LD_PRELOAD", "LD_LIBRARY_PATH",
                          "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT",
                          "HTTP_PROXY", "NODE_OPTIONS"):
            assert dangerous not in env, f"Dangerous var {dangerous} should be excluded"

    def test_only_whitelisted_vars_present(self):
        """Only vars on the whitelist appear in the env — nothing else leaks through."""
        fake_env = {
            "PATH": "/usr/bin",
            "HOME": "/home/test",
            "ANTHROPIC_API_KEY": "sk-ant-test",
            "RANDOM_VAR": "should_not_appear",
            "SECRET_STUFF": "nope",
        }
        env = self._get_env_from_chat(fake_env)
        assert "RANDOM_VAR" not in env
        assert "SECRET_STUFF" not in env
        assert "PATH" in env
        assert "ANTHROPIC_API_KEY" in env


class TestClaudeCodeUsesSubprocessRun:
    """Verify subprocess.run is used instead of subprocess.call."""

    def test_uses_subprocess_run(self):
        """chat() must use subprocess.run, not subprocess.call."""
        client = ClaudeCodeClient(model="sonnet")
        response_json = json.dumps({
            "finding_id": "f1", "action": "resolved", "reason": "ok",
        })

        with patch("mallcop.llm.claude_code.subprocess.run") as mock_run:
            mock_run.side_effect = _mock_run(response_json)
            client.chat("sonnet", "sys", [{"role": "user", "content": "hi"}], [])
            mock_run.assert_called_once()

    def test_subprocess_call_not_used(self):
        """subprocess.call must not be referenced in the module."""
        import mallcop.llm.claude_code as mod
        import inspect
        source = inspect.getsource(mod)
        assert "subprocess.call(" not in source, "subprocess.call should be replaced with subprocess.run"


class TestBuildLlmClientBackend:
    """Test build_llm_client with backend parameter."""

    def test_claude_code_backend_no_config(self):
        client = build_llm_client(None, backend="claude-code")
        assert isinstance(client, ClaudeCodeClient)

    def test_claude_code_backend_with_config(self):
        from mallcop.config import LLMConfig
        config = LLMConfig(provider="anthropic", api_key="fake", default_model="opus")
        client = build_llm_client(config, backend="claude-code")
        assert isinstance(client, ClaudeCodeClient)
        assert client._model == "opus"

    def test_anthropic_backend_default(self):
        from mallcop.config import LLMConfig
        from mallcop.llm import AnthropicClient
        config = LLMConfig(provider="anthropic", api_key="fake", default_model="haiku")
        client = build_llm_client(config, backend="anthropic")
        assert isinstance(client, AnthropicClient)

    def test_anthropic_backend_no_config_returns_none(self):
        client = build_llm_client(None, backend="anthropic")
        assert client is None
