"""Tests for mallcop chat CLI subcommand (chat.py).

TDD sequence:
1. chat_turn() sends correct payload to ManagedClient with session headers
2. chat_turn() appends user msg + agent response to ConversationStore
3. system prompt includes finding summaries from findings.jsonl
4. context window manager invoked to trim history
5. X-Mallcop-Session and X-Mallcop-Surface headers set on ManagedClient requests
6. token cost footer displayed (e.g. '[1.2 donuts]')
7. max_tokens=2000 enforced on each turn
"""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, call, patch

import pytest

from mallcop.chat import (
    MAX_TOKENS_PER_TURN,
    SURFACE,
    TOKENS_PER_DONUT,
    _burn_rate_footer,
    _build_system_prompt,
    _load_finding_summaries,
    chat_turn as _async_chat_turn,
)


def chat_turn(*args: Any, **kwargs: Any) -> Any:
    """Sync wrapper around async chat_turn for test convenience."""
    return asyncio.run(_async_chat_turn(*args, **kwargs))
from mallcop.conversation import ConversationStore
from mallcop.context_window import ContextWindowManager
from mallcop.llm_types import LLMResponse, ToolCall


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_llm_response(text: str = "Here is your answer.", tokens: int = 100) -> LLMResponse:
    return LLMResponse(
        tool_calls=[],
        resolution=None,
        tokens_used=tokens,
        raw_resolution={"content": text},
        text=text,
    )


def _make_mock_client(response: LLMResponse | None = None) -> MagicMock:
    client = MagicMock()
    client.chat.return_value = response or _make_llm_response()
    return client


def _make_store(tmp_path: Path) -> ConversationStore:
    return ConversationStore(tmp_path / "conversations.jsonl")


def _make_context_manager(store_messages: list | None = None) -> ContextWindowManager:
    """Return a ContextWindowManager that returns a simple context from history."""
    cm = ContextWindowManager()
    return cm


# ---------------------------------------------------------------------------
# Test 1: chat_turn() sends correct payload to ManagedClient
# ---------------------------------------------------------------------------

class TestChatTurnSendsCorrectPayload:
    """chat_turn() sends correct payload to ManagedClient."""

    def test_chat_sends_user_question_in_messages(self, tmp_path: Path) -> None:
        client = _make_mock_client()
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        chat_turn(
            question="What threats do I have?",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        client.chat.assert_called_once()
        _, kwargs = client.chat.call_args
        messages = kwargs.get("messages", client.chat.call_args[0][2] if len(client.chat.call_args[0]) > 2 else [])
        # Last message should be user role with the question
        user_messages = [m for m in messages if m.get("role") == "user"]
        assert any("What threats do I have?" in m.get("content", "") for m in user_messages)

    def test_chat_sends_system_prompt(self, tmp_path: Path) -> None:
        client = _make_mock_client()
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        chat_turn(
            question="Hello",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        _, kwargs = client.chat.call_args
        system_prompt = kwargs.get("system_prompt", client.chat.call_args[0][1] if len(client.chat.call_args[0]) > 1 else "")
        assert "security" in system_prompt.lower()

    def test_chat_uses_detective_model(self, tmp_path: Path) -> None:
        client = _make_mock_client()
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        chat_turn(
            question="Hello",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        args, kwargs = client.chat.call_args
        model = kwargs.get("model", args[0] if args else "")
        assert model == "detective"


# ---------------------------------------------------------------------------
# Test 2: chat_turn() appends user msg + agent response to ConversationStore
# ---------------------------------------------------------------------------

class TestChatTurnStoresMessages:
    """chat_turn() persists user and assistant messages."""

    def test_user_message_stored(self, tmp_path: Path) -> None:
        client = _make_mock_client()
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        chat_turn(
            question="What's my risk?",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        msgs = store.load_session(session_id)
        user_msgs = [m for m in msgs if m.role == "user"]
        assert len(user_msgs) == 1
        assert user_msgs[0].content == "What's my risk?"

    def test_assistant_message_stored(self, tmp_path: Path) -> None:
        response_text = "Your risk level is moderate."
        client = _make_mock_client(_make_llm_response(text=response_text, tokens=200))
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        chat_turn(
            question="What's my risk?",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        msgs = store.load_session(session_id)
        assistant_msgs = [m for m in msgs if m.role == "assistant"]
        assert len(assistant_msgs) == 1
        assert assistant_msgs[0].content == response_text

    def test_both_messages_in_session(self, tmp_path: Path) -> None:
        client = _make_mock_client()
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        chat_turn(
            question="Hello",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        msgs = store.load_session(session_id)
        assert len(msgs) == 2
        roles = [m.role for m in msgs]
        assert "user" in roles
        assert "assistant" in roles

    def test_messages_use_correct_session_id(self, tmp_path: Path) -> None:
        client = _make_mock_client()
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        chat_turn(
            question="Hi",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        msgs = store.load_session(session_id)
        assert all(m.session_id == session_id for m in msgs)

    def test_messages_use_correct_surface(self, tmp_path: Path) -> None:
        client = _make_mock_client()
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        chat_turn(
            question="Hi",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        msgs = store.load_session(session_id)
        assert all(m.surface == "cli" for m in msgs)


# ---------------------------------------------------------------------------
# Test 3: system prompt includes finding summaries from findings.jsonl
# ---------------------------------------------------------------------------

class TestSystemPromptFindingSummaries:
    """System prompt includes finding summaries from findings.jsonl."""

    def test_system_prompt_includes_finding_title(self, tmp_path: Path) -> None:
        findings = [
            {"id": "find-001", "severity": "high", "title": "Overly permissive S3 bucket"},
            {"id": "find-002", "severity": "medium", "title": "Unused IAM credentials"},
        ]
        findings_path = tmp_path / "findings.jsonl"
        findings_path.write_text("\n".join(json.dumps(f) for f in findings) + "\n")

        prompt = _build_system_prompt(tmp_path)

        assert "Overly permissive S3 bucket" in prompt
        assert "Unused IAM credentials" in prompt

    def test_system_prompt_includes_severity(self, tmp_path: Path) -> None:
        findings = [{"id": "f-1", "severity": "critical", "title": "Exposed secrets"}]
        (tmp_path / "findings.jsonl").write_text(json.dumps(findings[0]) + "\n")

        prompt = _build_system_prompt(tmp_path)

        assert "critical" in prompt.lower()

    def test_system_prompt_no_findings_file(self, tmp_path: Path) -> None:
        # No findings.jsonl — should use base prompt without crashing
        prompt = _build_system_prompt(tmp_path)

        assert "security" in prompt.lower()
        assert "Current findings" not in prompt

    def test_load_finding_summaries_returns_empty_for_missing_file(self, tmp_path: Path) -> None:
        summaries = _load_finding_summaries(tmp_path)
        assert summaries == []

    def test_load_finding_summaries_returns_list_of_strings(self, tmp_path: Path) -> None:
        findings = [{"id": "f-1", "severity": "high", "title": "Test finding"}]
        (tmp_path / "findings.jsonl").write_text(json.dumps(findings[0]) + "\n")

        summaries = _load_finding_summaries(tmp_path)

        assert len(summaries) == 1
        assert isinstance(summaries[0], str)
        assert "Test finding" in summaries[0]

    def test_chat_turn_system_prompt_passed_to_client(self, tmp_path: Path) -> None:
        findings = [{"id": "f-1", "severity": "high", "title": "Exposed credentials"}]
        (tmp_path / "findings.jsonl").write_text(json.dumps(findings[0]) + "\n")

        client = _make_mock_client()
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        chat_turn(
            question="Tell me about my findings",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        _, kwargs = client.chat.call_args
        system_prompt = kwargs.get("system_prompt", "")
        assert "Exposed credentials" in system_prompt


# ---------------------------------------------------------------------------
# Test 4: context window manager invoked to trim history
# ---------------------------------------------------------------------------

class TestContextWindowManagerInvoked:
    """ContextWindowManager.build_context() is called to trim history."""

    def test_context_manager_build_context_called(self, tmp_path: Path) -> None:
        client = _make_mock_client()
        store = _make_store(tmp_path)
        cm = MagicMock(spec=ContextWindowManager)
        cm.build_context.return_value = {
            "messages": [{"role": "user", "content": "Hello", "id": "x", "session_id": "s",
                          "surface": "cli", "timestamp": "", "finding_refs": [], "tokens_used": 0}],
            "summary": None,
            "finding_refs": [],
            "total_tokens": 5,
        }
        session_id = str(uuid.uuid4())

        chat_turn(
            question="Hello",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        cm.build_context.assert_called_once()

    def test_context_manager_receives_session_history(self, tmp_path: Path) -> None:
        """build_context() receives the full session history."""
        client = _make_mock_client()
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        # Pre-populate with a prior turn
        store.append(session_id=session_id, surface="cli", role="user", content="Prior question")
        store.append(session_id=session_id, surface="cli", role="assistant", content="Prior answer")

        cm = MagicMock(spec=ContextWindowManager)
        cm.build_context.return_value = {
            "messages": [],
            "summary": None,
            "finding_refs": [],
            "total_tokens": 0,
        }

        chat_turn(
            question="New question",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        cm.build_context.assert_called_once()
        history_arg = cm.build_context.call_args[0][0]
        # Should include the prior 2 messages plus the new user message (3 total)
        assert len(history_arg) == 3

    def test_summary_injected_into_messages_when_present(self, tmp_path: Path) -> None:
        """When context manager returns a summary, it's prepended to messages."""
        client = _make_mock_client()
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())
        cm = MagicMock(spec=ContextWindowManager)
        cm.build_context.return_value = {
            "messages": [{"role": "user", "content": "Current question", "id": "x",
                          "session_id": session_id, "surface": "cli", "timestamp": "",
                          "finding_refs": [], "tokens_used": 0}],
            "summary": "Earlier we discussed S3 bucket exposure.",
            "finding_refs": [],
            "total_tokens": 20,
        }

        chat_turn(
            question="Current question",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        args, kwargs = client.chat.call_args
        messages = kwargs.get("messages", args[2] if len(args) > 2 else [])
        summary_msgs = [m for m in messages if "Earlier we discussed" in m.get("content", "")]
        assert len(summary_msgs) == 1


# ---------------------------------------------------------------------------
# Test 5: X-Mallcop-Session and X-Mallcop-Surface headers set on ManagedClient
# ---------------------------------------------------------------------------

class TestManagedClientHeaders:
    """ManagedClient supports extra_headers for X-Mallcop-Session and X-Mallcop-Surface."""

    def test_managed_client_accepts_extra_headers(self) -> None:
        from mallcop.llm.managed import ManagedClient

        client = ManagedClient(
            endpoint="https://mallcop.app",
            service_token="mallcop-sk-test",
            extra_headers={
                "X-Mallcop-Session": "sess-abc",
                "X-Mallcop-Surface": "cli",
            },
        )

        assert client._extra_headers["X-Mallcop-Session"] == "sess-abc"
        assert client._extra_headers["X-Mallcop-Surface"] == "cli"

    def test_managed_client_sends_extra_headers_in_request(self, tmp_path: Path) -> None:
        from mallcop.llm.managed import ManagedClient
        import requests

        session_id = "test-session-id"
        client = ManagedClient(
            endpoint="https://mallcop.app",
            service_token="mallcop-sk-test",
            use_lanes=True,
            extra_headers={
                "X-Mallcop-Session": session_id,
                "X-Mallcop-Surface": "cli",
            },
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "content": [{"type": "text", "text": "Hello"}],
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }

        with patch("requests.post", return_value=mock_resp) as mock_post:
            client.chat(
                model="detective",
                system_prompt="You are an assistant.",
                messages=[{"role": "user", "content": "Hi"}],
                tools=[],
            )

            called_headers = mock_post.call_args[1]["headers"]
            assert called_headers["X-Mallcop-Session"] == session_id
            assert called_headers["X-Mallcop-Surface"] == "cli"

    def test_surface_constant_is_cli(self) -> None:
        assert SURFACE == "cli"


# ---------------------------------------------------------------------------
# Test 6: token cost footer displayed (e.g. '[1.2 donuts]')
# ---------------------------------------------------------------------------

class TestBurnRateFooter:
    """chat_turn() returns a burn-rate footer like '[1.2 donuts]'."""

    def test_footer_format(self) -> None:
        footer = _burn_rate_footer(1200)
        assert footer == "[1.2 donuts]"

    def test_footer_zero_tokens(self) -> None:
        footer = _burn_rate_footer(0)
        assert footer == "[0.0 donuts]"

    def test_footer_exact_one_donut(self) -> None:
        footer = _burn_rate_footer(TOKENS_PER_DONUT)
        assert footer == "[1.0 donuts]"

    def test_chat_turn_returns_footer(self, tmp_path: Path) -> None:
        client = _make_mock_client(_make_llm_response(tokens=2000))
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        result = chat_turn(
            question="Hi",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        assert "footer" in result
        assert "donuts" in result["footer"]
        assert "[" in result["footer"] and "]" in result["footer"]

    def test_chat_turn_footer_reflects_tokens_used(self, tmp_path: Path) -> None:
        tokens = 1500
        client = _make_mock_client(_make_llm_response(tokens=tokens))
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        result = chat_turn(
            question="Hi",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        expected = f"[{tokens / TOKENS_PER_DONUT:.1f} donuts]"
        assert result["footer"] == expected


# ---------------------------------------------------------------------------
# Test 7: max_tokens=2000 enforced on each turn
# ---------------------------------------------------------------------------

class TestMaxTokensEnforced:
    """chat_turn() sends max_tokens=2000 to ManagedClient.chat()."""

    def test_max_tokens_2000_sent(self, tmp_path: Path) -> None:
        client = _make_mock_client()
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        chat_turn(
            question="Hello",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        args, kwargs = client.chat.call_args
        max_tokens = kwargs.get("max_tokens")
        assert max_tokens == MAX_TOKENS_PER_TURN

    def test_max_tokens_constant_is_2000(self) -> None:
        assert MAX_TOKENS_PER_TURN == 2000

    def test_managed_client_uses_max_tokens_param(self) -> None:
        """ManagedClient.chat() passes max_tokens to request body."""
        from mallcop.llm.managed import ManagedClient

        client = ManagedClient(
            endpoint="https://mallcop.app",
            service_token="mallcop-sk-test",
            use_lanes=True,
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "content": [{"type": "text", "text": "Answer"}],
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }

        with patch("requests.post", return_value=mock_resp) as mock_post:
            client.chat(
                model="detective",
                system_prompt="System",
                messages=[{"role": "user", "content": "Hi"}],
                tools=[],
                max_tokens=2000,
            )

            body = mock_post.call_args[1]["json"]
            assert body["max_tokens"] == 2000


# ---------------------------------------------------------------------------
# Integration: chat command registered in CLI
# ---------------------------------------------------------------------------

class TestChatCommandRegistered:
    """'chat' is a registered click command in the CLI."""

    def test_chat_command_exists(self) -> None:
        from mallcop.cli import cli

        assert "chat" in cli.commands

    def test_chat_command_has_help(self) -> None:
        from mallcop.cli import cli
        from click.testing import CliRunner

        runner = CliRunner()
        result = runner.invoke(cli, ["chat", "--help"])
        assert result.exit_code == 0
        assert "chat" in result.output.lower()
