"""Tests for mallcop chat CLI subcommand (chat.py).

Rewritten for InteractiveRuntime-based chat_turn signature (mallcoppro-edc).

Required test invariants:
1. chat_turn calls interactive_runner.run_turn with messages containing the
   appended user message + at most 4 prior messages (5-msg window total).
2. chat_turn early-returns platform error when interactive_runner is None —
   user message NOT appended to store.
3. LLMAPIError(status_code=402) from run_turn -> _platform_error_response with _MSG_402.
4. LLMAPIError(status_code=503) from run_turn -> _platform_error_response with _MSG_503.
5. Assistant message appended to store with the runtime's text.
6. Donut accumulation correct across multiple chat_turn calls.
7. Budget warning fires when cumulative donuts exceed threshold.
8. session_id passed through to run_turn.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, call

import pytest

from mallcop.chat import (
    MAX_TOKENS_PER_TURN,
    SURFACE,
    TOKENS_PER_DONUT,
    _burn_rate_footer,
    _session_donut_spend,
    chat_turn as _async_chat_turn,
)


def chat_turn(*args: Any, **kwargs: Any) -> Any:
    """Sync wrapper around async chat_turn for test convenience."""
    return asyncio.run(_async_chat_turn(*args, **kwargs))


from mallcop.actors.interactive_runtime import TurnResult
from mallcop.conversation import ConversationStore
from mallcop.llm_types import LLMAPIError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_turn_result(text: str = "Here is your answer.", tokens: int = 100) -> TurnResult:
    return TurnResult(
        text=text,
        tokens_used=tokens,
        iterations=1,
        tool_calls=0,
        tool_call_log=[],
    )


def _make_mock_runner(result: TurnResult | None = None) -> MagicMock:
    runner = MagicMock()
    runner.run_turn.return_value = result or _make_turn_result()
    return runner


def _make_store(tmp_path: Path) -> ConversationStore:
    return ConversationStore(tmp_path / "conversations.jsonl")


# ---------------------------------------------------------------------------
# Invariant 1: run_turn called with correct messages (5-msg window)
# ---------------------------------------------------------------------------

class TestRunTurnMessages:
    """chat_turn calls run_turn with the user message in messages, up to 5 total."""

    def setup_method(self) -> None:
        _session_donut_spend.clear()

    def test_run_turn_called_with_user_message(self, tmp_path: Path) -> None:
        runner = _make_mock_runner()
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        chat_turn(
            question="What threats do I have?",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        runner.run_turn.assert_called_once()
        call_kwargs = runner.run_turn.call_args[1]
        messages = call_kwargs.get("messages", runner.run_turn.call_args[0][0] if runner.run_turn.call_args[0] else [])
        user_msgs = [m for m in messages if m.get("role") == "user"]
        assert any("What threats do I have?" in m.get("content", "") for m in user_msgs)

    def test_5_message_window_includes_recent_history(self, tmp_path: Path) -> None:
        """With 6 prior messages, run_turn gets only the last 5 (4 prior + just-appended user)."""
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        # Pre-populate 6 messages (3 turns)
        for i in range(3):
            store.append(session_id=session_id, surface="cli", role="user", content=f"Prior Q{i}")
            store.append(session_id=session_id, surface="cli", role="assistant", content=f"Prior A{i}")

        runner = _make_mock_runner()
        chat_turn(
            question="New question",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        call_kwargs = runner.run_turn.call_args[1]
        messages = call_kwargs.get("messages", [])
        # Should have at most 5 messages
        assert len(messages) <= 5
        # Last message is the newly appended user message
        assert messages[-1]["role"] == "user"
        assert messages[-1]["content"] == "New question"

    def test_fewer_than_5_messages_all_included(self, tmp_path: Path) -> None:
        """With only 2 prior messages + 1 new, all 3 are passed to run_turn."""
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        store.append(session_id=session_id, surface="cli", role="user", content="Prior Q")
        store.append(session_id=session_id, surface="cli", role="assistant", content="Prior A")

        runner = _make_mock_runner()
        chat_turn(
            question="New question",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        call_kwargs = runner.run_turn.call_args[1]
        messages = call_kwargs.get("messages", [])
        assert len(messages) == 3


# ---------------------------------------------------------------------------
# Invariant 2: None interactive_runner -> platform error, no store append
# ---------------------------------------------------------------------------

class TestNoneRunnerEarlyReturn:
    """interactive_runner=None returns platform error without appending user message."""

    def setup_method(self) -> None:
        _session_donut_spend.clear()

    def test_none_runner_returns_platform_error(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result = chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=None,
            store=store,
            root=tmp_path,
        )

        assert result.get("is_platform_error") is True
        assert "Pro subscription required" in result["response"]

    def test_none_runner_does_not_append_user_message(self, tmp_path: Path) -> None:
        """User message is NOT appended when interactive_runner is None."""
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=None,
            store=store,
            root=tmp_path,
        )

        msgs = store.load_session(session_id)
        user_msgs = [m for m in msgs if m.role == "user"]
        assert len(user_msgs) == 0

    def test_none_runner_appends_assistant_error_message(self, tmp_path: Path) -> None:
        """Platform error message is persisted as assistant message."""
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=None,
            store=store,
            root=tmp_path,
        )

        msgs = store.load_session(session_id)
        assistant_msgs = [m for m in msgs if m.role == "assistant"]
        assert len(assistant_msgs) == 1
        assert "Pro subscription required" in assistant_msgs[0].content


# ---------------------------------------------------------------------------
# Invariant 3 & 4: LLMAPIError 402/503 handling
# ---------------------------------------------------------------------------

class TestLLMAPIErrorHandling:
    """LLMAPIError 402/503 from run_turn returns platform message."""

    def setup_method(self) -> None:
        _session_donut_spend.clear()

    def test_402_returns_platform_message(self, tmp_path: Path) -> None:
        runner = MagicMock()
        runner.run_turn.side_effect = LLMAPIError("Managed inference error 402", status_code=402)
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result = chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        assert "insufficient donut balance" in result["response"]
        assert "I received your message" in result["response"]
        assert result.get("is_platform_error") is True

    def test_503_returns_platform_message(self, tmp_path: Path) -> None:
        runner = MagicMock()
        runner.run_turn.side_effect = LLMAPIError("Managed inference error 503", status_code=503)
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result = chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        assert "inference service unavailable" in result["response"]
        assert "I received your message" in result["response"]
        assert result.get("is_platform_error") is True

    def test_402_does_not_raise(self, tmp_path: Path) -> None:
        runner = MagicMock()
        runner.run_turn.side_effect = LLMAPIError("error", status_code=402)
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result = chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )
        assert result["tokens_used"] == 0

    def test_503_does_not_raise(self, tmp_path: Path) -> None:
        runner = MagicMock()
        runner.run_turn.side_effect = LLMAPIError("error", status_code=503)
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result = chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )
        assert result["tokens_used"] == 0

    def test_other_llmapierror_raises(self, tmp_path: Path) -> None:
        runner = MagicMock()
        runner.run_turn.side_effect = LLMAPIError("error", status_code=500)
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        with pytest.raises(LLMAPIError):
            chat_turn(
                question="Hello",
                session_id=session_id,
                interactive_runner=runner,
                store=store,
                root=tmp_path,
            )


# ---------------------------------------------------------------------------
# Invariant 5: Assistant message appended with runtime's text
# ---------------------------------------------------------------------------

class TestAssistantMessageStored:
    """Assistant message from TurnResult is persisted to store."""

    def setup_method(self) -> None:
        _session_donut_spend.clear()

    def test_assistant_message_stored(self, tmp_path: Path) -> None:
        response_text = "Your risk level is moderate."
        runner = _make_mock_runner(_make_turn_result(text=response_text, tokens=200))
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        chat_turn(
            question="What's my risk?",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        msgs = store.load_session(session_id)
        assistant_msgs = [m for m in msgs if m.role == "assistant"]
        assert len(assistant_msgs) == 1
        assert assistant_msgs[0].content == response_text

    def test_user_and_assistant_messages_stored(self, tmp_path: Path) -> None:
        runner = _make_mock_runner()
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        msgs = store.load_session(session_id)
        assert len(msgs) == 2
        roles = [m.role for m in msgs]
        assert "user" in roles
        assert "assistant" in roles

    def test_messages_use_correct_session_id(self, tmp_path: Path) -> None:
        runner = _make_mock_runner()
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        chat_turn(
            question="Hi",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        msgs = store.load_session(session_id)
        assert all(m.session_id == session_id for m in msgs)

    def test_messages_use_correct_surface(self, tmp_path: Path) -> None:
        runner = _make_mock_runner()
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        chat_turn(
            question="Hi",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        msgs = store.load_session(session_id)
        assert all(m.surface == "cli" for m in msgs)


# ---------------------------------------------------------------------------
# Invariant 6: Donut accumulation across multiple turns
# ---------------------------------------------------------------------------

class TestDonutAccumulation:
    """Donut spend accumulates correctly across multiple chat_turn calls."""

    def setup_method(self) -> None:
        _session_donut_spend.clear()

    def test_single_turn_donut_count(self, tmp_path: Path) -> None:
        tokens = 2000
        runner = _make_mock_runner(_make_turn_result(tokens=tokens))
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        assert _session_donut_spend[session_id] == tokens / TOKENS_PER_DONUT

    def test_accumulates_across_turns(self, tmp_path: Path) -> None:
        tokens_per_turn = 1000
        runner = _make_mock_runner(_make_turn_result(tokens=tokens_per_turn))
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        chat_turn(question="Turn 1", session_id=session_id, interactive_runner=runner, store=store, root=tmp_path)
        chat_turn(question="Turn 2", session_id=session_id, interactive_runner=runner, store=store, root=tmp_path)
        chat_turn(question="Turn 3", session_id=session_id, interactive_runner=runner, store=store, root=tmp_path)

        expected = 3 * tokens_per_turn / TOKENS_PER_DONUT
        assert _session_donut_spend[session_id] == expected

    def test_different_sessions_tracked_independently(self, tmp_path: Path) -> None:
        tokens = 1500
        runner = _make_mock_runner(_make_turn_result(tokens=tokens))
        store = _make_store(tmp_path)
        session_a = str(uuid.uuid4())
        session_b = str(uuid.uuid4())

        chat_turn(question="A", session_id=session_a, interactive_runner=runner, store=store, root=tmp_path)
        chat_turn(question="B", session_id=session_b, interactive_runner=runner, store=store, root=tmp_path)

        assert _session_donut_spend[session_a] == tokens / TOKENS_PER_DONUT
        assert _session_donut_spend[session_b] == tokens / TOKENS_PER_DONUT


# ---------------------------------------------------------------------------
# Invariant 7: Budget warning fires at threshold
# ---------------------------------------------------------------------------

class TestBudgetWarning:
    """Budget warning fires when cumulative donuts exceed threshold."""

    def setup_method(self) -> None:
        _session_donut_spend.clear()

    def test_no_warning_below_threshold(self, tmp_path: Path) -> None:
        tokens = 100  # 0.1 donuts — well below 50
        runner = _make_mock_runner(_make_turn_result(tokens=tokens))
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result = chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        assert "budget_warning" not in result

    def test_warning_fires_at_threshold(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MALLCOP_BUDGET_WARNING_THRESHOLD", "5")
        tokens = 5000  # 5 donuts — exactly at threshold
        runner = _make_mock_runner(_make_turn_result(tokens=tokens))
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result = chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        assert "budget_warning" in result
        assert "5.0 donuts" in result["budget_warning"]

    def test_warning_accumulates_across_turns(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MALLCOP_BUDGET_WARNING_THRESHOLD", "5")
        tokens_per_turn = 3000  # 3 donuts each
        runner = _make_mock_runner(_make_turn_result(tokens=tokens_per_turn))
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result1 = chat_turn(question="Turn 1", session_id=session_id, interactive_runner=runner, store=store, root=tmp_path)
        result2 = chat_turn(question="Turn 2", session_id=session_id, interactive_runner=runner, store=store, root=tmp_path)

        assert "budget_warning" not in result1
        assert "budget_warning" in result2

    def test_warning_does_not_cross_sessions(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MALLCOP_BUDGET_WARNING_THRESHOLD", "5")
        tokens = 4000  # 4 donuts — below threshold alone
        runner = _make_mock_runner(_make_turn_result(tokens=tokens))
        store = _make_store(tmp_path)

        session_a = str(uuid.uuid4())
        session_b = str(uuid.uuid4())

        chat_turn(question="Session A", session_id=session_a, interactive_runner=runner, store=store, root=tmp_path)
        result_b = chat_turn(question="Session B", session_id=session_b, interactive_runner=runner, store=store, root=tmp_path)

        assert "budget_warning" not in result_b


# ---------------------------------------------------------------------------
# Invariant 8: session_id passed through to run_turn
# ---------------------------------------------------------------------------

class TestSessionIdPassthrough:
    """session_id is forwarded to interactive_runner.run_turn."""

    def setup_method(self) -> None:
        _session_donut_spend.clear()

    def test_session_id_passed_to_run_turn(self, tmp_path: Path) -> None:
        runner = _make_mock_runner()
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        call_kwargs = runner.run_turn.call_args[1]
        assert call_kwargs.get("session_id") == session_id


# ---------------------------------------------------------------------------
# Burn-rate footer
# ---------------------------------------------------------------------------

class TestBurnRateFooter:
    """chat_turn() returns a burn-rate footer like '[1.2 donuts]'."""

    def setup_method(self) -> None:
        _session_donut_spend.clear()

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
        runner = _make_mock_runner(_make_turn_result(tokens=2000))
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result = chat_turn(
            question="Hi",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        assert "footer" in result
        assert "donuts" in result["footer"]
        assert "[" in result["footer"] and "]" in result["footer"]

    def test_chat_turn_footer_reflects_tokens_used(self, tmp_path: Path) -> None:
        tokens = 1500
        runner = _make_mock_runner(_make_turn_result(tokens=tokens))
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result = chat_turn(
            question="Hi",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        expected = f"[{tokens / TOKENS_PER_DONUT:.1f} donuts]"
        assert result["footer"] == expected


# ---------------------------------------------------------------------------
# Surface constant
# ---------------------------------------------------------------------------

class TestSurfaceConstant:
    def test_surface_constant_is_cli(self) -> None:
        assert SURFACE == "cli"


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
