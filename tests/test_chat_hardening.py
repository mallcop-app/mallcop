"""Tests for chat.py hardening features.

Updated for InteractiveRuntime-based chat_turn (mallcoppro-edc).

Two remaining protections tested here (third — findings context cap — moved
to InteractiveRuntime's system prompt, not chat_turn's concern):
1. Per-session donut budget warning (fires when cumulative spend >= threshold).
2. Forge 402/503 error handling: returns platform message, no re-raise.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from click.testing import CliRunner

from mallcop.chat import (
    TOKENS_PER_DONUT,
    DEFAULT_BUDGET_WARNING_THRESHOLD,
    _session_donut_spend,
    chat_turn as _async_chat_turn,
    run_chat_repl,
)


def chat_turn(*args, **kwargs):
    """Sync wrapper around async chat_turn for test convenience."""
    return asyncio.run(_async_chat_turn(*args, **kwargs))


from mallcop.actors.interactive_runtime import TurnResult
from mallcop.conversation import ConversationStore
from mallcop.llm_types import LLMAPIError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_turn_result(text: str = "Answer.", tokens: int = 100) -> TurnResult:
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


def _run_chat_turn(**kwargs: Any) -> dict:
    """Run chat_turn synchronously for use in sync test methods."""
    return chat_turn(**kwargs)


# ---------------------------------------------------------------------------
# Feature 1: Per-session donut budget warning
# ---------------------------------------------------------------------------

class TestBudgetWarning:
    """Budget warning fires when cumulative session spend >= threshold."""

    def setup_method(self) -> None:
        # Clear session spend tracker between tests.
        _session_donut_spend.clear()

    def test_no_warning_below_threshold(self, tmp_path: Path) -> None:
        """No budget_warning key in result when spend is below threshold."""
        # threshold=50, tokens_per_donut=1000 → need <50000 tokens
        tokens = 100  # 0.1 donuts — well below 50
        runner = _make_mock_runner(_make_turn_result(tokens=tokens))
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result = _run_chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        assert "budget_warning" not in result

    def test_warning_fires_at_threshold(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """budget_warning is present when cumulative spend reaches threshold."""
        # Set threshold to 5 donuts via env var for this test.
        monkeypatch.setenv("MALLCOP_BUDGET_WARNING_THRESHOLD", "5")
        # Use tokens that put us at exactly 5 donuts (5000 tokens).
        tokens = 5000  # = 5 donuts
        runner = _make_mock_runner(_make_turn_result(tokens=tokens))
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result = _run_chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        assert "budget_warning" in result
        assert "5.0 donuts" in result["budget_warning"]

    def test_warning_accumulates_across_turns(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Cumulative spend accumulates across multiple turns in the same session."""
        monkeypatch.setenv("MALLCOP_BUDGET_WARNING_THRESHOLD", "5")
        # 3 donuts per turn → warning fires on second turn (6 cumulative)
        tokens_per_turn = 3000  # 3 donuts
        runner = _make_mock_runner(_make_turn_result(tokens=tokens_per_turn))
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result1 = _run_chat_turn(
            question="Turn 1",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )
        result2 = _run_chat_turn(
            question="Turn 2",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        assert "budget_warning" not in result1
        assert "budget_warning" in result2

    def test_warning_message_contains_cumulative_donuts(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Warning message names the cumulative donut count."""
        monkeypatch.setenv("MALLCOP_BUDGET_WARNING_THRESHOLD", "2")
        tokens = 2500  # 2.5 donuts
        runner = _make_mock_runner(_make_turn_result(tokens=tokens))
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result = _run_chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        assert "budget_warning" in result
        assert "2.5 donuts" in result["budget_warning"]

    def test_warning_does_not_cross_sessions(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Spend from one session does not count toward another session's budget."""
        monkeypatch.setenv("MALLCOP_BUDGET_WARNING_THRESHOLD", "5")
        tokens = 4000  # 4 donuts — below threshold alone
        runner = _make_mock_runner(_make_turn_result(tokens=tokens))
        store = _make_store(tmp_path)

        session_a = str(uuid.uuid4())
        session_b = str(uuid.uuid4())

        # Session A: 4 donuts (below threshold)
        _run_chat_turn(
            question="Session A",
            session_id=session_a,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        # Session B: 4 donuts — should NOT warn (only 4, not 8)
        result_b = _run_chat_turn(
            question="Session B",
            session_id=session_b,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        assert "budget_warning" not in result_b

    def test_default_threshold_is_50(self) -> None:
        assert DEFAULT_BUDGET_WARNING_THRESHOLD == 50


# ---------------------------------------------------------------------------
# Feature 2: Forge 402/503 error handling
# ---------------------------------------------------------------------------

class TestForgeErrorHandling:
    """Forge 402/503 produce platform messages without re-raising."""

    def setup_method(self) -> None:
        _session_donut_spend.clear()

    def test_402_returns_platform_message(self, tmp_path: Path) -> None:
        """402 from run_turn → 'insufficient donut balance' message."""
        runner = MagicMock()
        runner.run_turn.side_effect = LLMAPIError("Managed inference error 402", status_code=402)
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result = _run_chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        assert "insufficient donut balance" in result["response"]
        assert "I received your message" in result["response"]
        assert "Your message is saved" in result["response"]

    def test_503_returns_platform_message(self, tmp_path: Path) -> None:
        """503 from run_turn → 'inference service unavailable' message."""
        runner = MagicMock()
        runner.run_turn.side_effect = LLMAPIError("Managed inference error 503", status_code=503)
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result = _run_chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        assert "inference service unavailable" in result["response"]
        assert "I received your message" in result["response"]
        assert "Your message is saved" in result["response"]

    def test_402_does_not_raise(self, tmp_path: Path) -> None:
        """402 error does not propagate — chat_turn returns normally."""
        runner = MagicMock()
        runner.run_turn.side_effect = LLMAPIError("error", status_code=402)
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        # Should not raise.
        result = _run_chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )
        assert result["tokens_used"] == 0

    def test_503_does_not_raise(self, tmp_path: Path) -> None:
        """503 error does not propagate — chat_turn returns normally."""
        runner = MagicMock()
        runner.run_turn.side_effect = LLMAPIError("error", status_code=503)
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result = _run_chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )
        assert result["tokens_used"] == 0

    def test_402_message_saved_to_store(self, tmp_path: Path) -> None:
        """Platform message is persisted to conversation store on 402."""
        runner = MagicMock()
        runner.run_turn.side_effect = LLMAPIError("error", status_code=402)
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        _run_chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        msgs = store.load_session(session_id)
        assistant_msgs = [m for m in msgs if m.role == "assistant"]
        assert len(assistant_msgs) == 1
        assert "insufficient donut balance" in assistant_msgs[0].content

    def test_other_errors_still_raise(self, tmp_path: Path) -> None:
        """Non-402/503 errors propagate normally."""
        runner = MagicMock()
        runner.run_turn.side_effect = LLMAPIError("error", status_code=500)
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        with pytest.raises(LLMAPIError):
            _run_chat_turn(
                question="Hello",
                session_id=session_id,
                interactive_runner=runner,
                store=store,
                root=tmp_path,
            )

    def test_generic_exception_still_raises(self, tmp_path: Path) -> None:
        """Generic exceptions (no status_code) propagate normally."""
        runner = MagicMock()
        runner.run_turn.side_effect = RuntimeError("network failure")
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        with pytest.raises(RuntimeError):
            _run_chat_turn(
                question="Hello",
                session_id=session_id,
                interactive_runner=runner,
                store=store,
                root=tmp_path,
            )

    def test_402_store_append_raises_still_returns_platform_msg(self, tmp_path: Path) -> None:
        """If store.append raises inside the 402 handler, chat_turn still returns the platform message."""
        runner = MagicMock()
        runner.run_turn.side_effect = LLMAPIError("error", status_code=402)
        store = MagicMock()
        # First call (user message) succeeds; second call (platform message) raises.
        store.append.side_effect = [None, IOError("disk full")]
        store.load_session.return_value = []
        session_id = str(uuid.uuid4())

        # Must not raise — store failure is swallowed.
        result = _run_chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        assert "insufficient donut balance" in result["response"]
        assert result["tokens_used"] == 0

    def test_503_store_append_raises_still_returns_platform_msg(self, tmp_path: Path) -> None:
        """If store.append raises inside the 503 handler, chat_turn still returns the platform message."""
        runner = MagicMock()
        runner.run_turn.side_effect = LLMAPIError("error", status_code=503)
        store = MagicMock()
        store.append.side_effect = [None, IOError("disk full")]
        store.load_session.return_value = []
        session_id = str(uuid.uuid4())

        result = _run_chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        assert "inference service unavailable" in result["response"]
        assert result["tokens_used"] == 0

    def test_402_returns_is_platform_error_true(self, tmp_path: Path) -> None:
        """402 from run_turn sets is_platform_error=True in the result dict."""
        runner = MagicMock()
        runner.run_turn.side_effect = LLMAPIError("error", status_code=402)
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result = _run_chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        assert result.get("is_platform_error") is True

    def test_503_returns_is_platform_error_true(self, tmp_path: Path) -> None:
        """503 from run_turn sets is_platform_error=True in the result dict."""
        runner = MagicMock()
        runner.run_turn.side_effect = LLMAPIError("error", status_code=503)
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result = _run_chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        assert result.get("is_platform_error") is True

    def test_success_does_not_set_is_platform_error(self, tmp_path: Path) -> None:
        """Successful turn does not set is_platform_error."""
        runner = _make_mock_runner()
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result = _run_chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        assert not result.get("is_platform_error")


# ---------------------------------------------------------------------------
# Bug fix: invalid MALLCOP_BUDGET_WARNING_THRESHOLD (mallcop-pro-tz5)
# ---------------------------------------------------------------------------

class TestBudgetThresholdValidation:
    """MALLCOP_BUDGET_WARNING_THRESHOLD <= 0 falls back to the default."""

    def setup_method(self) -> None:
        _session_donut_spend.clear()

    def test_threshold_zero_does_not_fire_on_first_turn(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With MALLCOP_BUDGET_WARNING_THRESHOLD=0, warning does NOT fire on first turn."""
        monkeypatch.setenv("MALLCOP_BUDGET_WARNING_THRESHOLD", "0")
        tokens = 100  # 0.1 donuts — well below the default 50
        runner = _make_mock_runner(_make_turn_result(tokens=tokens))
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result = _run_chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        assert "budget_warning" not in result

    def test_negative_threshold_does_not_fire_on_first_turn(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Negative MALLCOP_BUDGET_WARNING_THRESHOLD falls back to default — no spurious warning."""
        monkeypatch.setenv("MALLCOP_BUDGET_WARNING_THRESHOLD", "-10")
        tokens = 100
        runner = _make_mock_runner(_make_turn_result(tokens=tokens))
        store = _make_store(tmp_path)
        session_id = str(uuid.uuid4())

        result = _run_chat_turn(
            question="Hello",
            session_id=session_id,
            interactive_runner=runner,
            store=store,
            root=tmp_path,
        )

        assert "budget_warning" not in result


# ---------------------------------------------------------------------------
# Bug fix: budget_warning displayed in REPL (mallcop-pro-hic)
# ---------------------------------------------------------------------------

class TestReplBudgetWarningDisplay:
    """run_chat_repl prints budget_warning to stdout when chat_turn returns one."""

    def setup_method(self) -> None:
        _session_donut_spend.clear()

    def test_repl_shows_budget_warning(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """When chat_turn returns a budget_warning, run_chat_repl prints [budget] line."""
        import click as _click
        from unittest.mock import patch

        warning_msg = "You have spent 5.0 donuts this session."
        mock_result = {
            "response": "Here is the answer.",
            "footer": "tokens: 5000 | donuts: 5.0",
            "budget_warning": warning_msg,
            "tokens_used": 5000,
        }

        interactive_runner = MagicMock()

        @_click.command()
        def _repl_cmd():
            run_chat_repl(interactive_runner=interactive_runner, root=tmp_path)

        with patch("mallcop.chat.chat_turn", new=AsyncMock(return_value=mock_result)):
            runner = CliRunner()
            result = runner.invoke(_repl_cmd, input="What is 2+2?\nexit\n", catch_exceptions=False)

        assert "[budget]" in result.output
        assert warning_msg in result.output

    def test_repl_no_budget_line_without_warning(self, tmp_path: Path) -> None:
        """When chat_turn returns no budget_warning, run_chat_repl does not print [budget]."""
        import click as _click
        from unittest.mock import patch

        mock_result = {
            "response": "Here is the answer.",
            "footer": "tokens: 100 | donuts: 0.1",
            "tokens_used": 100,
        }

        interactive_runner = MagicMock()

        @_click.command()
        def _repl_cmd():
            run_chat_repl(interactive_runner=interactive_runner, root=tmp_path)

        with patch("mallcop.chat.chat_turn", new=AsyncMock(return_value=mock_result)):
            runner = CliRunner()
            result = runner.invoke(_repl_cmd, input="Hello\nexit\n", catch_exceptions=False)

        assert "[budget]" not in result.output
