"""Tests for chat.py hardening features.

Three protections:
1. Per-session donut budget warning (fires when cumulative spend >= threshold).
2. Findings context cap: _build_system_prompt loads at most 20 most-recent findings.
3. Forge 402/503 error handling: returns platform message, no re-raise.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from click.testing import CliRunner

from mallcop.chat import (
    MAX_FINDINGS_IN_PROMPT,
    TOKENS_PER_DONUT,
    DEFAULT_BUDGET_WARNING_THRESHOLD,
    _build_system_prompt,
    _load_finding_summaries,
    _session_donut_spend,
    chat_turn as _async_chat_turn,
    run_chat_repl,
)


def chat_turn(*args, **kwargs):
    """Sync wrapper around async chat_turn for test convenience."""
    return asyncio.run(_async_chat_turn(*args, **kwargs))
from mallcop.conversation import ConversationStore
from mallcop.context_window import ContextWindowManager
from mallcop.llm_types import LLMAPIError, LLMResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_llm_response(text: str = "Answer.", tokens: int = 100) -> LLMResponse:
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


def _write_findings(tmp_path: Path, count: int, base_ts: str = "2024-01-01T00:00:00Z") -> None:
    """Write *count* findings to findings.jsonl with sequential timestamps."""
    lines = []
    for i in range(count):
        ts = f"2024-01-{(i % 28) + 1:02d}T{(i % 24):02d}:00:00Z"
        lines.append(json.dumps({
            "id": f"find-{i:04d}",
            "severity": "medium",
            "title": f"Finding number {i}",
            "timestamp": ts,
        }))
    (tmp_path / "findings.jsonl").write_text("\n".join(lines) + "\n")


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
        client = _make_mock_client(_make_llm_response(tokens=tokens))
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        result = chat_turn(
            question="Hello",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        assert "budget_warning" not in result

    def test_warning_fires_at_threshold(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """budget_warning is present when cumulative spend reaches threshold."""
        # Set threshold to 5 donuts via env var for this test.
        monkeypatch.setenv("MALLCOP_BUDGET_WARNING_THRESHOLD", "5")
        # Use tokens that put us at exactly 5 donuts (5000 tokens).
        tokens = 5000  # = 5 donuts
        client = _make_mock_client(_make_llm_response(tokens=tokens))
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        result = chat_turn(
            question="Hello",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        assert "budget_warning" in result
        assert "5.0 donuts" in result["budget_warning"]

    def test_warning_accumulates_across_turns(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Cumulative spend accumulates across multiple turns in the same session."""
        monkeypatch.setenv("MALLCOP_BUDGET_WARNING_THRESHOLD", "5")
        # 3 donuts per turn → warning fires on second turn (6 cumulative)
        tokens_per_turn = 3000  # 3 donuts
        client = _make_mock_client(_make_llm_response(tokens=tokens_per_turn))
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        result1 = chat_turn(
            question="Turn 1",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )
        result2 = chat_turn(
            question="Turn 2",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        assert "budget_warning" not in result1
        assert "budget_warning" in result2

    def test_warning_message_contains_cumulative_donuts(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Warning message names the cumulative donut count."""
        monkeypatch.setenv("MALLCOP_BUDGET_WARNING_THRESHOLD", "2")
        tokens = 2500  # 2.5 donuts
        client = _make_mock_client(_make_llm_response(tokens=tokens))
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        result = chat_turn(
            question="Hello",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        assert "budget_warning" in result
        assert "2.5 donuts" in result["budget_warning"]

    def test_warning_does_not_cross_sessions(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Spend from one session does not count toward another session's budget."""
        monkeypatch.setenv("MALLCOP_BUDGET_WARNING_THRESHOLD", "5")
        tokens = 4000  # 4 donuts — below threshold alone
        client = _make_mock_client(_make_llm_response(tokens=tokens))
        store = _make_store(tmp_path)
        cm = ContextWindowManager()

        session_a = str(uuid.uuid4())
        session_b = str(uuid.uuid4())

        # Session A: 4 donuts (below threshold)
        chat_turn(
            question="Session A",
            session_id=session_a,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        # Session B: 4 donuts — should NOT warn (only 4, not 8)
        result_b = chat_turn(
            question="Session B",
            session_id=session_b,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        assert "budget_warning" not in result_b

    def test_default_threshold_is_50(self) -> None:
        assert DEFAULT_BUDGET_WARNING_THRESHOLD == 50


# ---------------------------------------------------------------------------
# Feature 2: Findings context cap (pure function — no external calls)
# ---------------------------------------------------------------------------

class TestFindingsContextCap:
    """_build_system_prompt caps findings at MAX_FINDINGS_IN_PROMPT (20)."""

    def test_max_findings_constant_is_20(self) -> None:
        assert MAX_FINDINGS_IN_PROMPT == 20

    def test_exactly_20_findings_when_50_exist(self, tmp_path: Path) -> None:
        """System prompt contains exactly 20 finding entries when 50 exist."""
        _write_findings(tmp_path, 50)

        prompt = _build_system_prompt(tmp_path)

        # Count occurrences of "find-" ID prefix in prompt.
        finding_count = prompt.count("find-")
        assert finding_count == 20

    def test_fewer_than_20_findings_all_included(self, tmp_path: Path) -> None:
        """When fewer than 20 findings exist, all are included."""
        _write_findings(tmp_path, 5)

        prompt = _build_system_prompt(tmp_path)

        finding_count = prompt.count("find-")
        assert finding_count == 5

    def test_load_finding_summaries_caps_at_20(self, tmp_path: Path) -> None:
        """_load_finding_summaries returns at most 20 entries."""
        _write_findings(tmp_path, 100)

        summaries = _load_finding_summaries(tmp_path)

        assert len(summaries) == 20

    def test_load_finding_summaries_returns_most_recent(self, tmp_path: Path) -> None:
        """With 50 findings, the 20 most-recent by timestamp are returned."""
        # Write 50 findings with timestamps 2024-01-01 through 2024-02-19.
        lines = []
        for i in range(50):
            # Day 1..50 (approximately)
            month = 1 + (i // 28)
            day = (i % 28) + 1
            ts = f"2024-{month:02d}-{day:02d}T00:00:00Z"
            lines.append(json.dumps({
                "id": f"find-{i:04d}",
                "severity": "medium",
                "title": f"Finding {i}",
                "timestamp": ts,
            }))
        (tmp_path / "findings.jsonl").write_text("\n".join(lines) + "\n")

        summaries = _load_finding_summaries(tmp_path)

        # The 20 most recent are findings 30..49 (highest timestamps).
        returned_ids = [s.split(":")[0].strip("[]meduihg ").split("]")[-1].strip() for s in summaries]
        # Simpler check: find-0030..find-0049 should appear, find-0000..find-0029 should not.
        joined = "\n".join(summaries)
        # At least the last 10 findings (most recent) should be present.
        for i in range(40, 50):
            assert f"find-{i:04d}" in joined, f"find-{i:04d} should be in the 20 most recent"
        # Early findings should NOT be present.
        for i in range(0, 10):
            assert f"find-{i:04d}" not in joined, f"find-{i:04d} should be excluded (too old)"

    def test_zero_findings_returns_base_prompt(self, tmp_path: Path) -> None:
        """No findings.jsonl returns the base system prompt."""
        prompt = _build_system_prompt(tmp_path)
        assert "Current findings" not in prompt
        assert "security" in prompt.lower()


# ---------------------------------------------------------------------------
# Feature 3: Forge 402/503 error handling
# ---------------------------------------------------------------------------

class TestForgeErrorHandling:
    """Forge 402/503 produce platform messages without re-raising."""

    def setup_method(self) -> None:
        _session_donut_spend.clear()

    def test_402_returns_platform_message(self, tmp_path: Path) -> None:
        """402 from Forge → 'insufficient donut balance' message."""
        client = MagicMock()
        client.chat.side_effect = LLMAPIError("Managed inference error 402", status_code=402)
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        result = chat_turn(
            question="Hello",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        assert "insufficient donut balance" in result["response"]
        assert "I received your message" in result["response"]
        assert "Your message is saved" in result["response"]

    def test_503_returns_platform_message(self, tmp_path: Path) -> None:
        """503 from Forge → 'inference service unavailable' message."""
        client = MagicMock()
        client.chat.side_effect = LLMAPIError("Managed inference error 503", status_code=503)
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        result = chat_turn(
            question="Hello",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        assert "inference service unavailable" in result["response"]
        assert "I received your message" in result["response"]
        assert "Your message is saved" in result["response"]

    def test_402_does_not_raise(self, tmp_path: Path) -> None:
        """402 error does not propagate — chat_turn returns normally."""
        client = MagicMock()
        client.chat.side_effect = LLMAPIError("error", status_code=402)
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        # Should not raise.
        result = chat_turn(
            question="Hello",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )
        assert result["tokens_used"] == 0

    def test_503_does_not_raise(self, tmp_path: Path) -> None:
        """503 error does not propagate — chat_turn returns normally."""
        client = MagicMock()
        client.chat.side_effect = LLMAPIError("error", status_code=503)
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        result = chat_turn(
            question="Hello",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )
        assert result["tokens_used"] == 0

    def test_402_message_saved_to_store(self, tmp_path: Path) -> None:
        """Platform message is persisted to conversation store on 402."""
        client = MagicMock()
        client.chat.side_effect = LLMAPIError("error", status_code=402)
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
        assistant_msgs = [m for m in msgs if m.role == "assistant"]
        assert len(assistant_msgs) == 1
        assert "insufficient donut balance" in assistant_msgs[0].content

    def test_other_errors_still_raise(self, tmp_path: Path) -> None:
        """Non-402/503 errors propagate normally."""
        client = MagicMock()
        client.chat.side_effect = LLMAPIError("error", status_code=500)
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        with pytest.raises(LLMAPIError):
            chat_turn(
                question="Hello",
                session_id=session_id,
                managed_client=client,
                store=store,
                context_manager=cm,
                root=tmp_path,
            )

    def test_generic_exception_still_raises(self, tmp_path: Path) -> None:
        """Generic exceptions (no status_code) propagate normally."""
        client = MagicMock()
        client.chat.side_effect = RuntimeError("network failure")
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        with pytest.raises(RuntimeError):
            chat_turn(
                question="Hello",
                session_id=session_id,
                managed_client=client,
                store=store,
                context_manager=cm,
                root=tmp_path,
            )

    def test_402_store_append_raises_still_returns_platform_msg(self, tmp_path: Path) -> None:
        """If store.append raises inside the 402 handler, chat_turn still returns the platform message."""
        client = MagicMock()
        client.chat.side_effect = LLMAPIError("error", status_code=402)
        store = MagicMock()
        # First call (user message) succeeds; second call (platform message) raises.
        store.append.side_effect = [None, IOError("disk full")]
        store.load_session.return_value = []
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        # Must not raise — store failure is swallowed.
        result = chat_turn(
            question="Hello",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        assert "insufficient donut balance" in result["response"]
        assert result["tokens_used"] == 0

    def test_503_store_append_raises_still_returns_platform_msg(self, tmp_path: Path) -> None:
        """If store.append raises inside the 503 handler, chat_turn still returns the platform message."""
        client = MagicMock()
        client.chat.side_effect = LLMAPIError("error", status_code=503)
        store = MagicMock()
        store.append.side_effect = [None, IOError("disk full")]
        store.load_session.return_value = []
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        result = chat_turn(
            question="Hello",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        assert "inference service unavailable" in result["response"]
        assert result["tokens_used"] == 0


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
        # Any token count: if threshold were truly 0, cumulative_donuts >= 0 is always True.
        tokens = 100  # 0.1 donuts — well below the default 50
        client = _make_mock_client(_make_llm_response(tokens=tokens))
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        result = chat_turn(
            question="Hello",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
            root=tmp_path,
        )

        assert "budget_warning" not in result

    def test_negative_threshold_does_not_fire_on_first_turn(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Negative MALLCOP_BUDGET_WARNING_THRESHOLD falls back to default — no spurious warning."""
        monkeypatch.setenv("MALLCOP_BUDGET_WARNING_THRESHOLD", "-10")
        tokens = 100
        client = _make_mock_client(_make_llm_response(tokens=tokens))
        store = _make_store(tmp_path)
        cm = ContextWindowManager()
        session_id = str(uuid.uuid4())

        result = chat_turn(
            question="Hello",
            session_id=session_id,
            managed_client=client,
            store=store,
            context_manager=cm,
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

        client = MagicMock()

        @_click.command()
        def _repl_cmd():
            run_chat_repl(managed_client=client, root=tmp_path)

        with patch("mallcop.chat.chat_turn", return_value=mock_result):
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

        client = MagicMock()

        @_click.command()
        def _repl_cmd():
            run_chat_repl(managed_client=client, root=tmp_path)

        with patch("mallcop.chat.chat_turn", return_value=mock_result):
            runner = CliRunner()
            result = runner.invoke(_repl_cmd, input="Hello\nexit\n", catch_exceptions=False)

        assert "[budget]" not in result.output
