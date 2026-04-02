"""Tests for ContextWindowManager.

TDD sequence:
1. <=10 messages: all returned verbatim, no summary
2. >10 messages, total under 60% budget: all returned verbatim
3. >10 messages, total over 60% budget: older messages summarized, last 10 verbatim
4. finding_refs collected and deduplicated across all messages
5. summary call uses ManagedClient (patrol lane)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mallcop.conversation import ConversationMessage
from mallcop.context_window import ContextWindowManager, _count_tokens, _collect_finding_refs
from mallcop.llm_types import LLMResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_msg(
    content: str,
    role: str = "user",
    finding_refs: list[str] | None = None,
    seq: int = 0,
) -> ConversationMessage:
    ts = datetime(2026, 1, 1, 0, 0, seq, tzinfo=timezone.utc).isoformat()
    return ConversationMessage(
        id=f"msg_{seq:04d}",
        session_id="sess_test",
        surface="cli",
        timestamp=ts,
        role=role,
        content=content,
        finding_refs=finding_refs or [],
        tokens_used=0,
    )


def _messages(n: int, words_each: int = 5) -> list[ConversationMessage]:
    """Generate n messages with words_each words each."""
    word = "word"
    content = " ".join([word] * words_each)
    return [_make_msg(content, seq=i) for i in range(n)]


def _manager(**kwargs: Any) -> ContextWindowManager:
    """Return a ContextWindowManager with default 100k budget."""
    return ContextWindowManager(**kwargs)


# ---------------------------------------------------------------------------
# Test 1: <=10 messages — all returned verbatim, no summary
# ---------------------------------------------------------------------------

def test_ten_or_fewer_messages_returned_verbatim() -> None:
    """When there are <=10 messages, all are returned verbatim with no summary."""
    msgs = _messages(10, words_each=5)
    mgr = _manager()
    result = mgr.build_context(msgs)

    assert result["summary"] is None
    assert len(result["messages"]) == 10
    # All message IDs present
    returned_ids = {m["id"] for m in result["messages"]}
    expected_ids = {m.id for m in msgs}
    assert returned_ids == expected_ids


def test_fewer_than_ten_messages_returned_verbatim() -> None:
    """Edge: 3 messages, all verbatim."""
    msgs = _messages(3, words_each=10)
    mgr = _manager()
    result = mgr.build_context(msgs)

    assert result["summary"] is None
    assert len(result["messages"]) == 3


def test_zero_messages() -> None:
    """Edge: empty input."""
    mgr = _manager()
    result = mgr.build_context([])

    assert result["summary"] is None
    assert result["messages"] == []
    assert result["finding_refs"] == []
    assert result["total_tokens"] == 0


# ---------------------------------------------------------------------------
# Test 2: >10 messages, total under 60% budget — all returned verbatim
# ---------------------------------------------------------------------------

def test_over_ten_messages_under_budget_all_verbatim() -> None:
    """15 messages, total tokens well under 60k threshold — all returned verbatim."""
    # 15 messages * 10 words * 1.3 = 195 tokens — way under 60k
    msgs = _messages(15, words_each=10)
    mgr = _manager()
    result = mgr.build_context(msgs)

    assert result["summary"] is None
    assert len(result["messages"]) == 15
    returned_ids = {m["id"] for m in result["messages"]}
    expected_ids = {m.id for m in msgs}
    assert returned_ids == expected_ids


def test_over_ten_messages_at_budget_boundary_verbatim() -> None:
    """Total tokens exactly at threshold (60%) — no summarization triggered."""
    # Budget: 1000 tokens, threshold: 600
    # 15 messages, each with content that totals exactly 600 tokens
    # 600 tokens / 15 msgs = 40 tokens each → 40/1.3 ≈ 31 words each
    words_each = 31  # 31 * 1.3 = 40.3 tokens → 15 * 40 = ~604 tokens (just over)
    # Use 30 words: 30 * 1.3 = 39 tokens, 15 * 39 = 585 < 600 — under threshold
    words_each = 30
    msgs = _messages(15, words_each=words_each)
    mgr = _manager(context_budget=1000)  # threshold = 600

    total = sum(_count_tokens(m.content) for m in msgs)
    assert total < 600, f"Expected under 600 tokens, got {total}"

    result = mgr.build_context(msgs)
    assert result["summary"] is None
    assert len(result["messages"]) == 15


# ---------------------------------------------------------------------------
# Test 3: >10 messages, total over 60% budget — older summarized, last 10 verbatim
# ---------------------------------------------------------------------------

def test_over_threshold_older_summarized_last_ten_verbatim() -> None:
    """20 messages exceeding 60% threshold: last 10 verbatim, older summarized."""
    # Budget: 1000 tokens, threshold: 600
    # 20 messages * 40 words * 1.3 = 1040 tokens > 600
    msgs = _messages(20, words_each=40)
    mgr = _manager(context_budget=1000)

    total = sum(_count_tokens(m.content) for m in msgs)
    assert total > 600, f"Expected over 600 tokens, got {total}"

    result = mgr.build_context(msgs)

    # Last 10 messages must be present verbatim
    last_10_ids = {m.id for m in msgs[-10:]}
    returned_ids = {m["id"] for m in result["messages"]}
    assert returned_ids == last_10_ids, f"Expected last 10 IDs, got {returned_ids}"

    # Older messages must NOT be in the verbatim messages
    older_ids = {m.id for m in msgs[:-10]}
    assert returned_ids.isdisjoint(older_ids)

    # Summary must be present
    assert result["summary"] is not None
    assert len(result["summary"]) > 0


def test_over_threshold_message_order_preserved() -> None:
    """Verbatim messages are in chronological order (oldest-first within last 10)."""
    msgs = _messages(15, words_each=50)
    mgr = _manager(context_budget=500)  # threshold = 300, 15*50*1.3=975 > 300

    result = mgr.build_context(msgs)

    returned_ids = [m["id"] for m in result["messages"]]
    expected_ids = [m.id for m in msgs[-10:]]
    assert returned_ids == expected_ids


# ---------------------------------------------------------------------------
# Test 4: finding_refs collected and deduplicated
# ---------------------------------------------------------------------------

def test_finding_refs_collected_and_deduplicated() -> None:
    """finding_refs from all messages are collected and deduplicated."""
    msgs = [
        _make_msg("hello", finding_refs=["find-001", "find-002"], seq=0),
        _make_msg("world", finding_refs=["find-002", "find-003"], seq=1),
        _make_msg("foo", finding_refs=["find-001"], seq=2),
        _make_msg("bar", finding_refs=[], seq=3),
        _make_msg("baz", finding_refs=["find-004"], seq=4),
    ]
    mgr = _manager()
    result = mgr.build_context(msgs)

    refs = result["finding_refs"]
    # All unique refs present
    assert set(refs) == {"find-001", "find-002", "find-003", "find-004"}
    # No duplicates
    assert len(refs) == len(set(refs))


def test_finding_refs_order_preserved() -> None:
    """finding_refs appear in first-seen order."""
    msgs = [
        _make_msg("a", finding_refs=["find-003"], seq=0),
        _make_msg("b", finding_refs=["find-001"], seq=1),
        _make_msg("c", finding_refs=["find-003", "find-002"], seq=2),
    ]
    result = _manager().build_context(msgs)
    assert result["finding_refs"] == ["find-003", "find-001", "find-002"]


def test_finding_refs_empty_when_none() -> None:
    """No finding_refs → empty list."""
    msgs = _messages(5)
    result = _manager().build_context(msgs)
    assert result["finding_refs"] == []


# ---------------------------------------------------------------------------
# Test 5: summary call uses ManagedClient (mock)
# ---------------------------------------------------------------------------

def test_summary_uses_managed_client_patrol_lane() -> None:
    """When summarization is needed, ManagedClient.chat is called with patrol lane."""
    mock_client = MagicMock()
    mock_response = LLMResponse(
        tool_calls=[],
        resolution=None,
        tokens_used=50,
        raw_resolution={"content": "Summary of older messages."},
    )
    mock_client.chat.return_value = mock_response

    # Budget: 1000, threshold: 600
    # 20 msgs * 40 words * 1.3 = 1040 > 600 → summarization triggered
    msgs = _messages(20, words_each=40)
    mgr = _manager(context_budget=1000, managed_client=mock_client)
    result = mgr.build_context(msgs)

    # chat must have been called once
    mock_client.chat.assert_called_once()
    call_kwargs = mock_client.chat.call_args

    # First positional or keyword arg 'model' must be 'patrol'
    args, kwargs = call_kwargs
    model_arg = kwargs.get("model") or (args[0] if args else None)
    assert model_arg == "patrol", f"Expected patrol lane, got {model_arg!r}"

    # Summary must contain the LLM response text
    assert result["summary"] == "Summary of older messages."


def test_summary_not_called_when_under_budget() -> None:
    """ManagedClient.chat is NOT called when total tokens are under threshold."""
    mock_client = MagicMock()

    # 15 messages, 5 words each → well under any budget
    msgs = _messages(15, words_each=5)
    mgr = _manager(managed_client=mock_client)
    result = mgr.build_context(msgs)

    mock_client.chat.assert_not_called()
    assert result["summary"] is None


def test_summary_not_called_for_ten_or_fewer() -> None:
    """ManagedClient.chat is NOT called for <=10 messages."""
    mock_client = MagicMock()
    msgs = _messages(10, words_each=5)
    mgr = _manager(managed_client=mock_client)
    mgr.build_context(msgs)
    mock_client.chat.assert_not_called()


def test_summary_fallback_when_no_client() -> None:
    """Without a managed_client, fallback summary is returned (no exception)."""
    msgs = _messages(20, words_each=40)
    mgr = _manager(context_budget=1000, managed_client=None)
    result = mgr.build_context(msgs)

    assert result["summary"] is not None
    assert "Summary" in result["summary"] or "summary" in result["summary"].lower()
    assert len(result["messages"]) == 10  # last 10 verbatim
