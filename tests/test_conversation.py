"""Tests for ConversationStore — conversations.jsonl writer/reader with flock."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from mallcop.conversation import ConversationMessage, ConversationStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _store(tmp_path: Path) -> ConversationStore:
    return ConversationStore(tmp_path / "conversations.jsonl")


# ---------------------------------------------------------------------------
# Test 1: append writes valid JSONL with all required fields
# ---------------------------------------------------------------------------

def test_append_writes_valid_jsonl(tmp_path: Path) -> None:
    store = _store(tmp_path)
    msg = store.append(
        session_id="sess_abc",
        surface="cli",
        role="user",
        content="hello",
        finding_refs=["fnd_001"],
        tokens_used=42,
    )
    path = tmp_path / "conversations.jsonl"
    assert path.exists(), "conversations.jsonl should exist after append"
    lines = [l for l in path.read_text().splitlines() if l.strip()]
    assert len(lines) == 1, "exactly one JSONL line"
    data = json.loads(lines[0])
    # All schema fields present
    assert data["id"].startswith("msg_")
    assert data["session_id"] == "sess_abc"
    assert data["surface"] == "cli"
    assert "timestamp" in data and data["timestamp"]
    assert data["role"] == "user"
    assert data["content"] == "hello"
    assert data["finding_refs"] == ["fnd_001"]
    assert data["tokens_used"] == 42
    # Returned message matches written data
    assert msg.id == data["id"]
    assert msg.session_id == "sess_abc"


# ---------------------------------------------------------------------------
# Test 2: load_session filters by session_id
# ---------------------------------------------------------------------------

def test_load_session_filters_by_session_id(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.append(session_id="sess_A", surface="cli", role="user", content="msg A1",
                 timestamp="2024-01-01T10:00:00+00:00")
    store.append(session_id="sess_B", surface="cli", role="user", content="msg B1",
                 timestamp="2024-01-01T10:01:00+00:00")
    store.append(session_id="sess_A", surface="cli", role="agent", content="msg A2",
                 timestamp="2024-01-01T10:02:00+00:00")

    msgs_a = store.load_session("sess_A")
    msgs_b = store.load_session("sess_B")
    msgs_c = store.load_session("sess_MISSING")

    assert len(msgs_a) == 2
    assert all(m.session_id == "sess_A" for m in msgs_a)
    assert len(msgs_b) == 1
    assert msgs_b[0].content == "msg B1"
    assert msgs_c == []


# ---------------------------------------------------------------------------
# Test 3: load_session returns messages in chronological order
# ---------------------------------------------------------------------------

def test_load_session_chronological_order(tmp_path: Path) -> None:
    store = _store(tmp_path)
    # Append out of order
    store.append(session_id="sess_X", surface="cli", role="agent", content="third",
                 timestamp="2024-01-01T12:00:00+00:00")
    store.append(session_id="sess_X", surface="cli", role="user", content="first",
                 timestamp="2024-01-01T10:00:00+00:00")
    store.append(session_id="sess_X", surface="cli", role="user", content="second",
                 timestamp="2024-01-01T11:00:00+00:00")

    msgs = store.load_session("sess_X")
    assert [m.content for m in msgs] == ["first", "second", "third"]


# ---------------------------------------------------------------------------
# Test 4: advisory flock — warn on failure, don't crash
# ---------------------------------------------------------------------------

def test_advisory_flock_warn_on_failure(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    import fcntl
    store = _store(tmp_path)

    # Simulate lock failure by making flock raise OSError
    import mallcop.conversation as conv_mod
    original_flock = fcntl.flock

    def flock_fail(fd: int, op: int) -> None:
        if op == fcntl.LOCK_EX | fcntl.LOCK_NB:
            raise OSError("Resource temporarily unavailable")
        return original_flock(fd, op)

    with patch.object(conv_mod.fcntl, "flock", side_effect=flock_fail):
        import logging
        with caplog.at_level(logging.WARNING, logger="mallcop.conversation"):
            msg = store.append(session_id="sess_lock", surface="cli", role="user", content="despite lock failure")

    # Should have warned
    assert any("advisory lock" in r.message for r in caplog.records), \
        "Expected a warning about advisory lock failure"
    # And the message should still have been written
    msgs = store.load_session("sess_lock")
    assert len(msgs) == 1
    assert msgs[0].content == "despite lock failure"


# ---------------------------------------------------------------------------
# Test 5: empty file returns empty list
# ---------------------------------------------------------------------------

def test_empty_file_returns_empty_list(tmp_path: Path) -> None:
    store = _store(tmp_path)
    # File does not exist yet
    assert store.load_session("sess_any") == []
    # Create empty file
    (tmp_path / "conversations.jsonl").write_text("")
    assert store.load_session("sess_any") == []


# ---------------------------------------------------------------------------
# Test 6: corrupt line is skipped with warning
# ---------------------------------------------------------------------------

def test_corrupt_line_skipped_with_warning(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    store = _store(tmp_path)
    path = tmp_path / "conversations.jsonl"

    # Write one good line, one corrupt line, one good line
    good1 = ConversationMessage(
        id="msg_good1", session_id="sess_y", surface="cli",
        timestamp="2024-01-01T10:00:00+00:00", role="user", content="good1",
    )
    good2 = ConversationMessage(
        id="msg_good2", session_id="sess_y", surface="cli",
        timestamp="2024-01-01T11:00:00+00:00", role="agent", content="good2",
    )
    path.write_text(
        good1.to_json() + "\n"
        + "this is not valid json {{{{" + "\n"
        + good2.to_json() + "\n"
    )

    import logging
    with caplog.at_level(logging.WARNING, logger="mallcop.conversation"):
        msgs = store.load_session("sess_y")

    assert len(msgs) == 2, "corrupt line should be skipped, not stop processing"
    assert msgs[0].content == "good1"
    assert msgs[1].content == "good2"
    assert any("corrupt" in r.message for r in caplog.records), \
        "Expected a warning about the corrupt line"
