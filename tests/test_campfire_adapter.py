"""Tests for CampfireConversationAdapter — real campfire round-trip.

These tests use a REAL campfire created via `cf create`.  No mocks of cf commands.
The campfire is disbanded after each test to keep the environment clean.
"""

from __future__ import annotations

import subprocess
import uuid
from typing import Generator

import pytest

from mallcop.context_window import ContextWindowManager
from mallcop.conversation import CampfireConversationAdapter, ConversationMessage


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_campfire(description: str) -> str:
    """Create a real campfire and return its ID."""
    result = subprocess.run(
        ["cf", "create", "--description", description],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"cf create failed: {result.stderr}"
    campfire_id = result.stdout.strip()
    assert campfire_id, "cf create returned empty campfire ID"
    return campfire_id


def _disband_campfire(campfire_id: str) -> None:
    """Disband a campfire (best-effort — suppress errors in teardown)."""
    subprocess.run(["cf", "disband", campfire_id], capture_output=True)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def campfire_id() -> Generator[str, None, None]:
    """Create a fresh campfire for the test, then disband it."""
    uid = str(uuid.uuid4())
    cf_id = _create_campfire(f"test-adapter-{uid}")
    yield cf_id
    _disband_campfire(cf_id)


# ---------------------------------------------------------------------------
# Test 1: append and load_session round-trip basic message
# ---------------------------------------------------------------------------

def test_round_trip_single_message(campfire_id: str) -> None:
    adapter = CampfireConversationAdapter(campfire_id)
    session_id = str(uuid.uuid4())

    msg = adapter.append(
        session_id=session_id,
        surface="cli",
        role="user",
        content="Hello from round-trip test",
        finding_refs=[],
        tokens_used=0,
    )

    assert msg.session_id == session_id
    assert msg.role == "user"
    assert msg.content == "Hello from round-trip test"
    assert msg.surface == "cli"

    loaded = adapter.load_session(session_id)
    assert len(loaded) == 1, f"Expected 1 message, got {len(loaded)}"
    m = loaded[0]
    assert m.id == msg.id
    assert m.session_id == session_id
    assert m.surface == "cli"
    assert m.role == "user"
    assert m.content == "Hello from round-trip test"
    assert m.finding_refs == []
    assert m.tokens_used == 0


# ---------------------------------------------------------------------------
# Test 2: user and mallcop (assistant) roles round-trip correctly
# ---------------------------------------------------------------------------

def test_round_trip_user_and_assistant_roles(campfire_id: str) -> None:
    adapter = CampfireConversationAdapter(campfire_id)
    session_id = str(uuid.uuid4())

    adapter.append(session_id=session_id, surface="cli", role="user", content="User question")
    adapter.append(session_id=session_id, surface="cli", role="assistant", content="Mallcop answer")

    loaded = adapter.load_session(session_id)
    assert len(loaded) == 2
    assert loaded[0].role == "user"
    assert loaded[0].content == "User question"
    assert loaded[1].role == "assistant"
    assert loaded[1].content == "Mallcop answer"


# ---------------------------------------------------------------------------
# Test 3: finding_refs round-trip via tags
# ---------------------------------------------------------------------------

def test_round_trip_finding_refs(campfire_id: str) -> None:
    adapter = CampfireConversationAdapter(campfire_id)
    session_id = str(uuid.uuid4())

    adapter.append(
        session_id=session_id,
        surface="slack",
        role="user",
        content="Finding question",
        finding_refs=["MC-001", "MC-042"],
        tokens_used=55,
    )

    loaded = adapter.load_session(session_id)
    assert len(loaded) == 1
    m = loaded[0]
    assert set(m.finding_refs) == {"MC-001", "MC-042"}
    assert m.surface == "slack"
    assert m.tokens_used == 55


# ---------------------------------------------------------------------------
# Test 4: load_session isolates by session_id
# ---------------------------------------------------------------------------

def test_load_session_isolates_by_session(campfire_id: str) -> None:
    adapter = CampfireConversationAdapter(campfire_id)
    sess_a = str(uuid.uuid4())
    sess_b = str(uuid.uuid4())

    adapter.append(session_id=sess_a, surface="cli", role="user", content="Session A message")
    adapter.append(session_id=sess_b, surface="cli", role="user", content="Session B message")
    adapter.append(session_id=sess_a, surface="cli", role="assistant", content="Session A reply")

    loaded_a = adapter.load_session(sess_a)
    loaded_b = adapter.load_session(sess_b)
    loaded_missing = adapter.load_session(str(uuid.uuid4()))

    assert len(loaded_a) == 2
    assert all(m.session_id == sess_a for m in loaded_a)
    assert len(loaded_b) == 1
    assert loaded_b[0].content == "Session B message"
    assert loaded_missing == []


# ---------------------------------------------------------------------------
# Test 5: chronological ordering by timestamp
# ---------------------------------------------------------------------------

def test_load_session_chronological_order(campfire_id: str) -> None:
    adapter = CampfireConversationAdapter(campfire_id)
    session_id = str(uuid.uuid4())

    # Append with explicit out-of-order timestamps
    adapter.append(
        session_id=session_id, surface="cli", role="assistant", content="third",
        timestamp="2024-01-01T12:00:00+00:00",
    )
    adapter.append(
        session_id=session_id, surface="cli", role="user", content="first",
        timestamp="2024-01-01T10:00:00+00:00",
    )
    adapter.append(
        session_id=session_id, surface="cli", role="user", content="second",
        timestamp="2024-01-01T11:00:00+00:00",
    )

    loaded = adapter.load_session(session_id)
    assert [m.content for m in loaded] == ["first", "second", "third"]


# ---------------------------------------------------------------------------
# Test 6: ContextWindowManager builds valid context from adapter output
# ---------------------------------------------------------------------------

def test_context_window_manager_from_adapter(campfire_id: str) -> None:
    adapter = CampfireConversationAdapter(campfire_id)
    session_id = str(uuid.uuid4())

    adapter.append(session_id=session_id, surface="cli", role="user", content="What is my security posture?")
    adapter.append(
        session_id=session_id,
        surface="cli",
        role="assistant",
        content="Based on your findings, there are 2 critical issues.",
        finding_refs=["MC-010"],
        tokens_used=120,
    )
    adapter.append(session_id=session_id, surface="cli", role="user", content="Tell me more about MC-010.")

    history = adapter.load_session(session_id)
    assert len(history) == 3

    # ContextWindowManager with no managed_client uses truncation fallback
    ctx_manager = ContextWindowManager(managed_client=None)
    context = ctx_manager.build_context(history)

    # Verify the context structure is valid
    assert "messages" in context
    assert "summary" in context
    assert "finding_refs" in context
    assert "total_tokens" in context

    # All messages should be verbatim (3 messages < verbatim_count=10)
    assert len(context["messages"]) == 3
    assert context["summary"] is None

    # finding_refs collected from all messages
    assert "MC-010" in context["finding_refs"]

    # Roles should be preserved
    roles = [m["role"] for m in context["messages"]]
    assert roles == ["user", "assistant", "user"]

    # Content should be preserved
    contents = [m["content"] for m in context["messages"]]
    assert contents[0] == "What is my security posture?"
    assert contents[2] == "Tell me more about MC-010."
