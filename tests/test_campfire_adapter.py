"""Tests for CampfireConversationAdapter — real campfire round-trip.

These tests use a REAL campfire created via `cf create`.  No mocks of cf commands.
The campfire is disbanded after each test to keep the environment clean.
"""

from __future__ import annotations

import asyncio
import subprocess
import uuid
from typing import Generator
from unittest.mock import AsyncMock, patch

import pytest

from mallcop.context_window import ContextWindowManager
from mallcop.conversation import (
    CampfireAdapterError,
    CampfireConversationAdapter,
    ConversationMessage,
)


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

    msg = asyncio.run(adapter.append(
        session_id=session_id,
        surface="cli",
        role="user",
        content="Hello from round-trip test",
        finding_refs=[],
        tokens_used=0,
    ))

    assert msg.session_id == session_id
    assert msg.role == "user"
    assert msg.content == "Hello from round-trip test"
    assert msg.surface == "cli"

    loaded = asyncio.run(adapter.load_session(session_id))
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

    asyncio.run(adapter.append(session_id=session_id, surface="cli", role="user", content="User question"))
    asyncio.run(adapter.append(session_id=session_id, surface="cli", role="assistant", content="Mallcop answer"))

    loaded = asyncio.run(adapter.load_session(session_id))
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

    asyncio.run(adapter.append(
        session_id=session_id,
        surface="slack",
        role="user",
        content="Finding question",
        finding_refs=["MC-001", "MC-042"],
        tokens_used=55,
    ))

    loaded = asyncio.run(adapter.load_session(session_id))
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

    asyncio.run(adapter.append(session_id=sess_a, surface="cli", role="user", content="Session A message"))
    asyncio.run(adapter.append(session_id=sess_b, surface="cli", role="user", content="Session B message"))
    asyncio.run(adapter.append(session_id=sess_a, surface="cli", role="assistant", content="Session A reply"))

    loaded_a = asyncio.run(adapter.load_session(sess_a))
    loaded_b = asyncio.run(adapter.load_session(sess_b))
    loaded_missing = asyncio.run(adapter.load_session(str(uuid.uuid4())))

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
    asyncio.run(adapter.append(
        session_id=session_id, surface="cli", role="assistant", content="third",
        timestamp="2024-01-01T12:00:00+00:00",
    ))
    asyncio.run(adapter.append(
        session_id=session_id, surface="cli", role="user", content="first",
        timestamp="2024-01-01T10:00:00+00:00",
    ))
    asyncio.run(adapter.append(
        session_id=session_id, surface="cli", role="user", content="second",
        timestamp="2024-01-01T11:00:00+00:00",
    ))

    loaded = asyncio.run(adapter.load_session(session_id))
    assert [m.content for m in loaded] == ["first", "second", "third"]


# ---------------------------------------------------------------------------
# Test 6: ContextWindowManager builds valid context from adapter output
# ---------------------------------------------------------------------------

def test_context_window_manager_from_adapter(campfire_id: str) -> None:
    adapter = CampfireConversationAdapter(campfire_id)
    session_id = str(uuid.uuid4())

    asyncio.run(adapter.append(session_id=session_id, surface="cli", role="user", content="What is my security posture?"))
    asyncio.run(adapter.append(
        session_id=session_id,
        surface="cli",
        role="assistant",
        content="Based on your findings, there are 2 critical issues.",
        finding_refs=["MC-010"],
        tokens_used=120,
    ))
    asyncio.run(adapter.append(session_id=session_id, surface="cli", role="user", content="Tell me more about MC-010."))

    history = asyncio.run(adapter.load_session(session_id))
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


# ---------------------------------------------------------------------------
# Test 7 (mallcop-pro-vhj): load_session returns [] when cf read returns "null"
# ---------------------------------------------------------------------------

def test_load_session_returns_empty_on_null_json() -> None:
    """cf read --json returning 'null' must not raise TypeError."""
    adapter = CampfireConversationAdapter("fake-campfire-id")

    with patch.object(adapter, "_cf", new=AsyncMock(return_value="null")):
        result = asyncio.run(adapter.load_session("any-session"))

    assert result == [], f"Expected [], got {result!r}"


# ---------------------------------------------------------------------------
# Test 8 (mallcop-pro-i2z): _cf() failure is handled gracefully
# ---------------------------------------------------------------------------

def test_load_session_returns_empty_on_cf_failure() -> None:
    """RuntimeError from _cf() in load_session must not propagate -- return []."""
    adapter = CampfireConversationAdapter("fake-campfire-id")

    with patch.object(adapter, "_cf", new=AsyncMock(side_effect=RuntimeError("cf: connection refused"))):
        result = asyncio.run(adapter.load_session("any-session"))

    assert result == [], f"Expected [], got {result!r}"


def test_append_raises_campfire_adapter_error_on_cf_failure() -> None:
    """RuntimeError from _cf() in append must be re-raised as CampfireAdapterError."""
    adapter = CampfireConversationAdapter("fake-campfire-id")

    with patch.object(adapter, "_cf", new=AsyncMock(side_effect=RuntimeError("cf: connection refused"))):
        with pytest.raises(CampfireAdapterError):
            asyncio.run(adapter.append(
                session_id="any-session",
                surface="cli",
                role="user",
                content="test content",
            ))


# ---------------------------------------------------------------------------
# Test 9 (mallcop-pro-cmy): session_id with colons/spaces round-trips correctly
# ---------------------------------------------------------------------------

def test_sanitize_session_id_replaces_special_chars() -> None:
    """session_id with colons and spaces is sanitized consistently."""
    adapter = CampfireConversationAdapter("fake-campfire-id")

    raw_session_id = "abc:def ghi/jkl"
    expected_safe = "abc_def_ghi_jkl"

    safe = adapter._sanitize_session_id(raw_session_id)
    assert safe == expected_safe, f"Expected {expected_safe!r}, got {safe!r}"

    # Tags built with the raw session_id should use the sanitized form
    tags = adapter._build_tags(raw_session_id, "cli", [])
    assert f"session:{expected_safe}" in tags, f"Expected sanitized tag in {tags}"
    # The raw (unsafe) form should NOT appear in any tag
    assert not any(raw_session_id in t for t in tags), \
        f"Raw session_id should not appear in tags: {tags}"


def test_load_session_coloned_session_id_round_trip(campfire_id: str) -> None:
    """session_id with a colon round-trips through append->load_session correctly."""
    adapter = CampfireConversationAdapter(campfire_id)
    # Use a session_id with a colon -- common in namespaced IDs like "tenant:user-uuid"
    raw_uuid = str(uuid.uuid4())
    session_id = f"tenant:{raw_uuid}"

    msg = asyncio.run(adapter.append(
        session_id=session_id,
        surface="cli",
        role="user",
        content="Message with colon session ID",
    ))
    assert msg.session_id == session_id

    # load_session must find the message using the same raw session_id
    loaded = asyncio.run(adapter.load_session(session_id))
    assert len(loaded) == 1, f"Expected 1 message, got {len(loaded)}"
    assert loaded[0].content == "Message with colon session ID"


# ---------------------------------------------------------------------------
# Test (mallcop-pro-qw5): empty-string id and timestamp are preserved, not replaced
# ---------------------------------------------------------------------------

def test_load_session_preserves_empty_string_id_and_timestamp() -> None:
    """Envelope with id='' and timestamp='' must be preserved as-is (not replaced via 'or' fallback)."""
    import json as _json

    adapter = CampfireConversationAdapter("fake-campfire-id")

    # Build a minimal cf read JSON response with id="" and timestamp=""
    safe_session_id = adapter._sanitize_session_id("sess_empty_str")
    envelope = {
        "id": "",
        "timestamp": "",
        "tokens_used": 0,
        "content": "test content with empty id",
    }
    cf_response = _json.dumps([
        {
            "tags": ["chat", f"session:{safe_session_id}", "platform:cli"],
            "payload": _json.dumps(envelope),
            "instance": "user",
        }
    ])

    with patch.object(adapter, "_cf", new=AsyncMock(return_value=cf_response)):
        result = asyncio.run(adapter.load_session("sess_empty_str"))

    assert len(result) == 1, f"Expected 1 message, got {len(result)}"
    # Empty string id must be preserved — not silently replaced with a new UUID
    assert result[0].id == "", f"Expected empty string id, got {result[0].id!r}"
    # Empty string timestamp must be preserved — not silently replaced
    assert result[0].timestamp == "", f"Expected empty string timestamp, got {result[0].timestamp!r}"


# ---------------------------------------------------------------------------
# Test (mallcop-pro-a40): empty strings in finding_refs are filtered out
# ---------------------------------------------------------------------------

def test_build_tags_filters_empty_finding_refs() -> None:
    """_build_tags must not emit a 'finding_ref:' tag for empty-string entries."""
    adapter = CampfireConversationAdapter("fake-campfire-id")

    tags = adapter._build_tags("sess_x", "cli", ["MC-001", "", "MC-002"])

    finding_ref_tags = [t for t in tags if t.startswith("finding_ref:")]
    assert "finding_ref:MC-001" in finding_ref_tags, "MC-001 should be present"
    assert "finding_ref:MC-002" in finding_ref_tags, "MC-002 should be present"
    assert "finding_ref:" not in finding_ref_tags, "Empty string must not produce a bare finding_ref: tag"
    assert len(finding_ref_tags) == 2, f"Expected 2 finding_ref tags, got {finding_ref_tags}"


def test_extract_finding_refs_filters_empty() -> None:
    """_extract_finding_refs must skip the bare 'finding_ref:' tag (empty string value)."""
    tags = ["mallcop:chat", "finding_ref:MC-001", "finding_ref:", "finding_ref:MC-002"]

    refs = CampfireConversationAdapter._extract_finding_refs(tags)

    assert refs == ["MC-001", "MC-002"], f"Expected ['MC-001', 'MC-002'], got {refs!r}"


def test_load_session_finding_refs_empty_string_filtered() -> None:
    """Appending finding_refs=['MC-001', ''] must load back as ['MC-001'] only."""
    import json as _json

    adapter = CampfireConversationAdapter("fake-campfire-id")

    # Simulate what the campfire would return after storing tags with an empty ref filtered out
    safe_session_id = adapter._sanitize_session_id("sess_refs_test")

    # The tags as they would be stored after _build_tags filters the empty string
    tags = adapter._build_tags("sess_refs_test", "cli", ["MC-001", ""])
    # Confirm the empty ref was not stored
    assert "finding_ref:" not in tags

    envelope = {"id": "msg_abc", "timestamp": "2024-01-01T10:00:00+00:00", "tokens_used": 0, "content": "hi"}
    cf_response = _json.dumps([
        {
            "tags": tags,
            "payload": _json.dumps(envelope),
            "instance": "user",
        }
    ])

    with patch.object(adapter, "_cf", new=AsyncMock(return_value=cf_response)):
        result = asyncio.run(adapter.load_session("sess_refs_test"))

    assert len(result) == 1
    assert result[0].finding_refs == ["MC-001"], f"Expected ['MC-001'], got {result[0].finding_refs!r}"
