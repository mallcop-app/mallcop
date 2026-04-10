"""Tests for read-recent-chat and search-chat-history tools.

Contains at least one real campfire integration test that creates a live
campfire, sends real chat messages via cf, calls the tool with a real
ToolContext, and verifies results. Campfire is disbanded in teardown.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from mallcop.config import BudgetConfig, DeliveryConfig, MallcopConfig
from mallcop.store import JsonlStore
from mallcop.tools import ToolContext
from mallcop.tools.chat_history import read_recent_chat, search_chat_history


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_campfire(description: str) -> str:
    """Create a real campfire, return its ID."""
    result = subprocess.run(
        ["cf", "create", "--description", description, "--transport", "filesystem", "--no-config", "--json"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"cf create failed: {result.stderr}"
    data = json.loads(result.stdout)
    campfire_id = data["campfire_id"]
    assert campfire_id, "cf create returned empty campfire_id"
    return campfire_id


def _disband_campfire(campfire_id: str) -> None:
    """Disband a campfire (best-effort)."""
    subprocess.run(["cf", "disband", campfire_id], capture_output=True)


def _send_chat_message(
    campfire_id: str,
    session_id: str,
    role: str,
    content: str,
) -> None:
    """Send a chat-tagged message to the campfire, mimicking CampfireConversationAdapter."""
    import re
    safe_session_id = re.sub(r"[^a-zA-Z0-9_-]", "_", session_id)

    instance = "user" if role == "user" else "assistant"
    envelope = json.dumps({
        "id": str(uuid.uuid4()),
        "timestamp": "2026-04-10T00:00:00+00:00",
        "tokens_used": 0,
        "content": content,
    })

    cmd = [
        "cf", "send", campfire_id,
        "--instance", instance,
        "--tag", "chat",
        "--tag", f"session:{safe_session_id}",
        envelope,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"cf send failed: {result.stderr}"


def _make_context(campfire_id: str, session_id: str, tmp_path: Path) -> ToolContext:
    """Build a minimal ToolContext pointing at the given campfire."""
    store = JsonlStore(tmp_path)
    config = MallcopConfig(
        secrets_backend="env",
        connectors={},
        routing={},
        actor_chain={},
        budget=BudgetConfig(),
        delivery=DeliveryConfig(campfire_id=campfire_id),
    )
    return ToolContext(
        store=store,
        connectors={},
        config=config,
        session_id=session_id,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def campfire_with_messages(tmp_path: Path):
    """Real campfire with 4 chat messages for two sessions. Disbanded after test."""
    uid = str(uuid.uuid4())[:8]
    campfire_id = _create_campfire(f"test-chat-history-{uid}")

    session_a = f"sess-{uid}-A"
    session_b = f"sess-{uid}-B"

    # Session A: 4 messages
    _send_chat_message(campfire_id, session_a, "user", "Hello, what are my findings?")
    _send_chat_message(campfire_id, session_a, "assistant", "You have 3 open findings.")
    _send_chat_message(campfire_id, session_a, "user", "Tell me more about the critical one.")
    _send_chat_message(campfire_id, session_a, "assistant", "The critical finding involves an S3 bucket.")

    # Session B: 2 messages (should not appear in session A queries)
    _send_chat_message(campfire_id, session_b, "user", "Session B message.")
    _send_chat_message(campfire_id, session_b, "assistant", "Session B response.")

    yield campfire_id, session_a, session_b

    _disband_campfire(campfire_id)


# ---------------------------------------------------------------------------
# Real campfire integration tests
# ---------------------------------------------------------------------------

def test_read_recent_chat_returns_messages_from_real_campfire(
    campfire_with_messages, tmp_path: Path
) -> None:
    """read-recent-chat with n=2 returns 2 most recent messages from session A only."""
    campfire_id, session_a, session_b = campfire_with_messages
    ctx = _make_context(campfire_id, session_a, tmp_path)

    result = asyncio.run(read_recent_chat(ctx, n=2))

    assert isinstance(result, dict)
    messages = result["messages"]
    assert len(messages) == 2, (
        f"Expected 2 messages, got {len(messages)}: {messages}"
    )
    # Most recent 2 in chronological order: user "Tell me more..." then assistant "The critical..."
    assert messages[0]["role"] == "user"
    assert "critical" in messages[0]["content"].lower() or "tell me more" in messages[0]["content"].lower()
    assert messages[1]["role"] == "assistant"
    assert "critical" in messages[1]["content"].lower() or "s3" in messages[1]["content"].lower()


def test_read_recent_chat_session_isolation(
    campfire_with_messages, tmp_path: Path
) -> None:
    """Messages from session B do not appear when querying session A."""
    campfire_id, session_a, session_b = campfire_with_messages
    ctx = _make_context(campfire_id, session_a, tmp_path)

    result = asyncio.run(read_recent_chat(ctx, n=20))
    messages = result["messages"]

    for msg in messages:
        assert "Session B" not in msg["content"], (
            f"Session B message leaked into session A results: {msg}"
        )
    # session A has 4 messages
    assert len(messages) == 4, f"Expected 4 messages for session A, got {len(messages)}"


def test_search_chat_history_finds_matching_messages(
    campfire_with_messages, tmp_path: Path
) -> None:
    """search-chat-history finds messages containing the query string."""
    campfire_id, session_a, _ = campfire_with_messages
    ctx = _make_context(campfire_id, session_a, tmp_path)

    result = asyncio.run(search_chat_history(ctx, query="critical"))

    assert isinstance(result, dict)
    messages = result["messages"]
    assert len(messages) >= 1, f"Expected at least 1 match for 'critical', got {messages}"
    for msg in messages:
        assert "critical" in msg["content"].lower(), (
            f"Returned message doesn't contain 'critical': {msg}"
        )


def test_search_chat_history_no_match_returns_empty(
    campfire_with_messages, tmp_path: Path
) -> None:
    """search-chat-history returns empty list when no messages match."""
    campfire_id, session_a, _ = campfire_with_messages
    ctx = _make_context(campfire_id, session_a, tmp_path)

    result = asyncio.run(search_chat_history(ctx, query="zzz-no-match-xyzzy"))

    assert result["messages"] == []
    assert result["count"] == 0


# ---------------------------------------------------------------------------
# Unit tests (empty session_id / missing campfire_id guard)
# ---------------------------------------------------------------------------

def test_read_recent_chat_returns_empty_when_session_id_empty(tmp_path: Path) -> None:
    """read-recent-chat returns empty list when session_id is empty string."""
    store = JsonlStore(tmp_path)
    config = MallcopConfig(
        secrets_backend="env",
        connectors={},
        routing={},
        actor_chain={},
        budget=BudgetConfig(),
        delivery=DeliveryConfig(campfire_id="some-campfire-id"),
    )
    ctx = ToolContext(store=store, connectors={}, config=config, session_id="")

    result = asyncio.run(read_recent_chat(ctx, n=5))
    assert result == {"messages": [], "count": 0}


def test_search_chat_history_returns_empty_when_session_id_empty(tmp_path: Path) -> None:
    """search-chat-history returns empty list when session_id is empty string."""
    store = JsonlStore(tmp_path)
    config = MallcopConfig(
        secrets_backend="env",
        connectors={},
        routing={},
        actor_chain={},
        budget=BudgetConfig(),
        delivery=DeliveryConfig(campfire_id="some-campfire-id"),
    )
    ctx = ToolContext(store=store, connectors={}, config=config, session_id="")

    result = asyncio.run(search_chat_history(ctx, query="anything"))
    assert result == {"messages": [], "count": 0}


def test_read_recent_chat_returns_empty_when_campfire_id_empty(tmp_path: Path) -> None:
    """read-recent-chat returns empty list when campfire_id is empty."""
    store = JsonlStore(tmp_path)
    config = MallcopConfig(
        secrets_backend="env",
        connectors={},
        routing={},
        actor_chain={},
        budget=BudgetConfig(),
        delivery=DeliveryConfig(campfire_id=""),
    )
    ctx = ToolContext(store=store, connectors={}, config=config, session_id="sess-123")

    result = asyncio.run(read_recent_chat(ctx, n=5))
    assert result == {"messages": [], "count": 0}


def test_search_chat_history_returns_empty_when_query_empty(tmp_path: Path) -> None:
    """search-chat-history returns empty list when query is empty."""
    store = JsonlStore(tmp_path)
    config = MallcopConfig(
        secrets_backend="env",
        connectors={},
        routing={},
        actor_chain={},
        budget=BudgetConfig(),
        delivery=DeliveryConfig(campfire_id="some-campfire-id"),
    )
    ctx = ToolContext(store=store, connectors={}, config=config, session_id="sess-123")

    result = asyncio.run(search_chat_history(ctx, query=""))
    assert result == {"messages": [], "count": 0}


def test_read_recent_chat_n_clamps_to_range(tmp_path: Path) -> None:
    """read-recent-chat clamps n to [1, 20] without error (mocked cf)."""
    store = JsonlStore(tmp_path)
    config = MallcopConfig(
        secrets_backend="env",
        connectors={},
        routing={},
        actor_chain={},
        budget=BudgetConfig(),
        delivery=DeliveryConfig(campfire_id="fake-id"),
    )
    ctx = ToolContext(store=store, connectors={}, config=config, session_id="sess-clamp")

    async def _mock_cf(*args, **kwargs):
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(
            json.dumps([
                {
                    "instance": "user",
                    "tags": ["chat", "session:sess-clamp"],
                    "payload": json.dumps({"id": "m1", "timestamp": "2026-04-10T00:00:00+00:00", "tokens_used": 0, "content": "hello"}),
                    "timestamp": "2026-04-10T00:00:00+00:00",
                }
            ]).encode(),
            b"",
        ))
        return mock_proc

    with patch("asyncio.create_subprocess_exec", side_effect=_mock_cf):
        # n=0 clamps to 1
        result = asyncio.run(read_recent_chat(ctx, n=0))
        assert result["count"] == 1

        # n=99 clamps to 20, but we only have 1 message
        result = asyncio.run(read_recent_chat(ctx, n=99))
        assert result["count"] == 1


def test_read_recent_chat_handles_cf_error_gracefully(tmp_path: Path) -> None:
    """read-recent-chat returns empty list when cf subprocess returns non-zero."""
    store = JsonlStore(tmp_path)
    config = MallcopConfig(
        secrets_backend="env",
        connectors={},
        routing={},
        actor_chain={},
        budget=BudgetConfig(),
        delivery=DeliveryConfig(campfire_id="fake-id"),
    )
    ctx = ToolContext(store=store, connectors={}, config=config, session_id="sess-err")

    async def _failing_cf(*args, **kwargs):
        mock_proc = AsyncMock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(return_value=(b"", b"campfire not found"))
        return mock_proc

    with patch("asyncio.create_subprocess_exec", side_effect=_failing_cf):
        result = asyncio.run(read_recent_chat(ctx, n=5))
        assert result == {"messages": [], "count": 0}


def test_search_chat_history_max_10_results(tmp_path: Path) -> None:
    """search-chat-history returns at most 10 results even if more match."""
    store = JsonlStore(tmp_path)
    config = MallcopConfig(
        secrets_backend="env",
        connectors={},
        routing={},
        actor_chain={},
        budget=BudgetConfig(),
        delivery=DeliveryConfig(campfire_id="fake-id"),
    )
    ctx = ToolContext(store=store, connectors={}, config=config, session_id="sess-many")

    # Build 15 messages all containing "needle"
    msgs = []
    for i in range(15):
        msgs.append({
            "instance": "user",
            "tags": ["chat", "session:sess-many"],
            "payload": json.dumps({
                "id": f"m{i}",
                "timestamp": "2026-04-10T00:00:00+00:00",
                "tokens_used": 0,
                "content": f"needle message {i}",
            }),
            "timestamp": "2026-04-10T00:00:00+00:00",
        })

    async def _mock_cf(*args, **kwargs):
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(
            json.dumps(msgs).encode(),
            b"",
        ))
        return mock_proc

    with patch("asyncio.create_subprocess_exec", side_effect=_mock_cf):
        result = asyncio.run(search_chat_history(ctx, query="needle"))
        assert result["count"] == 10
        assert len(result["messages"]) == 10
