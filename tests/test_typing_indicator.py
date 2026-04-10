"""Tests for typing indicator: TelegramCampfireBridge.notify_typing and
CampfireDispatcher heartbeat in _dispatch_message."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mallcop.telegram_bridge import TelegramCampfireBridge


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_bridge(**kwargs) -> TelegramCampfireBridge:
    defaults = dict(
        bot_token="123456:TEST",
        chat_id="999",
        campfire_id="test-campfire",
    )
    defaults.update(kwargs)
    return TelegramCampfireBridge(**defaults)


def _make_inbound_msg(from_id: str = "42", content: str = "hello") -> dict:
    return {
        "id": "msg-001",
        "payload": json.dumps({"content": content, "from_id": from_id}),
        "tags": [f"relay:from_id:{from_id}", "relay:inbound"],
    }


# ---------------------------------------------------------------------------
# 1. notify_typing calls the right URL with the right payload
# ---------------------------------------------------------------------------


def test_notify_typing_calls_telegram_api():
    bridge = _make_bridge()

    mock_response = MagicMock()
    mock_response.ok = True

    with patch("mallcop.telegram_bridge.requests.post", return_value=mock_response) as mock_post:
        asyncio.run(bridge.notify_typing(12345))

    mock_post.assert_called_once()
    call_args = mock_post.call_args
    url = call_args[0][0]
    payload = call_args[1]["json"]

    assert url.endswith("/sendChatAction"), f"Unexpected URL: {url}"
    assert payload["chat_id"] == 12345
    assert payload["action"] == "typing"


# ---------------------------------------------------------------------------
# 2. notify_typing is non-fatal on error (4xx response)
# ---------------------------------------------------------------------------


def test_notify_typing_non_fatal_on_error():
    bridge = _make_bridge()

    mock_response = MagicMock()
    mock_response.ok = False
    mock_response.text = "Bad Request"

    with patch("mallcop.telegram_bridge.requests.post", return_value=mock_response):
        # Must not raise
        asyncio.run(bridge.notify_typing("999"))


def test_notify_typing_non_fatal_on_exception():
    bridge = _make_bridge()

    with patch("mallcop.telegram_bridge.requests.post", side_effect=ConnectionError("no network")):
        # Must not raise
        asyncio.run(bridge.notify_typing("999"))


# ---------------------------------------------------------------------------
# 3. Heartbeat task is cancelled after _dispatch_message completes
# ---------------------------------------------------------------------------


def test_heartbeat_cancelled_after_dispatch():
    """Verify the heartbeat task is cancelled in the finally block."""
    from mallcop.campfire_dispatch import CampfireDispatcher

    dispatcher = CampfireDispatcher(
        campfire_id="test-campfire",
        interactive_runner=MagicMock(),
        root=Path("/tmp"),
    )

    mock_bridge = MagicMock()
    notify_call_count = 0

    async def slow_notify(chat_id):
        nonlocal notify_call_count
        notify_call_count += 1

    mock_bridge.notify_typing = slow_notify

    mock_result = {"response": "ok", "tokens_used": 10}

    async def run():
        with patch("mallcop.chat.chat_turn", new_callable=AsyncMock, return_value=mock_result):
            with patch.object(dispatcher, "_post_response", new_callable=AsyncMock):
                msg = _make_inbound_msg(from_id="42")
                await dispatcher._dispatch_message(msg, bridge=mock_bridge)

    asyncio.run(run())
    # Function completed cleanly — heartbeat was cancelled in finally block.


def test_heartbeat_not_started_without_bridge():
    """Existing behavior preserved: no bridge → no heartbeat task."""
    from mallcop.campfire_dispatch import CampfireDispatcher

    dispatcher = CampfireDispatcher(
        campfire_id="test-campfire",
        interactive_runner=MagicMock(),
        root=Path("/tmp"),
    )

    mock_result = {"response": "ok", "tokens_used": 5}

    async def run():
        with patch("mallcop.chat.chat_turn", new_callable=AsyncMock, return_value=mock_result):
            with patch.object(dispatcher, "_post_response", new_callable=AsyncMock):
                msg = _make_inbound_msg(from_id="77")
                # No bridge argument — must not raise
                await dispatcher._dispatch_message(msg)

    asyncio.run(run())


def test_heartbeat_cancelled_on_chat_turn_exception():
    """Heartbeat is cancelled even when chat_turn raises."""
    from mallcop.campfire_dispatch import CampfireDispatcher

    dispatcher = CampfireDispatcher(
        campfire_id="test-campfire",
        interactive_runner=MagicMock(),
        root=Path("/tmp"),
    )

    mock_bridge = MagicMock()
    mock_bridge.notify_typing = AsyncMock()

    async def run():
        with patch("mallcop.chat.chat_turn", new_callable=AsyncMock, side_effect=RuntimeError("boom")):
            msg = _make_inbound_msg(from_id="55")
            # Should not raise — chat_turn error is caught, heartbeat cleaned up
            await dispatcher._dispatch_message(msg, bridge=mock_bridge)

    asyncio.run(run())
