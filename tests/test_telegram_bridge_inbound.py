"""Tests for TelegramCampfireBridge — campfire-inbound mode.

These tests are fully mocked (no real Telegram credentials, no real campfire)
and always run regardless of environment variables.  They cover the
``run_once_inbound()`` method and the ``_poll_campfire_inbound()`` helper added
for the pro-online webhook tier.

Mocking strategy: patch ``asyncio.create_subprocess_exec`` to intercept all cf
subprocess calls.  Telegram HTTP (``requests.get`` / ``requests.post``) is also
patched to assert that getUpdates is never called.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest

from mallcop.telegram_bridge import TelegramCampfireBridge


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_bridge_inbound() -> TelegramCampfireBridge:
    """Return a bridge in campfire-inbound mode with dummy credentials."""
    return TelegramCampfireBridge(
        bot_token="test-token",
        chat_id="chat-123",
        campfire_id="campfire-abc",
        inbound_mode=True,
    )


def _cf_json_bytes(messages: list[dict]) -> bytes:
    """Encode campfire message list as UTF-8 JSON bytes for subprocess mock."""
    return json.dumps(messages).encode()


def _make_proc(stdout: bytes = b"[]", returncode: int = 0) -> MagicMock:
    """Return a mock asyncio subprocess with a fixed stdout response."""
    proc = MagicMock()
    proc.returncode = returncode

    async def _communicate():
        return (stdout, b"")

    proc.communicate = _communicate
    return proc


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_run_once_inbound_does_not_call_getupdates() -> None:
    """run_once_inbound must never call Telegram getUpdates."""
    bridge = _make_bridge_inbound()

    with (
        patch(
            "asyncio.create_subprocess_exec",
            return_value=_make_proc(),
        ),
        patch("requests.get") as mock_get,
        patch("requests.post") as mock_post,
    ):
        asyncio.run(bridge.run_once_inbound())

    mock_get.assert_not_called()
    # post is only called for Telegram sendMessage; with empty campfire there's nothing to send
    mock_post.assert_not_called()


def test_run_once_inbound_forwards_messages_to_campfire() -> None:
    """Each tg-inbound message must be forwarded to campfire with chat+session tags."""
    bridge = _make_bridge_inbound()

    inbound_messages = [
        {
            "payload": json.dumps({"content": "hello from user", "from": "user-42"}),
            "tags": ["tg-inbound"],
        },
    ]

    cf_calls: list[list[str]] = []

    async def make_proc(*args, **kwargs):
        cmd_args = list(args)
        cf_calls.append(cmd_args)
        # tg-inbound read → return inbound messages; everything else → empty
        if "--tag" in cmd_args and "tg-inbound" in cmd_args:
            return _make_proc(stdout=_cf_json_bytes(inbound_messages))
        return _make_proc()

    with patch("asyncio.create_subprocess_exec", side_effect=make_proc):
        asyncio.run(bridge.run_once_inbound())

    # There must be at least one cf send call
    send_calls = [c for c in cf_calls if "send" in c]
    assert send_calls, f"Expected at least one cf send call; all calls: {cf_calls}"

    # The send must carry the 'chat' tag
    chat_sends = [c for c in send_calls if "chat" in c]
    assert chat_sends, f"Expected a cf send with 'chat' tag; sends: {send_calls}"

    # The send must carry a session:<chat_id> tag
    session_sends = [c for c in chat_sends if any("session:" in arg for arg in c)]
    assert session_sends, (
        f"Expected 'session:' tag in cf send; chat sends: {chat_sends}"
    )


def test_run_once_inbound_forwards_responses_to_telegram() -> None:
    """response-tagged campfire messages must be forwarded to Telegram sendMessage."""
    bridge = _make_bridge_inbound()

    response_messages = [
        {
            "payload": json.dumps({"content": "agent reply here"}),
            "tags": ["response"],
        },
    ]

    async def make_proc(*args, **kwargs):
        cmd_args = list(args)
        if "--tag" in cmd_args and "tg-inbound" in cmd_args:
            return _make_proc(stdout=b"[]")
        if "--tag" in cmd_args and "response" in cmd_args:
            return _make_proc(stdout=_cf_json_bytes(response_messages))
        return _make_proc()

    mock_post_resp = MagicMock()
    mock_post_resp.raise_for_status.return_value = None

    with (
        patch("asyncio.create_subprocess_exec", side_effect=make_proc),
        patch("requests.post", return_value=mock_post_resp) as mock_post,
    ):
        asyncio.run(bridge.run_once_inbound())

    mock_post.assert_called_once()
    call_kwargs = mock_post.call_args
    # requests.post(url, json=payload, timeout=...)
    payload = call_kwargs.kwargs.get("json") or (
        call_kwargs.args[1] if len(call_kwargs.args) > 1 else {}
    )
    assert payload.get("text") == "agent reply here", (
        f"Expected Telegram sendMessage text='agent reply here', got payload: {payload}"
    )
