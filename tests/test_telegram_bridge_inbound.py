"""Tests for TelegramCampfireBridge — campfire-inbound mode.

These tests are fully mocked (no real Telegram credentials, no real campfire)
and always run regardless of environment variables.  They cover the
``run_once_inbound()`` method.

The raw CBOR file reader (_poll_campfire_inbound) has been removed as part of
the migration to hosted campfire (mallcop-pro-dlu). The inbound forwarding path
is a stub until mallcop-pro-qkc lands.

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


def test_run_once_inbound_stub_no_forwarding() -> None:
    """run_once_inbound is a stub pending mallcop-pro-qkc.

    The old CBOR file reader has been removed. Until the convention-based
    inbound reader (mallcop-pro-qkc) is implemented, run_once_inbound does
    not forward tg-inbound messages to campfire. This test documents that
    stub behaviour.
    """
    bridge = _make_bridge_inbound()

    cf_calls: list[list[str]] = []

    async def make_proc(*args, **kwargs):
        cmd_args = list(args)
        cf_calls.append(cmd_args)
        return _make_proc()

    with patch("asyncio.create_subprocess_exec", side_effect=make_proc):
        asyncio.run(bridge.run_once_inbound())

    # No cf send should happen — the inbound reader is a stub (TODO: mallcop-pro-qkc)
    send_calls = [c for c in cf_calls if "send" in c]
    assert not send_calls, (
        f"Expected no cf send calls in stub mode; got: {send_calls}"
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
