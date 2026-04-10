"""Tests for TelegramCampfireBridge — campfire-inbound mode.

These tests are fully mocked (no real Telegram credentials, no real campfire)
and always run regardless of environment variables.  They cover the
``run_once_inbound()`` method and its helpers.

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
# Tests: basic contract
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


# ---------------------------------------------------------------------------
# Tests: relay:inbound forwarding to campfire
# ---------------------------------------------------------------------------

def test_run_once_inbound_does_not_read_relay_inbound() -> None:
    """The bridge MUST NOT read relay:inbound — that's the dispatcher's job.

    Regression test: previously the bridge read relay:inbound and re-wrote
    each message as chat+session tagged, racing with the dispatcher for the
    same cursor and causing a feedback loop where chat history compounded
    on every poll cycle, generating hundreds of duplicate Telegram replies.
    """
    bridge = _make_bridge_inbound()

    cf_calls: list[list[str]] = []

    async def make_proc(*args, **kwargs):
        cf_calls.append(list(args))
        return _make_proc()

    with patch("asyncio.create_subprocess_exec", side_effect=make_proc):
        asyncio.run(bridge.run_once_inbound())

    # No cf read with --tag relay:inbound
    inbound_reads = [c for c in cf_calls if "read" in c and "relay:inbound" in c]
    assert not inbound_reads, f"Bridge must not read relay:inbound; got: {inbound_reads}"
    # No cf send at all (the bridge only reads responses, no writes)
    send_calls = [c for c in cf_calls if "send" in c]
    assert not send_calls, f"Bridge must not write to campfire; got: {send_calls}"


# ---------------------------------------------------------------------------
# Tests: relay:response → Telegram forwarding
# ---------------------------------------------------------------------------

def test_run_once_inbound_is_noop() -> None:
    """run_once_inbound is a no-op — no cf calls and no Telegram sends."""
    bridge = _make_bridge_inbound()

    cf_calls: list[list[str]] = []

    async def make_proc(*args, **kwargs):
        cf_calls.append(list(args))
        return _make_proc()

    with (
        patch("asyncio.create_subprocess_exec", side_effect=make_proc),
        patch("requests.post") as mock_post,
    ):
        asyncio.run(bridge.run_once_inbound())

    assert not cf_calls, f"run_once_inbound must make no cf calls; got: {cf_calls}"
    mock_post.assert_not_called()


def test_run_once_inbound_no_relay_response_no_telegram_send() -> None:
    """No relay:response messages → no Telegram sendMessage calls."""
    bridge = _make_bridge_inbound()

    with (
        patch("asyncio.create_subprocess_exec", return_value=_make_proc()),
        patch("requests.post") as mock_post,
    ):
        asyncio.run(bridge.run_once_inbound())

    mock_post.assert_not_called()


# ---------------------------------------------------------------------------
# Tests: _extract_inbound_fields helper
# ---------------------------------------------------------------------------

def test_extract_inbound_fields_json_payload() -> None:
    """Parses content and from_id from a JSON payload."""
    msg = {"payload": json.dumps({"content": "hi there", "from_id": "999", "platform": "telegram"})}
    bridge = _make_bridge_inbound()
    content, from_id = bridge._extract_inbound_fields(msg)
    assert content == "hi there"
    assert from_id == "999"


def test_extract_inbound_fields_from_key_fallback() -> None:
    """Falls back to 'from' key when 'from_id' is absent."""
    msg = {"payload": json.dumps({"content": "hello", "from": "77"})}
    bridge = _make_bridge_inbound()
    content, from_id = bridge._extract_inbound_fields(msg)
    assert content == "hello"
    assert from_id == "77"


def test_extract_inbound_fields_unknown_from_id_when_absent() -> None:
    """from_id defaults to 'unknown' when neither from_id nor from are present."""
    msg = {"payload": json.dumps({"content": "test"})}
    bridge = _make_bridge_inbound()
    content, from_id = bridge._extract_inbound_fields(msg)
    assert content == "test"
    assert from_id == "unknown"


def test_extract_inbound_fields_empty_payload() -> None:
    """Returns (None, 'unknown') for empty payload."""
    msg = {"payload": ""}
    bridge = _make_bridge_inbound()
    content, from_id = bridge._extract_inbound_fields(msg)
    assert content is None
    assert from_id == "unknown"


def test_extract_inbound_fields_raw_string_payload() -> None:
    """Non-JSON payload is returned as raw content."""
    msg = {"payload": "plain text message"}
    bridge = _make_bridge_inbound()
    content, from_id = bridge._extract_inbound_fields(msg)
    assert content == "plain text message"
    assert from_id == "unknown"
