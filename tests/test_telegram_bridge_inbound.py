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

def test_run_once_inbound_forwards_inbound_messages_to_campfire() -> None:
    """relay:inbound messages from campfire must be forwarded as chat+session tags."""
    bridge = _make_bridge_inbound()

    inbound_messages = [
        {
            "payload": json.dumps({
                "content": "hello from telegram",
                "from_id": "456",
                "platform": "telegram",
            }),
            "tags": ["relay:inbound", "session:456"],
        },
    ]

    cf_calls: list[list[str]] = []

    async def make_proc(*args, **kwargs):
        cmd_args = list(args)
        cf_calls.append(cmd_args)
        if "relay:inbound" in cmd_args:
            return _make_proc(stdout=_cf_json_bytes(inbound_messages))
        return _make_proc()

    with patch("asyncio.create_subprocess_exec", side_effect=make_proc):
        asyncio.run(bridge.run_once_inbound())

    send_calls = [c for c in cf_calls if "send" in c]
    assert len(send_calls) == 1, f"Expected exactly one cf send call, got: {send_calls}"
    send_args = send_calls[0]
    assert "--tag" in send_args
    tag_idx = send_args.index("--tag")
    # chat tag must be present
    assert "chat" in send_args[tag_idx:], f"Expected 'chat' tag in send args: {send_args}"
    # session:<from_id> tag must be present
    session_tags = [a for a in send_args if str(a).startswith("session:")]
    assert session_tags, f"Expected session:<id> tag in send args: {send_args}"
    assert "456" in session_tags[0], f"Expected session:456 tag, got: {session_tags}"


def test_run_once_inbound_no_inbound_messages_no_cf_send() -> None:
    """No relay:inbound messages → no cf send calls."""
    bridge = _make_bridge_inbound()

    cf_calls: list[list[str]] = []

    async def make_proc(*args, **kwargs):
        cf_calls.append(list(args))
        return _make_proc()

    with patch("asyncio.create_subprocess_exec", side_effect=make_proc):
        asyncio.run(bridge.run_once_inbound())

    send_calls = [c for c in cf_calls if "send" in c]
    assert not send_calls, f"Expected no cf send calls; got: {send_calls}"


def test_run_once_inbound_multiple_inbound_messages() -> None:
    """Multiple relay:inbound messages are each forwarded as separate cf send calls."""
    bridge = _make_bridge_inbound()

    inbound_messages = [
        {
            "payload": json.dumps({"content": "msg one", "from_id": "111"}),
            "tags": ["relay:inbound", "session:111"],
        },
        {
            "payload": json.dumps({"content": "msg two", "from_id": "222"}),
            "tags": ["relay:inbound", "session:222"],
        },
    ]

    cf_calls: list[list[str]] = []

    async def make_proc(*args, **kwargs):
        cmd_args = list(args)
        cf_calls.append(cmd_args)
        if "relay:inbound" in cmd_args:
            return _make_proc(stdout=_cf_json_bytes(inbound_messages))
        return _make_proc()

    with patch("asyncio.create_subprocess_exec", side_effect=make_proc):
        asyncio.run(bridge.run_once_inbound())

    send_calls = [c for c in cf_calls if "send" in c]
    assert len(send_calls) == 2, f"Expected 2 cf send calls, got: {send_calls}"


def test_run_once_inbound_skips_empty_content() -> None:
    """relay:inbound messages with empty/missing content are silently skipped."""
    bridge = _make_bridge_inbound()

    inbound_messages = [
        {
            "payload": json.dumps({"content": "", "from_id": "789"}),
            "tags": ["relay:inbound"],
        },
    ]

    cf_calls: list[list[str]] = []

    async def make_proc(*args, **kwargs):
        cmd_args = list(args)
        cf_calls.append(cmd_args)
        if "relay:inbound" in cmd_args:
            return _make_proc(stdout=_cf_json_bytes(inbound_messages))
        return _make_proc()

    with patch("asyncio.create_subprocess_exec", side_effect=make_proc):
        asyncio.run(bridge.run_once_inbound())

    send_calls = [c for c in cf_calls if "send" in c]
    assert not send_calls, f"Expected no cf send for empty content; got: {send_calls}"


# ---------------------------------------------------------------------------
# Tests: relay:response → Telegram forwarding
# ---------------------------------------------------------------------------

def test_run_once_inbound_forwards_relay_responses_to_telegram() -> None:
    """relay:response tagged messages must be forwarded to Telegram sendMessage."""
    bridge = _make_bridge_inbound()

    relay_responses = [
        {
            "payload": json.dumps({"content": "agent reply here"}),
            "tags": ["relay:response"],
        },
    ]

    async def make_proc(*args, **kwargs):
        cmd_args = list(args)
        if "relay:response" in cmd_args:
            return _make_proc(stdout=_cf_json_bytes(relay_responses))
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
    payload = call_kwargs.kwargs.get("json") or (
        call_kwargs.args[1] if len(call_kwargs.args) > 1 else {}
    )
    assert payload.get("text") == "agent reply here", (
        f"Expected Telegram sendMessage text='agent reply here', got payload: {payload}"
    )


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
