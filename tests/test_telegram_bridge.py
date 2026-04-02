"""Tests for TelegramCampfireBridge — real Telegram bot, real campfire.

Requires:
    MALLCOP_TEST_TELEGRAM_BOT_TOKEN — Telegram bot token
    MALLCOP_TEST_TELEGRAM_CHAT_ID   — Telegram chat ID

Tests are skipped when the env var is not set.
"""

from __future__ import annotations

import json
import os
import subprocess
import uuid

import pytest

from mallcop.telegram_bridge import TelegramCampfireBridge


# ---------------------------------------------------------------------------
# Skip guard
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.skipif(
    not os.environ.get("MALLCOP_TEST_TELEGRAM_BOT_TOKEN"),
    reason="MALLCOP_TEST_TELEGRAM_BOT_TOKEN not set",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_campfire(description: str) -> str:
    """Create a real campfire and return its ID."""
    env = os.environ.copy()
    result = subprocess.run(
        ["cf", "create", "--description", description],
        capture_output=True, text=True, env=env,
    )
    assert result.returncode == 0, f"cf create failed: {result.stderr}"
    campfire_id = result.stdout.strip()
    assert campfire_id, "cf create returned empty campfire ID"
    return campfire_id


def _disband_campfire(campfire_id: str) -> None:
    """Disband a campfire (best-effort)."""
    subprocess.run(["cf", "disband", campfire_id], capture_output=True)


def _read_all(campfire_id: str, tag: str | None = None) -> list[dict]:
    """Read all messages from campfire with optional tag filter."""
    cmd = ["cf", "read", campfire_id, "--all", "--json"]
    if tag:
        cmd += ["--tag", tag]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"cf read failed: {result.stderr}"
    raw = result.stdout.strip()
    if not raw:
        return []
    return json.loads(raw)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def bot_token() -> str:
    return os.environ["MALLCOP_TEST_TELEGRAM_BOT_TOKEN"]


@pytest.fixture
def chat_id() -> str:
    return os.environ["MALLCOP_TEST_TELEGRAM_CHAT_ID"]


@pytest.fixture
def campfire_id():
    """Fresh campfire per test, disbanded after."""
    uid = str(uuid.uuid4())[:8]
    cf_id = _create_campfire(f"test-telegram-bridge-{uid}")
    yield cf_id
    _disband_campfire(cf_id)


@pytest.fixture
def bridge(bot_token: str, chat_id: str, campfire_id: str) -> TelegramCampfireBridge:
    """Bridge instance wired to the test campfire."""
    cf_home = os.environ.get("CF_HOME")
    return TelegramCampfireBridge(
        bot_token=bot_token,
        chat_id=chat_id,
        campfire_id=campfire_id,
        poll_interval=0.1,
        cf_home=cf_home,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_send_to_telegram_delivers_message(bridge: TelegramCampfireBridge) -> None:
    """_send_to_telegram posts to Telegram without raising."""
    import asyncio
    # Just verify no exception is raised (HTTP 200 from Telegram).
    asyncio.run(bridge._send_to_telegram("mallcop test ping"))


def test_poll_telegram_returns_list(bridge: TelegramCampfireBridge) -> None:
    """_poll_telegram returns a list (may be empty)."""
    import asyncio
    updates = asyncio.run(bridge._poll_telegram())
    assert isinstance(updates, list)


def test_send_to_campfire_posts_with_correct_tags(
    bridge: TelegramCampfireBridge,
    campfire_id: str,
    chat_id: str,
) -> None:
    """_send_to_campfire posts message with chat and session:<chat_id> tags."""
    import asyncio
    asyncio.run(bridge._send_to_campfire("hello from telegram", chat_id))

    messages = _read_all(campfire_id, tag="chat")
    assert len(messages) >= 1, "Expected at least one chat-tagged message in campfire"

    # Verify the last message has the correct tags.
    msg = messages[-1]
    tags = msg.get("tags", [])
    assert "chat" in tags, f"Expected 'chat' tag, got: {tags}"
    assert f"session:{chat_id}" in tags, f"Expected 'session:{chat_id}' tag, got: {tags}"
    assert "platform:telegram" in tags, f"Expected 'platform:telegram' tag, got: {tags}"

    # Verify payload (campfire stores message body under "payload" key).
    raw_payload = msg.get("payload", "")
    try:
        payload = json.loads(raw_payload)
        assert payload.get("content") == "hello from telegram"
    except json.JSONDecodeError:
        pytest.fail(f"Message payload is not valid JSON: {raw_payload!r}")


def test_poll_campfire_returns_list(bridge: TelegramCampfireBridge) -> None:
    """_poll_campfire returns a list (may be empty)."""
    import asyncio
    messages = asyncio.run(bridge._poll_campfire())
    assert isinstance(messages, list)
