"""E2E integration tests for the bidirectional daemon flow.

Exercises the full chain with a real campfire and mocked external calls:

  Telegram user message
    → campfire (--tag chat --tag session:xxx --instance mallcop)
      → CampfireDispatcher reads it, calls chat_turn (mocked)
        → posts response to campfire (--tag response --instance mallcop)
          → TelegramCampfireBridge reads it via _poll_campfire
            → _extract_response_text extracts content
              → delivered to Telegram (mocked)

Also covers the daemon finding-publication path:
  _run_one_scan returns findings → dispatcher.publish_finding called.

Requires CF_HOME in environment (real campfire, no Telegram creds needed).
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mallcop.telegram_bridge import TelegramCampfireBridge
import mallcop.daemon as daemon_mod


# ---------------------------------------------------------------------------
# Skip if no campfire session
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.skipif(
    not os.environ.get("CF_HOME"),
    reason="CF_HOME not set — campfire session required for E2E tests",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cf(*args: str) -> str:
    result = subprocess.run(
        ["cf", *args],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"cf {args[0]} failed: {result.stderr}"
    return result.stdout.strip()


def _create_campfire(description: str) -> str:
    return _cf("create", "--description", description)


def _disband_campfire(campfire_id: str) -> None:
    subprocess.run(["cf", "disband", campfire_id], capture_output=True)


def _send(campfire_id: str, payload: str, *extra_flags: str) -> None:
    _cf("send", campfire_id, *extra_flags, payload)


def _read_all(campfire_id: str, tag: str | None = None) -> list[dict]:
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
def campfire_id():
    uid = str(uuid.uuid4())[:8]
    cf_id = _create_campfire(f"e2e-daemon-{uid}")
    yield cf_id
    _disband_campfire(cf_id)


@pytest.fixture
def bridge(campfire_id: str) -> TelegramCampfireBridge:
    cf_home = os.environ.get("CF_HOME")
    return TelegramCampfireBridge(
        bot_token="fake-token-for-test",
        chat_id="12345",
        campfire_id=campfire_id,
        poll_interval=0.1,
        cf_home=cf_home,
    )


# ---------------------------------------------------------------------------
# Test 1: Bridge _poll_campfire returns mallcop-instance response messages
#
# This is the regression test for the P1 bug where the filter dropped
# instance=mallcop messages (exactly the ones the bridge needs to forward).
# ---------------------------------------------------------------------------

def test_bridge_poll_campfire_returns_mallcop_responses(
    bridge: TelegramCampfireBridge,
    campfire_id: str,
) -> None:
    """_poll_campfire must return messages with instance=mallcop and tag=response."""
    payload = json.dumps({"content": "Your scan found 2 findings."})
    _send(
        campfire_id, payload,
        "--tag", "response",
        "--instance", "mallcop",
    )

    messages = asyncio.run(bridge._poll_campfire())
    assert len(messages) >= 1, (
        "_poll_campfire returned nothing — instance=mallcop filter is broken again"
    )


# ---------------------------------------------------------------------------
# Test 2: _extract_response_text extracts "content" key correctly
# ---------------------------------------------------------------------------

def test_extract_response_text_uses_content_key() -> None:
    """_extract_response_text must return the 'content' key (dispatcher uses this)."""
    msg = {"payload": json.dumps({"content": "Hello from mallcop"})}
    text = TelegramCampfireBridge._extract_response_text(msg)
    assert text == "Hello from mallcop"


def test_extract_response_text_raw_fallback() -> None:
    """_extract_response_text returns raw payload when not JSON."""
    msg = {"payload": "plain text response"}
    text = TelegramCampfireBridge._extract_response_text(msg)
    assert text == "plain text response"


# ---------------------------------------------------------------------------
# Test 3: Full bridge round-trip — campfire response → Telegram delivery
#
# Posts a response-tagged mallcop message to campfire, runs one bridge poll
# cycle, and verifies _send_to_telegram is called with the right content.
# ---------------------------------------------------------------------------

def test_bridge_run_cycle_delivers_campfire_response_to_telegram(
    bridge: TelegramCampfireBridge,
    campfire_id: str,
) -> None:
    """A response-tagged campfire message must flow through to _send_to_telegram."""
    payload = json.dumps({"content": "2 findings detected. Check your console."})
    _send(
        campfire_id, payload,
        "--tag", "response",
        "--instance", "mallcop",
    )

    delivered: list[str] = []

    async def fake_send_to_telegram(text: str) -> None:
        delivered.append(text)

    async def fake_poll_telegram() -> list[dict]:
        return []  # no incoming Telegram messages in this test

    async def run_one_cycle() -> None:
        with (
            patch.object(bridge, "_send_to_telegram", side_effect=fake_send_to_telegram),
            patch.object(bridge, "_poll_telegram", side_effect=fake_poll_telegram),
        ):
            # Run the bridge loop once then cancel it.
            task = asyncio.create_task(bridge.run())
            await asyncio.sleep(0.3)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    asyncio.run(run_one_cycle())

    assert len(delivered) >= 1, "Expected _send_to_telegram to be called"
    assert delivered[0] == "2 findings detected. Check your console."


# ---------------------------------------------------------------------------
# Test 4: Daemon _scan_loop publishes findings via create_task
# ---------------------------------------------------------------------------

def test_scan_loop_publishes_findings_on_success() -> None:
    """When _run_one_scan returns findings, publish_finding is called for each."""
    dispatcher = MagicMock()
    publish_calls: list[object] = []

    async def fake_publish(finding):
        publish_calls.append(finding)

    dispatcher.publish_finding = fake_publish

    scan_attempts: list[int] = []

    async def fake_to_thread(fn, *args, **kwargs):
        scan_attempts.append(1)
        return [{"id": "finding-001"}, {"id": "finding-002"}]

    sleep_calls: list[float] = []

    async def fake_sleep(interval: float) -> None:
        sleep_calls.append(interval)
        raise asyncio.CancelledError

    from pathlib import Path
    tmp = Path("/tmp")

    async def run() -> None:
        with (
            patch.object(asyncio, "sleep", side_effect=fake_sleep),
            patch.object(asyncio, "to_thread", side_effect=fake_to_thread),
        ):
            await daemon_mod._scan_loop(dispatcher, tmp, interval=1.0)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(run())

    assert len(scan_attempts) == 1, "Expected exactly 1 scan attempt"
    # Allow a brief event loop drain so create_task callbacks fire.
    asyncio.run(asyncio.sleep(0))
    assert len(publish_calls) == 2, (
        f"Expected publish_finding called twice, got {len(publish_calls)}"
    )
    assert publish_calls[0] == {"id": "finding-001"}
    assert publish_calls[1] == {"id": "finding-002"}
