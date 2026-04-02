"""Tests for CampfireDispatcher — real campfire, no mocks of cf or subprocess.

The tests create real campfires, send real messages, run the dispatcher,
and verify real campfire state. managed_client is mocked (it's an
external inference endpoint, not cf or subprocess).

Tests for subprocess error handling (timeout, OSError) mock
asyncio.create_subprocess_exec — the subprocess is the external system
being guarded against, not cf message semantics.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mallcop.campfire_dispatch import CampfireDispatcher
from mallcop.llm_types import LLMResponse
from mallcop.schemas import Finding, FindingStatus, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_campfire(description: str) -> str:
    """Create a real campfire and return its ID."""
    result = subprocess.run(
        ["cf", "create", "--description", description],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"cf create failed: {result.stderr}"
    campfire_id = result.stdout.strip()
    assert campfire_id, "cf create returned empty campfire ID"
    return campfire_id


def _disband_campfire(campfire_id: str) -> None:
    """Disband a campfire (best-effort)."""
    subprocess.run(["cf", "disband", campfire_id], capture_output=True)


def _send_message(campfire_id: str, payload: str, tags: list[str]) -> str:
    """Send a message to campfire via cf send. Returns message ID."""
    cmd = ["cf", "send", campfire_id]
    for tag in tags:
        cmd += ["--tag", tag]
    cmd.append(payload)
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"cf send failed: {result.stderr}"
    return result.stdout.strip()


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


def _make_mock_client(response_text: str = "Security analysis complete.") -> MagicMock:
    """Return a mock ManagedClient that returns a canned response."""
    client = MagicMock()
    llm_resp = LLMResponse(
        tool_calls=[],
        resolution=None,
        tokens_used=42,
        raw_resolution={"content": response_text},
        text=response_text,
    )
    client.chat.return_value = llm_resp
    return client


def _make_finding(
    finding_id: str = "MC-001",
    severity: Severity = Severity.CRITICAL,
    detector: str = "test-connector",
    connector_name: str | None = None,
) -> Finding:
    """Create a minimal Finding for testing."""
    meta: dict[str, Any] = {}
    if connector_name:
        meta["connector"] = connector_name
    return Finding(
        id=finding_id,
        timestamp=datetime(2026, 4, 2, tzinfo=timezone.utc),
        detector=detector,
        event_ids=["evt-001"],
        title="Test finding title",
        severity=severity,
        status=FindingStatus.OPEN,
        annotations=[],
        metadata=meta,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def campfire_id():
    """Fresh campfire per test, disbanded after."""
    uid = str(uuid.uuid4())[:8]
    cf_id = _create_campfire(f"test-dispatch-{uid}")
    yield cf_id
    _disband_campfire(cf_id)


# ---------------------------------------------------------------------------
# Test 1: dispatch loop processes a chat message and posts response
# ---------------------------------------------------------------------------

def test_dispatch_loop_processes_chat_message(campfire_id: str, tmp_path: Path) -> None:
    """Dispatcher reads a chat message, calls chat_turn, posts response back to campfire."""
    session_id = str(uuid.uuid4())
    mock_client = _make_mock_client("Here is my security analysis.")

    # Send a chat message into the campfire before starting the dispatcher.
    question_payload = json.dumps({"content": "What are my open findings?"})
    _send_message(
        campfire_id,
        question_payload,
        tags=["chat", f"session:{session_id}", "platform:campfire"],
    )

    dispatcher = CampfireDispatcher(
        campfire_id=campfire_id,
        managed_client=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    async def run_one_poll():
        # Run exactly one poll cycle: read messages, dispatch, stop.
        # We do this by manually calling the internal methods to avoid
        # needing to cancel an infinite loop race.
        messages = await dispatcher._read_new_messages()
        for msg in messages:
            await dispatcher._dispatch_message(msg)

    asyncio.run(run_one_poll())

    # Verify mock_client.chat was called — means chat_turn() ran.
    assert mock_client.chat.called, "chat_turn() did not invoke managed_client.chat()"

    # Verify a response was posted back to campfire.
    all_msgs = _read_all(campfire_id, tag="chat")
    # Filter to mallcop-instance response messages.
    responses = [
        m for m in all_msgs
        if m.get("instance") == "mallcop"
        and "response" in m.get("tags", [])
    ]
    assert len(responses) >= 1, (
        f"Expected at least 1 response from mallcop instance on campfire, "
        f"got 0. All messages: {[m.get('tags') for m in all_msgs]}"
    )

    # Response payload should contain the mock response text.
    resp_payload = json.loads(responses[0]["payload"])
    assert resp_payload["content"] == "Here is my security analysis."
    assert resp_payload["tokens_used"] == 42

    # Response should carry the session tag.
    session_tag = f"session:{session_id}"
    assert session_tag in responses[0]["tags"], (
        f"Expected session tag {session_tag!r} in response tags: {responses[0]['tags']}"
    )


# ---------------------------------------------------------------------------
# Test 2: publish_finding writes to campfire with correct tags
# ---------------------------------------------------------------------------

def test_publish_finding_writes_correct_tags(campfire_id: str, tmp_path: Path) -> None:
    """publish_finding() sends a finding message with finding, severity, connector, id tags."""
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id=campfire_id,
        managed_client=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    finding = _make_finding(
        finding_id="MC-042",
        severity=Severity.CRITICAL,
        detector="github-scanner",
        connector_name="github",
    )

    asyncio.run(dispatcher.publish_finding(finding))

    # Read all messages from campfire and find the finding message.
    all_msgs = _read_all(campfire_id, tag="finding")

    assert len(all_msgs) >= 1, "Expected at least 1 finding message on campfire"

    finding_msg = all_msgs[0]
    tags = finding_msg.get("tags", [])

    assert "finding" in tags, f"Expected 'finding' tag, got: {tags}"
    assert "severity:critical" in tags, f"Expected 'severity:critical' tag, got: {tags}"
    assert "connector:github" in tags, f"Expected 'connector:github' tag, got: {tags}"
    assert "id:MC-042" in tags, f"Expected 'id:MC-042' tag, got: {tags}"
    assert finding_msg.get("instance") == "mallcop", (
        f"Expected instance='mallcop', got: {finding_msg.get('instance')}"
    )

    # Payload should be the full finding dict.
    payload = json.loads(finding_msg["payload"])
    assert payload["id"] == "MC-042"
    assert payload["severity"] == "critical"


# ---------------------------------------------------------------------------
# Test 3: publish_finding uses detector as connector fallback
# ---------------------------------------------------------------------------

def test_publish_finding_uses_detector_as_connector_fallback(
    campfire_id: str, tmp_path: Path
) -> None:
    """When metadata has no 'connector' key, finding.detector is used as connector tag."""
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id=campfire_id,
        managed_client=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    # No connector_name in metadata — detector="aws-iam" will be used.
    finding = _make_finding(
        finding_id="MC-007",
        severity=Severity.WARN,
        detector="aws-iam",
        connector_name=None,
    )

    asyncio.run(dispatcher.publish_finding(finding))

    all_msgs = _read_all(campfire_id, tag="finding")
    assert len(all_msgs) >= 1
    tags = all_msgs[0].get("tags", [])

    assert "connector:aws-iam" in tags, f"Expected 'connector:aws-iam', got: {tags}"
    assert "severity:warn" in tags, f"Expected 'severity:warn', got: {tags}"
    assert "id:MC-007" in tags, f"Expected 'id:MC-007', got: {tags}"


# ---------------------------------------------------------------------------
# Test 4: dispatcher ignores its own mallcop-instance responses
# ---------------------------------------------------------------------------

def test_dispatch_skips_own_mallcop_messages(campfire_id: str, tmp_path: Path) -> None:
    """Dispatcher does not dispatch messages sent by instance='mallcop'."""
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id=campfire_id,
        managed_client=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    # Send a message with instance=mallcop (our own response) — should be ignored.
    _send_message(
        campfire_id,
        json.dumps({"content": "This is our own response"}),
        tags=["chat", "response"],
    )

    # We need to also set instance=mallcop on the sent message.
    # Since our helper doesn't support --instance, use subprocess directly.
    send_cmd = [
        "cf", "send", campfire_id,
        "--instance", "mallcop",
        "--tag", "chat",
        "--tag", "response",
        json.dumps({"content": "Our own message"}),
    ]
    result = subprocess.run(send_cmd, capture_output=True, text=True)
    assert result.returncode == 0

    async def run_one_poll():
        messages = await dispatcher._read_new_messages()
        for msg in messages:
            await dispatcher._dispatch_message(msg)

    asyncio.run(run_one_poll())

    # Neither message should trigger chat_turn():
    # - The first message (no --instance) has no session: tag → skipped with warning.
    # - The second message has instance=mallcop → skipped as our own message.
    call_count = mock_client.chat.call_count
    assert call_count == 0, (
        f"chat_turn() called {call_count} times — dispatcher should have skipped both messages"
    )


# ---------------------------------------------------------------------------
# Test 5: run() loop cancels cleanly
# ---------------------------------------------------------------------------

def test_run_loop_cancels_cleanly(campfire_id: str, tmp_path: Path) -> None:
    """run() loop shuts down cleanly when cancelled."""
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id=campfire_id,
        managed_client=mock_client,
        root=tmp_path,
        poll_interval=0.05,
    )

    async def run_briefly():
        task = asyncio.create_task(dispatcher.run())
        await asyncio.sleep(0.15)  # let it run a couple of polls
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass  # expected

    asyncio.run(run_briefly())
    # If we get here without exception, the loop cancelled cleanly.


# ---------------------------------------------------------------------------
# Test 6 (mallcop-pro-woq): _run_cf() raises TimeoutError when subprocess hangs
# ---------------------------------------------------------------------------

def test_run_cf_raises_timeout_when_subprocess_hangs(tmp_path: Path) -> None:
    """_run_cf() raises asyncio.TimeoutError when cf subprocess never completes."""
    from mallcop.campfire_dispatch import _run_cf

    # A mock process whose communicate() coroutine hangs forever.
    async def _hang():
        await asyncio.sleep(3600)  # effectively forever
        return b"", b""

    mock_proc = MagicMock()
    mock_proc.communicate = _hang

    async def _create_hanging_proc(*args, **kwargs):
        return mock_proc

    async def run():
        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=_create_hanging_proc,
        ):
            # Use a very short timeout so the test doesn't actually wait 30s.
            import mallcop.campfire_dispatch as mod
            original_timeout = mod._CF_TIMEOUT
            mod._CF_TIMEOUT = 0.01
            try:
                await _run_cf("read", "fake-campfire-id")
            finally:
                mod._CF_TIMEOUT = original_timeout

    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(run())


# ---------------------------------------------------------------------------
# Test 7 (mallcop-pro-8tg): run() raises RuntimeError when cf binary missing
# ---------------------------------------------------------------------------

def test_run_raises_runtime_error_when_cf_not_found(tmp_path: Path) -> None:
    """run() raises RuntimeError (not raw OSError) when cf binary is not on PATH."""
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id="fake-campfire-id",
        managed_client=mock_client,
        root=tmp_path,
        poll_interval=0.05,
        cf_bin="/nonexistent/path/to/cf",
    )

    async def _raise_oserror(*args, **kwargs):
        raise OSError("No such file or directory: '/nonexistent/path/to/cf'")

    async def run():
        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=_raise_oserror,
        ):
            await dispatcher.run()

    with pytest.raises(RuntimeError, match="cf binary not found or not executable"):
        asyncio.run(run())


# ---------------------------------------------------------------------------
# Test 8 (mallcop-pro-cr9): dispatcher skips messages without a session: tag
# ---------------------------------------------------------------------------

def test_dispatch_skips_message_without_session_tag(
    campfire_id: str, tmp_path: Path
) -> None:
    """Dispatcher logs a warning and skips messages that have no session: tag."""
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id=campfire_id,
        managed_client=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    # Send a chat message with NO session: tag.
    _send_message(
        campfire_id,
        json.dumps({"content": "What findings do I have?"}),
        tags=["chat", "platform:campfire"],
    )

    async def run_one_poll():
        messages = await dispatcher._read_new_messages()
        for msg in messages:
            await dispatcher._dispatch_message(msg)

    with patch("mallcop.campfire_dispatch._log") as mock_log:
        asyncio.run(run_one_poll())

        # chat_turn() must NOT have been called.
        assert not mock_client.chat.called, (
            "chat_turn() was called despite missing session: tag"
        )

        # Warning must have been logged.
        assert mock_log.warning.called, "Expected a warning log for missing session: tag"
        warning_text = " ".join(str(a) for a in mock_log.warning.call_args[0])
        assert "session" in warning_text.lower(), (
            f"Warning should mention 'session', got: {warning_text!r}"
        )

    # No response should appear on campfire.
    all_msgs = _read_all(campfire_id, tag="response")
    assert len(all_msgs) == 0, (
        f"Expected no response messages, got: {all_msgs}"
    )


# ---------------------------------------------------------------------------
# Test 9 (mallcop-pro-6p0): dispatcher forwards budget_warning to campfire
# ---------------------------------------------------------------------------

def test_dispatch_forwards_budget_warning(campfire_id: str, tmp_path: Path) -> None:
    """When chat_turn returns a budget_warning, dispatcher posts a second campfire message."""
    session_id = str(uuid.uuid4())
    mock_client = _make_mock_client("Analysis complete.")
    dispatcher = CampfireDispatcher(
        campfire_id=campfire_id,
        managed_client=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    _send_message(
        campfire_id,
        json.dumps({"content": "Check my security posture"}),
        tags=["chat", f"session:{session_id}", "platform:campfire"],
    )

    # Patch chat_turn to return a budget_warning.
    budget_warning_text = "Donut balance below 10% — purchase more to continue."

    async def run_one_poll():
        messages = await dispatcher._read_new_messages()
        for msg in messages:
            # Patch chat_turn at its definition site (local import inside
            # _dispatch_message uses mallcop.chat.chat_turn).
            # chat_turn is now async — use AsyncMock so await works.
            with patch("mallcop.chat.chat_turn", new=AsyncMock(return_value={
                "response": "Analysis complete.",
                "tokens_used": 55,
                "budget_warning": budget_warning_text,
            })):
                await dispatcher._dispatch_message(msg)

    asyncio.run(run_one_poll())

    # Read all campfire messages and find the budget-warning message.
    all_msgs = _read_all(campfire_id, tag="budget-warning")
    assert len(all_msgs) >= 1, (
        f"Expected at least 1 budget-warning message, got 0. "
        f"All messages: {[m.get('tags') for m in _read_all(campfire_id)]}"
    )

    warning_msg = all_msgs[0]
    assert "budget-warning" in warning_msg.get("tags", []), (
        f"Expected 'budget-warning' tag, got: {warning_msg.get('tags')}"
    )
    session_tag = f"session:{session_id}"
    assert session_tag in warning_msg.get("tags", []), (
        f"Expected session tag {session_tag!r}, got: {warning_msg.get('tags')}"
    )
    payload = json.loads(warning_msg["payload"])
    assert payload.get("budget_warning") == budget_warning_text, (
        f"Expected warning text in payload, got: {payload}"
    )


# ---------------------------------------------------------------------------
# Test 10 (mallcop-pro-ueq): platform-error tag on 402/503 responses
# ---------------------------------------------------------------------------

def test_dispatch_adds_platform_error_tag_on_platform_error(
    campfire_id: str, tmp_path: Path
) -> None:
    """When chat_turn returns is_platform_error=True, response carries platform-error tag."""
    session_id = str(uuid.uuid4())
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id=campfire_id,
        managed_client=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    _send_message(
        campfire_id,
        json.dumps({"content": "Check balance"}),
        tags=["chat", f"session:{session_id}", "platform:campfire"],
    )

    async def run_one_poll():
        messages = await dispatcher._read_new_messages()
        for msg in messages:
            with patch("mallcop.chat.chat_turn", new=AsyncMock(return_value={
                "response": "I received your message but can't respond right now — insufficient donut balance.",
                "tokens_used": 0,
                "is_platform_error": True,
            })):
                await dispatcher._dispatch_message(msg)

    asyncio.run(run_one_poll())

    all_msgs = _read_all(campfire_id, tag="response")
    assert len(all_msgs) >= 1, "Expected at least 1 response message"

    response_msg = all_msgs[0]
    tags = response_msg.get("tags", [])
    assert "platform-error" in tags, (
        f"Expected 'platform-error' tag when is_platform_error=True, got: {tags}"
    )


def test_dispatch_no_platform_error_tag_on_normal_response(
    campfire_id: str, tmp_path: Path
) -> None:
    """Normal response (is_platform_error absent/False) does NOT carry platform-error tag."""
    session_id = str(uuid.uuid4())
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id=campfire_id,
        managed_client=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    _send_message(
        campfire_id,
        json.dumps({"content": "What are my findings?"}),
        tags=["chat", f"session:{session_id}", "platform:campfire"],
    )

    async def run_one_poll():
        messages = await dispatcher._read_new_messages()
        for msg in messages:
            with patch("mallcop.chat.chat_turn", new=AsyncMock(return_value={
                "response": "You have 3 open findings.",
                "tokens_used": 42,
            })):
                await dispatcher._dispatch_message(msg)

    asyncio.run(run_one_poll())

    all_msgs = _read_all(campfire_id, tag="response")
    assert len(all_msgs) >= 1, "Expected at least 1 response message"

    response_msg = all_msgs[0]
    tags = response_msg.get("tags", [])
    assert "platform-error" not in tags, (
        f"Expected no 'platform-error' tag on normal response, got: {tags}"
    )
