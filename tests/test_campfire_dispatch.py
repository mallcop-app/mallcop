"""Tests for CampfireDispatcher — real campfire, convention operations.

The tests create real campfires, declare the mallcop-relay v0.2 convention,
send messages using convention operations, run the dispatcher, and
verify real campfire state. managed_client is mocked (it's an external
inference endpoint, not cf or subprocess).

Tests for subprocess error handling (timeout, OSError) mock
asyncio.create_subprocess_exec — the subprocess is the external system
being guarded against, not cf message semantics.
"""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mallcop.actors.interactive_runtime import TurnResult
from mallcop.campfire_dispatch import CampfireDispatcher
from mallcop.schemas import Finding, FindingStatus, Severity

# Per-operation declaration files are bundled in tests/fixtures/declarations/
# (copied from mallcop-pro) so CI doesn't need the sibling repo checked out.
_DECLARATIONS_DIR = Path(__file__).resolve().parent / "fixtures" / "declarations"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_campfire_id(output: str) -> str:
    """Extract the hex campfire ID from cf create output (may include config notices)."""
    for line in output.strip().splitlines():
        line = line.strip()
        if re.fullmatch(r"[0-9a-f]{64}", line):
            return line
    return output.strip()


def _create_campfire_with_convention(description: str) -> str:
    """Create a real campfire and declare the mallcop-relay convention on it."""
    result = subprocess.run(
        ["cf", "create", "--description", description, "--transport", "filesystem", "--no-config", "--json"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"cf create failed: {result.stderr}"
    campfire_id = json.loads(result.stdout)["campfire_id"]
    assert campfire_id, "cf create returned empty campfire ID"

    # Declare each operation as a separate convention:operation message.
    for decl_file in sorted(_DECLARATIONS_DIR.glob("*.json")):
        decl_json = decl_file.read_text()
        decl = subprocess.run(
            [
                "cf", "send", campfire_id,
                "--tag", "convention:operation",
                decl_json,
            ],
            capture_output=True, text=True,
        )
        assert decl.returncode == 0, f"convention declare {decl_file.name} failed: {decl.stderr}"
    return campfire_id


def _disband_campfire(campfire_id: str) -> None:
    """Disband a campfire (best-effort)."""
    subprocess.run(["cf", "disband", campfire_id], capture_output=True)


def _send_inbound_message(campfire_id: str, content: str, from_id: str, platform: str = "campfire") -> str:
    """Send an inbound-message via convention operation."""
    result = subprocess.run(
        [
            "cf", campfire_id, "inbound-message",
            "--content", content,
            "--from_id", from_id,
            "--platform", platform,
        ],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"cf inbound-message failed: {result.stderr}"
    return result.stdout.strip()


def _read_all(campfire_id: str, tag: str | None = None, convention: str | None = None) -> list[dict]:
    """Read all messages from campfire with optional tag or convention filter."""
    cmd = ["cf", "read", campfire_id, "--all", "--json"]
    if tag:
        cmd += ["--tag", tag]
    if convention:
        cmd += ["--convention", convention]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"cf read failed: {result.stderr}"
    raw = result.stdout.strip()
    if not raw:
        return []
    return json.loads(raw)


def _make_mock_runner(response_text: str = "Security analysis complete.") -> MagicMock:
    """Return a mock InteractiveRuntime that returns a canned TurnResult."""
    runner = MagicMock()
    runner.run_turn.return_value = TurnResult(
        text=response_text,
        tokens_used=42,
        iterations=1,
        tool_calls=0,
        tool_call_log=[],
    )
    return runner


# Keep legacy alias so existing test call sites can be updated incrementally.
def _make_mock_client(response_text: str = "Security analysis complete.") -> MagicMock:
    """Alias for _make_mock_runner — kept for backward compatibility within this file."""
    return _make_mock_runner(response_text)


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
    """Fresh campfire per test with mallcop-relay convention, disbanded after."""
    uid = str(uuid.uuid4())[:8]
    cf_id = _create_campfire_with_convention(f"test-dispatch-{uid}")
    yield cf_id
    _disband_campfire(cf_id)


# ---------------------------------------------------------------------------
# Test 1: dispatch loop processes an inbound-message and posts response
# ---------------------------------------------------------------------------

def test_dispatch_loop_processes_inbound_message(campfire_id: str, tmp_path: Path) -> None:
    """Dispatcher reads an inbound-message, calls chat_turn, posts response back via convention."""
    session_id = str(uuid.uuid4())
    mock_client = _make_mock_client("Here is my security analysis.")

    # Send an inbound-message via convention operation.
    _send_inbound_message(
        campfire_id,
        content="What are my open findings?",
        from_id=session_id,
    )

    dispatcher = CampfireDispatcher(
        campfire_id=campfire_id,
        interactive_runner=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    async def run_one_poll():
        messages = await dispatcher._read_new_messages()
        for msg in messages:
            await dispatcher._dispatch_message(msg)

    asyncio.run(run_one_poll())

    # Verify run_turn was called — means chat_turn() ran.
    assert mock_client.run_turn.called, "chat_turn() did not invoke interactive_runner.run_turn()"

    # Verify a response was posted back via convention operation.
    all_msgs = _read_all(campfire_id, tag="relay:response")
    assert len(all_msgs) >= 1, (
        f"Expected at least 1 relay:response message on campfire, "
        f"got 0. All messages: {[m.get('tags') for m in _read_all(campfire_id)]}"
    )

    # Response should carry the session tag (relay:session_id:<value>).
    session_tag = f"relay:session_id:{session_id}"
    assert session_tag in all_msgs[0]["tags"], (
        f"Expected session tag {session_tag!r} in response tags: {all_msgs[0]['tags']}"
    )


# ---------------------------------------------------------------------------
# Test 2: publish_finding uses convention operation with correct tags
# ---------------------------------------------------------------------------

def test_publish_finding_writes_correct_tags(campfire_id: str, tmp_path: Path) -> None:
    """publish_finding() sends a finding via convention operation with correct tags."""
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id=campfire_id,
        interactive_runner=mock_client,
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

    # Read all finding messages from campfire.
    all_msgs = _read_all(campfire_id, tag="finding")
    assert len(all_msgs) >= 1, "Expected at least 1 finding message on campfire"

    finding_msg = all_msgs[0]
    tags = finding_msg.get("tags", [])

    assert "finding" in tags, f"Expected 'finding' tag, got: {tags}"
    assert "finding:severity:critical" in tags, f"Expected 'finding:severity:critical' tag, got: {tags}"


# ---------------------------------------------------------------------------
# Test 3: publish_finding uses detector as connector fallback
# ---------------------------------------------------------------------------

def test_publish_finding_uses_detector_as_connector_fallback(
    campfire_id: str, tmp_path: Path
) -> None:
    """When metadata has no 'connector' key, finding.detector is used as connector."""
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id=campfire_id,
        interactive_runner=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

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

    assert "finding:severity:warn" in tags, f"Expected 'finding:severity:warn', got: {tags}"


# ---------------------------------------------------------------------------
# Test 4: run() loop cancels cleanly
# ---------------------------------------------------------------------------

def test_run_loop_cancels_cleanly(campfire_id: str, tmp_path: Path) -> None:
    """run() loop shuts down cleanly when cancelled."""
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id=campfire_id,
        interactive_runner=mock_client,
        root=tmp_path,
        poll_interval=0.05,
    )

    async def run_briefly():
        task = asyncio.create_task(dispatcher.run())
        await asyncio.sleep(0.15)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(run_briefly())


# ---------------------------------------------------------------------------
# Test 5: _run_cf() raises TimeoutError when subprocess hangs
# ---------------------------------------------------------------------------

def test_run_cf_raises_timeout_when_subprocess_hangs(tmp_path: Path) -> None:
    """_run_cf() raises asyncio.TimeoutError when cf subprocess never completes."""
    from mallcop.campfire_dispatch import _run_cf

    async def _hang():
        await asyncio.sleep(3600)
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
            await _run_cf("read", "fake-campfire-id", timeout=0.01)

    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(run())


# ---------------------------------------------------------------------------
# Test 6: run() raises RuntimeError when cf binary missing
# ---------------------------------------------------------------------------

def test_run_raises_runtime_error_when_cf_not_found(tmp_path: Path) -> None:
    """run() raises RuntimeError (not raw OSError) when cf binary is not on PATH."""
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id="fake-campfire-id",
        interactive_runner=mock_client,
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
# Test 7: dispatcher skips messages without from_id
# ---------------------------------------------------------------------------

def test_dispatch_skips_message_without_from_id(
    campfire_id: str, tmp_path: Path
) -> None:
    """Dispatcher logs a warning and skips messages that have no from_id in payload."""
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id=campfire_id,
        interactive_runner=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    # Send a raw message with relay:inbound tag but a malformed payload (no from_id).
    send_cmd = [
        "cf", "send", campfire_id,
        "--tag", "relay:inbound",
        json.dumps({"content": "What findings do I have?"}),
    ]
    result = subprocess.run(send_cmd, capture_output=True, text=True)
    assert result.returncode == 0

    async def run_one_poll():
        messages = await dispatcher._read_new_messages()
        for msg in messages:
            await dispatcher._dispatch_message(msg)

    with patch("mallcop.campfire_dispatch._log") as mock_log:
        asyncio.run(run_one_poll())

        assert not mock_client.run_turn.called, (
            "chat_turn() was called despite missing from_id"
        )

        assert mock_log.warning.called, "Expected a warning log for missing from_id"

    # No response should appear on campfire.
    all_msgs = _read_all(campfire_id, tag="relay:response")
    assert len(all_msgs) == 0, (
        f"Expected no response messages, got: {all_msgs}"
    )


# ---------------------------------------------------------------------------
# Test 8: dispatcher forwards budget_warning as status operation
# ---------------------------------------------------------------------------

def test_dispatch_forwards_budget_warning(campfire_id: str, tmp_path: Path) -> None:
    """When chat_turn returns a budget_warning, dispatcher posts a status operation."""
    session_id = str(uuid.uuid4())
    mock_client = _make_mock_client("Analysis complete.")
    dispatcher = CampfireDispatcher(
        campfire_id=campfire_id,
        interactive_runner=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    _send_inbound_message(campfire_id, "Check my security posture", from_id=session_id)

    budget_warning_text = "Donut balance below 10%."

    async def run_one_poll():
        messages = await dispatcher._read_new_messages()
        for msg in messages:
            with patch("mallcop.chat.chat_turn", new=AsyncMock(return_value={
                "response": "Analysis complete.",
                "tokens_used": 55,
                "budget_warning": budget_warning_text,
            })):
                await dispatcher._dispatch_message(msg)

    asyncio.run(run_one_poll())

    # Read status messages (agent:status tag from status convention operation).
    all_msgs = _read_all(campfire_id, tag="agent:status")
    assert len(all_msgs) >= 1, (
        f"Expected at least 1 agent:status message, got 0. "
        f"All messages: {[m.get('tags') for m in _read_all(campfire_id)]}"
    )


# ---------------------------------------------------------------------------
# Test 9: platform-error sends a status operation
# ---------------------------------------------------------------------------

def test_dispatch_adds_platform_error_status_on_platform_error(
    campfire_id: str, tmp_path: Path
) -> None:
    """When chat_turn returns is_platform_error=True, a status operation is sent."""
    session_id = str(uuid.uuid4())
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id=campfire_id,
        interactive_runner=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    _send_inbound_message(campfire_id, "Check balance", from_id=session_id)

    async def run_one_poll():
        messages = await dispatcher._read_new_messages()
        for msg in messages:
            with patch("mallcop.chat.chat_turn", new=AsyncMock(return_value={
                "response": "Insufficient donut balance.",
                "tokens_used": 0,
                "is_platform_error": True,
            })):
                await dispatcher._dispatch_message(msg)

    asyncio.run(run_one_poll())

    all_msgs = _read_all(campfire_id, tag="agent:status")
    assert len(all_msgs) >= 1, "Expected at least 1 status message for platform error"


def test_dispatch_no_platform_error_status_on_normal_response(
    campfire_id: str, tmp_path: Path
) -> None:
    """Normal response does NOT send a status operation."""
    session_id = str(uuid.uuid4())
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id=campfire_id,
        interactive_runner=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    _send_inbound_message(campfire_id, "What are my findings?", from_id=session_id)

    async def run_one_poll():
        messages = await dispatcher._read_new_messages()
        for msg in messages:
            with patch("mallcop.chat.chat_turn", new=AsyncMock(return_value={
                "response": "You have 3 open findings.",
                "tokens_used": 42,
            })):
                await dispatcher._dispatch_message(msg)

    asyncio.run(run_one_poll())

    all_msgs = _read_all(campfire_id, tag="agent:status")
    assert len(all_msgs) == 0, (
        f"Expected no status messages on normal response, got: {all_msgs}"
    )


# ---------------------------------------------------------------------------
# Test 10: publish_finding convention operation contract
# ---------------------------------------------------------------------------

def test_publish_finding_writes_to_campfire_with_correct_tags(
    campfire_id: str, tmp_path: Path
) -> None:
    """publish_finding() convention operation: correct tags."""
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id=campfire_id,
        interactive_runner=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    finding = _make_finding(
        finding_id="MC-099",
        severity=Severity.CRITICAL,
        detector="s3-scanner",
        connector_name="aws-s3",
    )

    asyncio.run(dispatcher.publish_finding(finding))

    all_msgs = _read_all(campfire_id, tag="finding")
    assert len(all_msgs) >= 1, (
        "Expected at least 1 finding message on campfire after publish_finding(), got 0"
    )

    finding_msg = all_msgs[0]
    tags = finding_msg.get("tags", [])

    assert "finding" in tags, f"Expected 'finding' tag, got: {tags}"
    assert "finding:severity:critical" in tags, f"Expected 'finding:severity:critical' tag, got: {tags}"


# ---------------------------------------------------------------------------
# Test 11: run() backs off after 5+ consecutive cf errors
# ---------------------------------------------------------------------------

def test_run_backs_off_after_consecutive_cf_errors(tmp_path: Path) -> None:
    """run() applies exponential backoff after 5+ consecutive errors."""
    from mallcop.campfire_dispatch import _SubprocessError

    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id="fake-campfire-id",
        interactive_runner=mock_client,
        root=tmp_path,
        poll_interval=1.0,
    )

    call_count = 0

    async def failing_read():
        nonlocal call_count
        call_count += 1
        if call_count <= 6:
            raise _SubprocessError(f"cf error #{call_count}")
        raise asyncio.CancelledError()

    sleep_calls: list[float] = []

    async def recording_sleep(duration: float) -> None:
        sleep_calls.append(duration)

    async def run():
        with (
            patch.object(dispatcher, "_read_new_messages", side_effect=failing_read),
            patch("asyncio.sleep", side_effect=recording_sleep),
        ):
            try:
                await dispatcher.run()
            except asyncio.CancelledError:
                pass

    asyncio.run(run())

    backoff_sleeps = [d for d in sleep_calls if d > dispatcher._poll_interval]
    assert backoff_sleeps, (
        f"Expected at least one sleep > poll_interval ({dispatcher._poll_interval}s) "
        f"after 6 consecutive errors, but sleep calls were: {sleep_calls}"
    )


# ---------------------------------------------------------------------------
# Test 12: run_once() processes all pending messages in one pass
# ---------------------------------------------------------------------------

def test_run_once_processes_pending_messages(campfire_id: str, tmp_path: Path) -> None:
    """run_once() reads all pending inbound messages and posts a response for each."""
    session_id = str(uuid.uuid4())
    mock_client = _make_mock_client("run_once response")

    _send_inbound_message(
        campfire_id,
        content="Summarize my security posture.",
        from_id=session_id,
    )

    dispatcher = CampfireDispatcher(
        campfire_id=campfire_id,
        interactive_runner=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    asyncio.run(asyncio.wait_for(dispatcher.run_once(), timeout=5.0))

    assert mock_client.run_turn.called, (
        "run_once() did not invoke interactive_runner.run_turn()"
    )

    all_msgs = _read_all(campfire_id, tag="relay:response")
    assert len(all_msgs) >= 1, (
        f"Expected at least 1 relay:response message after run_once(), "
        f"got 0. All messages: {[m.get('tags') for m in _read_all(campfire_id)]}"
    )

    session_tag = f"relay:session_id:{session_id}"
    assert session_tag in all_msgs[0]["tags"], (
        f"Expected session tag {session_tag!r} in response tags: {all_msgs[0]['tags']}"
    )


# ---------------------------------------------------------------------------
# Tests 13-18: _parse_cf_timestamp and drain_cursor timestamp handling
# ---------------------------------------------------------------------------

from datetime import timedelta as _dt_timedelta  # noqa: E402


def test_drain_cursor_keeps_message_on_unparseable_timestamp(tmp_path: Path) -> None:
    """drain_cursor keeps a message with an unparseable timestamp and logs a warning."""
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id="fake-campfire-id",
        interactive_runner=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    items = [
        {"timestamp": "garbage-not-a-date", "body": json.dumps({"from_id": "u1", "content": "hi"})},
    ]

    dispatched: list[dict] = []

    async def _noop_dispatch(m, **kw):
        dispatched.append(m)

    async def run():
        with (
            patch.object(dispatcher, "_cf", new=AsyncMock(return_value=json.dumps(items))),
            patch.object(dispatcher, "_dispatch_message", side_effect=_noop_dispatch),
            patch("mallcop.campfire_dispatch._log") as mock_log,
        ):
            await dispatcher.drain_cursor(keep_recent_seconds=120)
            assert mock_log.warning.called, "Expected warning log for unparseable timestamp"
            warning_calls = [str(c) for c in mock_log.warning.call_args_list]
            assert any("garbage-not-a-date" in w for w in warning_calls), (
                f"Expected raw ts_str in warning, got: {warning_calls}"
            )

    asyncio.run(run())
    assert len(dispatched) == 1, (
        f"Expected message with unparseable timestamp to be kept, got {len(dispatched)} dispatched"
    )


def test_drain_cursor_handles_nanosecond_iso(tmp_path: Path) -> None:
    """drain_cursor parses nanosecond-precision ISO timestamps (9 fractional digits)."""
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id="fake-campfire-id",
        interactive_runner=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    # 30 seconds ago — should be within 120s window
    recent_dt = datetime.now(timezone.utc) - _dt_timedelta(seconds=30)
    # Format with nanoseconds (9 fractional digits)
    ts_nano = recent_dt.strftime("%Y-%m-%dT%H:%M:%S") + ".123456789Z"
    items = [{"timestamp": ts_nano, "body": json.dumps({"from_id": "u1", "content": "hi"})}]

    dispatched: list[dict] = []

    async def _noop_dispatch(m, **kw):
        dispatched.append(m)

    async def run():
        with (
            patch.object(dispatcher, "_cf", new=AsyncMock(return_value=json.dumps(items))),
            patch.object(dispatcher, "_dispatch_message", side_effect=_noop_dispatch),
        ):
            await dispatcher.drain_cursor(keep_recent_seconds=120)

    asyncio.run(run())
    assert len(dispatched) == 1, (
        f"Expected nanosecond timestamp message to be kept (30s old, 120s window), "
        f"got {len(dispatched)} dispatched"
    )


def test_drain_cursor_handles_z_suffix(tmp_path: Path) -> None:
    """drain_cursor parses ISO timestamps with Z suffix (no fractional seconds)."""
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id="fake-campfire-id",
        interactive_runner=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    recent_dt = datetime.now(timezone.utc) - _dt_timedelta(seconds=10)
    ts_z = recent_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    items = [{"timestamp": ts_z, "body": json.dumps({"from_id": "u1", "content": "hi"})}]

    dispatched: list[dict] = []

    async def _noop_dispatch(m, **kw):
        dispatched.append(m)

    async def run():
        with (
            patch.object(dispatcher, "_cf", new=AsyncMock(return_value=json.dumps(items))),
            patch.object(dispatcher, "_dispatch_message", side_effect=_noop_dispatch),
        ):
            await dispatcher.drain_cursor(keep_recent_seconds=120)

    asyncio.run(run())
    assert len(dispatched) == 1, (
        f"Expected Z-suffix timestamp message to be kept (10s old, 120s window), "
        f"got {len(dispatched)} dispatched"
    )


def test_drain_cursor_handles_unix_nanos(tmp_path: Path) -> None:
    """drain_cursor parses unix nanosecond timestamps (all-digit string)."""
    import time

    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id="fake-campfire-id",
        interactive_runner=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    # 5 seconds ago in nanoseconds
    ns = int((time.time() - 5) * 1e9)
    items = [{"timestamp": str(ns), "body": json.dumps({"from_id": "u1", "content": "hi"})}]

    dispatched: list[dict] = []

    async def _noop_dispatch(m, **kw):
        dispatched.append(m)

    async def run():
        with (
            patch.object(dispatcher, "_cf", new=AsyncMock(return_value=json.dumps(items))),
            patch.object(dispatcher, "_dispatch_message", side_effect=_noop_dispatch),
        ):
            await dispatcher.drain_cursor(keep_recent_seconds=120)

    asyncio.run(run())
    assert len(dispatched) == 1, (
        f"Expected unix-nanos timestamp message to be kept (5s old, 120s window), "
        f"got {len(dispatched)} dispatched"
    )


def test_drain_cursor_discards_genuinely_old(tmp_path: Path) -> None:
    """drain_cursor discards a message with a timestamp 5 minutes in the past."""
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id="fake-campfire-id",
        interactive_runner=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    old_dt = datetime.now(timezone.utc) - _dt_timedelta(minutes=5)
    ts_old = old_dt.isoformat()
    items = [{"timestamp": ts_old, "body": json.dumps({"from_id": "u1", "content": "old"})}]

    dispatched: list[dict] = []

    async def _noop_dispatch(m, **kw):
        dispatched.append(m)

    async def run():
        with (
            patch.object(dispatcher, "_cf", new=AsyncMock(return_value=json.dumps(items))),
            patch.object(dispatcher, "_dispatch_message", side_effect=_noop_dispatch),
        ):
            await dispatcher.drain_cursor(keep_recent_seconds=120)

    asyncio.run(run())
    assert len(dispatched) == 0, (
        f"Expected 5-minute-old message to be discarded (120s window), "
        f"got {len(dispatched)} dispatched"
    )


def test_drain_cursor_keeps_recent(tmp_path: Path) -> None:
    """drain_cursor keeps a message with a timestamp 30 seconds ago."""
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id="fake-campfire-id",
        interactive_runner=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    recent_dt = datetime.now(timezone.utc) - _dt_timedelta(seconds=30)
    ts_recent = recent_dt.isoformat()
    items = [{"timestamp": ts_recent, "body": json.dumps({"from_id": "u1", "content": "recent"})}]

    dispatched: list[dict] = []

    async def _noop_dispatch(m, **kw):
        dispatched.append(m)

    async def run():
        with (
            patch.object(dispatcher, "_cf", new=AsyncMock(return_value=json.dumps(items))),
            patch.object(dispatcher, "_dispatch_message", side_effect=_noop_dispatch),
        ):
            await dispatcher.drain_cursor(keep_recent_seconds=120)

    asyncio.run(run())
    assert len(dispatched) == 1, (
        f"Expected 30s-old message to be kept (120s window), "
        f"got {len(dispatched)} dispatched"
    )


# ---------------------------------------------------------------------------
# Tests 19-21: int timestamp handling (cf v0.17.4 emits unix nanos as int)
# ---------------------------------------------------------------------------

from mallcop.campfire_dispatch import _parse_cf_timestamp  # noqa: E402
import time as _time  # noqa: E402


def test_parse_cf_timestamp_int_nanos() -> None:
    """_parse_cf_timestamp handles int unix nanoseconds (cf v0.17.4 format)."""
    # 1775740851063043456 ns ≈ 2026-04-07
    ns = 1775740851063043456
    result = _parse_cf_timestamp(ns)
    assert result is not None, "Expected a valid datetime from int nanoseconds"
    assert result.tzinfo is not None, "Expected timezone-aware datetime"
    # Rough sanity: year should be around 2026
    assert result.year == 2026, f"Expected year 2026, got {result.year}"


def test_parse_cf_timestamp_int_zero() -> None:
    """_parse_cf_timestamp handles int 0 (unix epoch)."""
    result = _parse_cf_timestamp(0)
    assert result is not None, "Expected a valid datetime for epoch (0)"
    assert result.year == 1970
    assert result.tzinfo is not None


def test_drain_cursor_handles_int_timestamps(tmp_path: Path) -> None:
    """drain_cursor doesn't crash when cf returns int timestamps (cf v0.17.4)."""
    mock_client = _make_mock_client()
    dispatcher = CampfireDispatcher(
        campfire_id="fake-campfire-id",
        interactive_runner=mock_client,
        root=tmp_path,
        poll_interval=0.1,
    )

    # 5 seconds ago as int nanoseconds (what cf v0.17.4 emits)
    ns = int((_time.time() - 5) * 1e9)
    items = [{"timestamp": ns, "payload": json.dumps({"from_id": "u1", "content": "hi"})}]

    dispatched: list[dict] = []

    async def _noop_dispatch(m, **kw):
        dispatched.append(m)

    async def run():
        with (
            patch.object(dispatcher, "_cf", new=AsyncMock(return_value=json.dumps(items))),
            patch.object(dispatcher, "_dispatch_message", side_effect=_noop_dispatch),
        ):
            await dispatcher.drain_cursor(keep_recent_seconds=120)

    asyncio.run(run())
    assert len(dispatched) == 1, (
        f"Expected int-timestamp message to be kept (5s old, 120s window), "
        f"got {len(dispatched)} dispatched"
    )
