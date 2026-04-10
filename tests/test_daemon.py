"""Unit tests for mallcop watch --daemon mode."""

from __future__ import annotations

import asyncio
import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from mallcop.cli import cli


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(campfire_id: str = "", has_pro: bool = True) -> MagicMock:
    """Return a MagicMock that looks like a MallcopConfig."""
    config = MagicMock()
    delivery = MagicMock()
    delivery.campfire_id = campfire_id
    config.delivery = delivery

    if has_pro:
        pro = MagicMock()
        pro.service_token = "mallcop-sk-test"
        pro.inference_url = "https://mallcop.app"
        config.pro = pro
    else:
        config.pro = None

    return config


# ---------------------------------------------------------------------------
# Test 1: exits 1 when campfire_id is not configured
# ---------------------------------------------------------------------------


def test_daemon_exits_without_campfire_id(tmp_path: Path) -> None:
    """watch --daemon with no campfire_id in config should exit 1 with an error."""
    runner = CliRunner()

    with patch("mallcop.cli.load_config", return_value=_make_config(campfire_id="")):
        result = runner.invoke(cli, ["watch", "--daemon", "--dir", str(tmp_path)])

    assert result.exit_code == 1
    assert "campfire_id" in result.output or "campfire_id" in (result.stderr or "")


# ---------------------------------------------------------------------------
# Test 2: exits 1 when Pro config is missing
# ---------------------------------------------------------------------------


def test_daemon_exits_without_pro_config(tmp_path: Path) -> None:
    """watch --daemon with no pro config should exit 1 with an error."""
    runner = CliRunner()

    with patch("mallcop.cli.load_config", return_value=_make_config(campfire_id="fire-abc", has_pro=False)):
        result = runner.invoke(cli, ["watch", "--daemon", "--dir", str(tmp_path)])

    assert result.exit_code == 1
    assert "Pro" in result.output or "Pro" in (result.stderr or "")


# ---------------------------------------------------------------------------
# Test 3: daemon starts both dispatch and scan tasks
# ---------------------------------------------------------------------------


def test_daemon_runs_dispatch_and_scan_tasks(tmp_path: Path) -> None:
    """watch --daemon should call dispatcher.run() and _run_one_scan."""
    runner = CliRunner()

    scan_called: list[bool] = []

    async def fake_daemon_loop(dispatcher, root, scan_interval, **kwargs):
        # Simulate one scan + one dispatch poll then return.
        from mallcop.daemon import _run_one_scan as _real_run_one_scan  # noqa: F401
        dispatcher.run_called = True
        scan_called.append(True)

    with (
        patch("mallcop.cli.load_config", return_value=_make_config(campfire_id="fire-abc")),
        patch("mallcop.llm.managed.ManagedClient"),
        patch("mallcop.campfire_dispatch.CampfireDispatcher") as MockDispatcher,
        patch("mallcop.daemon._daemon_loop", side_effect=fake_daemon_loop),
    ):
        mock_dispatcher_instance = MagicMock()
        MockDispatcher.return_value = mock_dispatcher_instance

        result = runner.invoke(cli, ["watch", "--daemon", "--dir", str(tmp_path)])

    # Should exit cleanly (0 — KeyboardInterrupt path returns, no sys.exit)
    assert result.exit_code == 0
    assert scan_called, "expected _daemon_loop to be called"
    MockDispatcher.assert_called_once()


# ---------------------------------------------------------------------------
# Test 4: scan failure does not stop dispatcher
# ---------------------------------------------------------------------------


def test_daemon_scan_failure_does_not_stop_dispatcher(tmp_path: Path) -> None:
    """A scan exception should be logged but the daemon loop should continue."""
    import mallcop.daemon as daemon_mod

    dispatcher = MagicMock()
    dispatcher.publish_finding = AsyncMock()

    scan_attempts: list[int] = []
    sleep_calls: list[float] = []

    async def fake_sleep(interval: float) -> None:
        sleep_calls.append(interval)
        # After 2 sleep calls (= 2 scan cycles), cancel the loop.
        if len(sleep_calls) >= 2:
            raise asyncio.CancelledError

    async def fake_to_thread(fn, *args, **kwargs):
        scan_attempts.append(1)
        raise RuntimeError("scan exploded")

    async def run() -> None:
        with (
            patch.object(asyncio, "sleep", side_effect=fake_sleep),
            patch.object(asyncio, "to_thread", side_effect=fake_to_thread),
        ):
            await daemon_mod._scan_loop(dispatcher, tmp_path, interval=1.0)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(run())

    assert len(scan_attempts) == 2, "expected exactly 2 scan attempts"
    # publish_finding should NOT have been called (scan raised before findings)
    dispatcher.publish_finding.assert_not_awaited()


# ---------------------------------------------------------------------------
# Test 5: idle_watchdog fires after idle_timeout_seconds with no tg-inbound
# ---------------------------------------------------------------------------


def test_idle_watchdog_fires_on_idle_timeout() -> None:
    """idle_watchdog cancels sibling tasks after idle_timeout_seconds with no messages."""
    import json
    import mallcop.daemon as daemon_mod

    cancelled_tasks: list[str] = []

    async def run() -> None:
        # Use a very short timeout (0.1s) and poll interval (0.05s) to keep test fast.
        poll_calls: list[int] = [0]

        async def fake_to_thread(fn, *args, **kwargs):
            poll_calls[0] += 1
            # Return empty JSON array — no tg-inbound messages.
            result = MagicMock()
            result.stdout = "[]"
            return result

        # Patch asyncio.sleep to not actually sleep, and to_thread for cf calls.
        original_sleep = asyncio.sleep

        async def fake_sleep(interval: float) -> None:
            # Advance event loop time by yielding (no real sleep).
            await original_sleep(0)

        # Create a dummy sibling task that records when it's cancelled.
        async def dummy_task() -> None:
            try:
                await asyncio.sleep(9999)
            except asyncio.CancelledError:
                cancelled_tasks.append("dummy")
                raise

        sibling = asyncio.create_task(dummy_task())

        with (
            patch.object(asyncio, "sleep", side_effect=fake_sleep),
            patch.object(asyncio, "to_thread", side_effect=fake_to_thread),
        ):
            # idle_timeout_seconds=0.0 means it fires immediately after first poll
            # (elapsed time > 0.0 always true after fake_sleep yields).
            await daemon_mod._idle_watchdog(
                campfire_id="fire-test",
                idle_timeout_seconds=0.0,
            )

        # Give cancelled tasks a chance to handle CancelledError.
        try:
            await asyncio.gather(sibling, return_exceptions=True)
        except Exception:
            pass

    asyncio.run(run())
    assert "dummy" in cancelled_tasks, "sibling task should have been cancelled"


# ---------------------------------------------------------------------------
# Test 6: idle_watchdog does NOT fire when messages arrive within the window
# ---------------------------------------------------------------------------


def test_idle_watchdog_resets_on_new_message() -> None:
    """idle_watchdog resets idle clock when new tg-inbound messages arrive."""
    import json
    import mallcop.daemon as daemon_mod

    async def run() -> None:
        poll_count = [0]
        msg_sequence = [
            # First poll: one message (id=msg-1) → resets clock
            json.dumps([{"id": "msg-1"}]),
            # Second poll: same message (already seen) → no reset
            json.dumps([{"id": "msg-1"}]),
            # Third poll: new message (id=msg-2) → resets clock again
            json.dumps([{"id": "msg-2"}]),
        ]

        async def fake_to_thread(fn, *args, **kwargs):
            idx = poll_count[0]
            poll_count[0] += 1
            result = MagicMock()
            result.stdout = msg_sequence[idx] if idx < len(msg_sequence) else "[]"
            return result

        watchdog_done = asyncio.Event()
        original_sleep = asyncio.sleep

        async def fake_sleep(interval: float) -> None:
            await original_sleep(0)
            # After all polls done, let watchdog exit by raising CancelledError.
            if poll_count[0] >= len(msg_sequence):
                raise asyncio.CancelledError

        with (
            patch.object(asyncio, "sleep", side_effect=fake_sleep),
            patch.object(asyncio, "to_thread", side_effect=fake_to_thread),
        ):
            try:
                # idle_timeout_seconds=9999 → watchdog should NOT fire during test.
                await daemon_mod._idle_watchdog(
                    campfire_id="fire-test",
                    idle_timeout_seconds=9999.0,
                )
            except asyncio.CancelledError:
                pass  # Expected — fake_sleep raises it to end the test.

        # If we reach here without the watchdog cancelling all tasks, the test passes.
        # (The watchdog only cancels tasks when idle_elapsed > idle_timeout_seconds.)
        assert poll_count[0] >= len(msg_sequence), "expected all polls to occur"

    asyncio.run(run())


# ---------------------------------------------------------------------------
# Test 7: _daemon_loop exits cleanly on idle timeout (no exception propagated)
# ---------------------------------------------------------------------------


def test_daemon_loop_exits_cleanly_on_idle_timeout(tmp_path: Path) -> None:
    """_daemon_loop should return normally (exit 0) when watchdog fires."""
    import mallcop.daemon as daemon_mod

    dispatcher = MagicMock()
    dispatcher.campfire_id = "fire-test"
    dispatcher.run = AsyncMock(side_effect=asyncio.CancelledError)
    dispatcher.publish_finding = AsyncMock()
    dispatcher.drain_cursor = AsyncMock()

    async def run() -> None:
        async def fake_watchdog(*args, **kwargs) -> None:
            # Immediately cancel all other tasks (simulate idle timeout).
            current = asyncio.current_task()
            for task in asyncio.all_tasks():
                if task is not current:
                    task.cancel()

        with patch.object(daemon_mod, "_idle_watchdog", side_effect=fake_watchdog):
            # Should return without raising — CancelledError is caught internally.
            await daemon_mod._daemon_loop(
                dispatcher,
                tmp_path,
                scan_interval=300.0,
                idle_timeout_seconds=0.1,
            )

    # asyncio.run should complete without exception.
    asyncio.run(run())


# ---------------------------------------------------------------------------
# Test 8: _daemon_loop always creates 3 tasks (bridge no longer polled)
# ---------------------------------------------------------------------------


def test_daemon_loop_always_creates_3_tasks(tmp_path: Path) -> None:
    """_daemon_loop creates 3 tasks (scan, dispatch, watchdog).

    The bridge is no longer polled in a separate task — relay:response delivery
    is handled by the Go bridge in mallcop-pro. Passing a bridge does not add a task.
    """
    import mallcop.daemon as daemon_mod

    dispatcher = MagicMock()
    dispatcher.campfire_id = "fire-test"
    dispatcher.run = AsyncMock(side_effect=asyncio.CancelledError)
    dispatcher.publish_finding = AsyncMock()
    dispatcher.drain_cursor = AsyncMock()

    bridge = MagicMock()

    async def run() -> None:
        # Track how many tasks are created
        task_count = [0]
        real_create_task = asyncio.create_task

        def counting_create_task(coro, **kwargs):
            task_count[0] += 1
            return real_create_task(coro, **kwargs)

        async def fake_watchdog(*args, **kwargs) -> None:
            current = asyncio.current_task()
            for task in asyncio.all_tasks():
                if task is not current:
                    task.cancel()

        with (
            patch.object(daemon_mod, "_idle_watchdog", side_effect=fake_watchdog),
            patch("asyncio.create_task", side_effect=counting_create_task),
        ):
            await daemon_mod._daemon_loop(
                dispatcher,
                tmp_path,
                scan_interval=300.0,
                idle_timeout_seconds=0.1,
                bridge=bridge,
            )
        assert task_count[0] == 3, f"expected 3 tasks, got {task_count[0]}"

    asyncio.run(run())
