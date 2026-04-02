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
        pro.api_key = "mallcop-sk-test"
        pro.endpoint = "https://mallcop.app"
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

    async def fake_daemon_loop(dispatcher, root, scan_interval):
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
