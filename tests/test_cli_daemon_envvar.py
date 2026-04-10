"""Tests for daemon env-var config path (container mode)."""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from click.testing import CliRunner
from mallcop.cli import cli


def test_daemon_envvar_creates_bridge_when_inbound_mode(tmp_path: Path) -> None:
    """Container mode with MALLCOP_INBOUND_MODE=campfire should create bridge."""
    runner = CliRunner()
    env = {
        'MALLCOP_CAMPFIRE_ID': 'fire-abc',
        'MALLCOP_PRO_SERVICE_TOKEN': 'mallcop-sk-test',
        'MALLCOP_PRO_INFERENCE_URL': 'https://mallcop.app',
        'MALLCOP_TELEGRAM_BOT_TOKEN': 'bot123',
        'MALLCOP_TELEGRAM_CHAT_ID': '456',
        'MALLCOP_INBOUND_MODE': 'campfire',
    }

    daemon_loop_args = {}

    async def capture_daemon_loop(dispatcher, root, scan_interval, **kwargs):
        daemon_loop_args.update(kwargs)
        daemon_loop_args['dispatcher'] = dispatcher

    with (
        patch.dict('os.environ', env),
        patch('mallcop.llm.managed.ManagedClient') as MockMC,
        patch('mallcop.campfire_dispatch.CampfireDispatcher') as MockCD,
        patch('mallcop.telegram_bridge.TelegramCampfireBridge') as MockBridge,
        patch('mallcop.daemon._daemon_loop', side_effect=capture_daemon_loop),
    ):
        result = runner.invoke(cli, ['watch', '--daemon', '--dir', str(tmp_path)])

    assert result.exit_code == 0
    MockMC.assert_called_once()
    MockCD.assert_called_once()
    MockBridge.assert_called_once_with(
        bot_token='bot123', chat_id='456',
        campfire_id='fire-abc', inbound_mode=True,
    )
    assert daemon_loop_args.get('bridge') is not None


def test_daemon_envvar_no_bridge_without_inbound_mode(tmp_path: Path) -> None:
    """Container mode without MALLCOP_INBOUND_MODE should not create bridge."""
    runner = CliRunner()
    env = {
        'MALLCOP_CAMPFIRE_ID': 'fire-abc',
        'MALLCOP_PRO_SERVICE_TOKEN': 'mallcop-sk-test',
    }

    daemon_loop_args = {}

    async def capture_daemon_loop(dispatcher, root, scan_interval, **kwargs):
        daemon_loop_args.update(kwargs)

    with (
        patch.dict('os.environ', env),
        patch('mallcop.llm.managed.ManagedClient'),
        patch('mallcop.campfire_dispatch.CampfireDispatcher'),
        patch('mallcop.daemon._daemon_loop', side_effect=capture_daemon_loop),
    ):
        result = runner.invoke(cli, ['watch', '--daemon', '--dir', str(tmp_path)])

    assert result.exit_code == 0
    assert daemon_loop_args.get('bridge') is None


def test_daemon_envvar_falls_back_to_config(tmp_path: Path) -> None:
    """Without env vars, should fall through to load_config path."""
    runner = CliRunner()
    # No MALLCOP_CAMPFIRE_ID or MALLCOP_PRO_SERVICE_TOKEN in env
    env_clear = {
        'MALLCOP_CAMPFIRE_ID': '',
        'MALLCOP_PRO_SERVICE_TOKEN': '',
    }

    config = MagicMock()
    config.delivery.campfire_id = 'fire-from-config'
    pro = MagicMock()
    pro.service_token = 'mallcop-sk-config'
    pro.inference_url = 'https://mallcop.app'
    config.pro = pro

    async def capture_daemon_loop(dispatcher, root, scan_interval, **kwargs):
        pass

    with (
        patch.dict('os.environ', env_clear),
        patch('mallcop.cli.load_config', return_value=config),
        patch('mallcop.llm.managed.ManagedClient'),
        patch('mallcop.campfire_dispatch.CampfireDispatcher'),
        patch('mallcop.daemon._daemon_loop', side_effect=capture_daemon_loop),
    ):
        result = runner.invoke(cli, ['watch', '--daemon', '--dir', str(tmp_path)])

    assert result.exit_code == 0
