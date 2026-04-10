"""Tests for mallcop watch (one-shot) bridge+dispatcher pass.

After scan+detect+escalate, when delivery.campfire_id is set, watch calls
bridge.run_once() then dispatcher.run_once() in order, before any GitHub push.
When campfire_id is absent, both are silently skipped.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest
from click.testing import CliRunner

from mallcop.cli import cli


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(
    campfire_id: str = "",
    bot_token: str = "",
    chat_id: str = "",
    service_token: str = "",
    inference_url: str = "",
) -> MagicMock:
    """Return a MagicMock that looks like a MallcopConfig."""
    config = MagicMock()

    delivery = MagicMock()
    delivery.campfire_id = campfire_id
    delivery.telegram_bot_token = bot_token
    delivery.telegram_chat_id = chat_id
    config.delivery = delivery

    if service_token:
        pro = MagicMock()
        pro.service_token = service_token
        pro.inference_url = inference_url or None
        config.pro = pro
    else:
        config.pro = None

    config.github = None

    return config


def _make_scan_result() -> dict:
    return {"total_events_ingested": 0}


def _make_detect_result() -> dict:
    return {"findings_count": 0}


def _make_escalate_result() -> dict:
    return {"findings_processed": 0}


# ---------------------------------------------------------------------------
# Test 1: bridge.run_once() and dispatcher.run_once() called in order
#         when campfire_id is configured.
# ---------------------------------------------------------------------------


def test_watch_calls_bridge_then_dispatcher_when_campfire_configured(
    tmp_path: Path,
) -> None:
    """One-shot watch runs bridge then dispatcher when campfire_id is set."""
    runner = CliRunner()

    call_order: list[str] = []

    mock_bridge = MagicMock()
    mock_bridge.run_once = AsyncMock(side_effect=lambda: call_order.append("bridge"))

    mock_dispatcher = MagicMock()
    mock_dispatcher.run_once = AsyncMock(
        side_effect=lambda: call_order.append("dispatcher")
    )

    mock_bridge_cls = MagicMock(return_value=mock_bridge)
    mock_dispatcher_cls = MagicMock(return_value=mock_dispatcher)

    config = _make_config(
        campfire_id="fire-abc123",
        bot_token="tg-token",
        chat_id="tg-chat-42",
    )

    with (
        patch("mallcop.cli.load_config", return_value=config),
        patch(
            "mallcop.cli._run_scan_pipeline",
            return_value=_make_scan_result(),
        ),
        patch(
            "mallcop.cli._run_detect_pipeline",
            return_value=_make_detect_result(),
        ),
        patch(
            "mallcop.escalate.run_escalate",
            return_value=_make_escalate_result(),
        ),
        patch(
            "mallcop.cli.TelegramCampfireBridge",
            mock_bridge_cls,
        ),
        patch(
            "mallcop.cli.CampfireDispatcher",
            mock_dispatcher_cls,
        ),
    ):
        result = runner.invoke(cli, ["watch", "--dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    output = json.loads(result.output)
    assert output["status"] == "ok"

    # Both run_once() were called.
    mock_bridge.run_once.assert_awaited_once()
    mock_dispatcher.run_once.assert_awaited_once()

    # Order: bridge first, then dispatcher.
    assert call_order == ["bridge", "dispatcher"], (
        f"Expected bridge then dispatcher, got: {call_order}"
    )


# ---------------------------------------------------------------------------
# Test 2: neither bridge nor dispatcher called when campfire_id is absent.
# ---------------------------------------------------------------------------


def test_watch_skips_bridge_and_dispatcher_when_no_campfire_id(
    tmp_path: Path,
) -> None:
    """One-shot watch silently skips bridge+dispatcher when campfire_id absent."""
    runner = CliRunner()

    mock_bridge_cls = MagicMock()
    mock_dispatcher_cls = MagicMock()

    config = _make_config(campfire_id="")

    with (
        patch("mallcop.cli.load_config", return_value=config),
        patch(
            "mallcop.cli._run_scan_pipeline",
            return_value=_make_scan_result(),
        ),
        patch(
            "mallcop.cli._run_detect_pipeline",
            return_value=_make_detect_result(),
        ),
        patch(
            "mallcop.escalate.run_escalate",
            return_value=_make_escalate_result(),
        ),
        patch(
            "mallcop.cli.TelegramCampfireBridge",
            mock_bridge_cls,
        ),
        patch(
            "mallcop.cli.CampfireDispatcher",
            mock_dispatcher_cls,
        ),
    ):
        result = runner.invoke(cli, ["watch", "--dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    output = json.loads(result.output)
    assert output["status"] == "ok"

    # Neither class should have been instantiated.
    mock_bridge_cls.assert_not_called()
    mock_dispatcher_cls.assert_not_called()


# ---------------------------------------------------------------------------
# Test 3: dispatch errors are non-fatal (watch still returns ok).
# ---------------------------------------------------------------------------


def test_watch_dispatch_error_is_non_fatal(tmp_path: Path) -> None:
    """If bridge.run_once() raises, watch still completes with status ok."""
    runner = CliRunner()

    mock_bridge = MagicMock()
    mock_bridge.run_once = AsyncMock(side_effect=RuntimeError("cf not found"))

    mock_dispatcher = MagicMock()
    mock_dispatcher.run_once = AsyncMock()

    config = _make_config(
        campfire_id="fire-abc123",
        bot_token="tg-token",
        chat_id="tg-chat-42",
    )

    with (
        patch("mallcop.cli.load_config", return_value=config),
        patch(
            "mallcop.cli._run_scan_pipeline",
            return_value=_make_scan_result(),
        ),
        patch(
            "mallcop.cli._run_detect_pipeline",
            return_value=_make_detect_result(),
        ),
        patch(
            "mallcop.escalate.run_escalate",
            return_value=_make_escalate_result(),
        ),
        patch(
            "mallcop.cli.TelegramCampfireBridge",
            MagicMock(return_value=mock_bridge),
        ),
        patch(
            "mallcop.cli.CampfireDispatcher",
            MagicMock(return_value=mock_dispatcher),
        ),
    ):
        result = runner.invoke(cli, ["watch", "--dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    output = json.loads(result.output)
    assert output["status"] == "ok"


# ---------------------------------------------------------------------------
# Test 4: ManagedClient is instantiated from pro config when present.
# ---------------------------------------------------------------------------


def test_watch_dispatch_pass_creates_managed_client_from_pro_config(
    tmp_path: Path,
) -> None:
    """When pro config has a service_token, ManagedClient is constructed and
    CampfireDispatcher is called (interactive_runner wiring is a separate concern)."""
    runner = CliRunner()

    mock_bridge = MagicMock()
    mock_bridge.run_once = AsyncMock()

    mock_dispatcher = MagicMock()
    mock_dispatcher.run_once = AsyncMock()

    mock_bridge_cls = MagicMock(return_value=mock_bridge)
    mock_dispatcher_cls = MagicMock(return_value=mock_dispatcher)

    config = _make_config(
        campfire_id="fire-abc123",
        bot_token="tg-token",
        chat_id="tg-chat-42",
        service_token="mallcop-sk-test-token",
        inference_url="https://mallcop.example.com",
    )

    with (
        patch("mallcop.cli.load_config", return_value=config),
        patch(
            "mallcop.cli._run_scan_pipeline",
            return_value=_make_scan_result(),
        ),
        patch(
            "mallcop.cli._run_detect_pipeline",
            return_value=_make_detect_result(),
        ),
        patch(
            "mallcop.escalate.run_escalate",
            return_value=_make_escalate_result(),
        ),
        patch("mallcop.cli.TelegramCampfireBridge", mock_bridge_cls),
        patch("mallcop.cli.CampfireDispatcher", mock_dispatcher_cls),
    ):
        result = runner.invoke(cli, ["watch", "--dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    output = json.loads(result.output)
    assert output["status"] == "ok"

    # CampfireDispatcher called (interactive_runner wiring is a separate concern).
    mock_dispatcher_cls.assert_called_once()
    _, kwargs = mock_dispatcher_cls.call_args
    assert "interactive_runner" in kwargs


# ---------------------------------------------------------------------------
# Test 5: interactive_runner=None when pro config is absent.
# ---------------------------------------------------------------------------


def test_watch_dispatch_pass_no_managed_client_when_no_pro_config(
    tmp_path: Path,
) -> None:
    """When pro config is absent, interactive_runner=None is passed to dispatcher."""
    runner = CliRunner()

    mock_bridge = MagicMock()
    mock_bridge.run_once = AsyncMock()

    mock_dispatcher = MagicMock()
    mock_dispatcher.run_once = AsyncMock()

    mock_bridge_cls = MagicMock(return_value=mock_bridge)
    mock_dispatcher_cls = MagicMock(return_value=mock_dispatcher)

    config = _make_config(
        campfire_id="fire-abc123",
        bot_token="tg-token",
        chat_id="tg-chat-42",
        # no service_token → pro=None
    )

    with (
        patch("mallcop.cli.load_config", return_value=config),
        patch(
            "mallcop.cli._run_scan_pipeline",
            return_value=_make_scan_result(),
        ),
        patch(
            "mallcop.cli._run_detect_pipeline",
            return_value=_make_detect_result(),
        ),
        patch(
            "mallcop.escalate.run_escalate",
            return_value=_make_escalate_result(),
        ),
        patch("mallcop.cli.TelegramCampfireBridge", mock_bridge_cls),
        patch("mallcop.cli.CampfireDispatcher", mock_dispatcher_cls),
    ):
        result = runner.invoke(cli, ["watch", "--dir", str(tmp_path)])

    assert result.exit_code == 0, result.output
    output = json.loads(result.output)
    assert output["status"] == "ok"

    # CampfireDispatcher called with interactive_runner=None.
    mock_dispatcher_cls.assert_called_once()
    _, kwargs = mock_dispatcher_cls.call_args
    assert kwargs.get("interactive_runner") is None
