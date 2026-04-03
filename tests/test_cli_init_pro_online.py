"""Tests for mallcop init --pro-online flag."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mallcop.cli import _setup_pro_online


class TestSetupProOnlineDirect:
    """Unit tests for _setup_pro_online() called directly."""

    def _make_config(self, **overrides) -> dict:
        """Build a config_data dict with all required fields."""
        config: dict = {
            "pro": {
                "service_token": "mallcop-sk-test123",
                "account_url": "https://mallcop.app/api/account",
            },
            "delivery": {
                "telegram_bot_token": "123456:ABC-DEF",
                "telegram_chat_id": "-100999",
                "campfire_id": "cf-abc123",
            },
        }
        for key, val in overrides.items():
            if "." in key:
                section, field = key.split(".", 1)
                config[section][field] = val
            else:
                config[key] = val
        return config

    def test_missing_service_token_returns_none(self):
        config = self._make_config()
        config["pro"]["service_token"] = ""
        result = _setup_pro_online(config)
        assert result is None

    def test_missing_telegram_bot_token_returns_none(self):
        config = self._make_config()
        config["delivery"]["telegram_bot_token"] = ""
        result = _setup_pro_online(config)
        assert result is None

    def test_missing_telegram_chat_id_returns_none(self):
        config = self._make_config()
        config["delivery"]["telegram_chat_id"] = ""
        result = _setup_pro_online(config)
        assert result is None

    def test_missing_campfire_id_returns_none(self):
        config = self._make_config()
        config["delivery"]["campfire_id"] = ""
        result = _setup_pro_online(config)
        assert result is None

    @patch("mallcop.cli.requests" if False else "requests.post")
    def test_success_updates_config_and_returns_result(self, mock_post):
        """With valid config, setWebhook + register both succeed."""
        # Mock both POST calls: Telegram setWebhook, then mallcop-pro register
        webhook_resp = MagicMock()
        webhook_resp.status_code = 200
        webhook_resp.raise_for_status = MagicMock()

        register_resp = MagicMock()
        register_resp.status_code = 200
        register_resp.raise_for_status = MagicMock()

        mock_post.side_effect = [webhook_resp, register_resp]

        config = self._make_config()
        result = _setup_pro_online(config)

        assert result is not None
        assert result["pro_online"] is True
        assert "webhook_url" in result
        assert "mallcop-sk-test123" in result["webhook_url"]

        # Config should be mutated
        assert config["delivery"]["pro_online"] is True
        assert config["delivery"]["telegram_webhook_url"] == result["webhook_url"]

        # Verify Telegram setWebhook was called correctly
        call_args = mock_post.call_args_list[0]
        assert "api.telegram.org" in call_args[0][0]
        assert "setWebhook" in call_args[0][0]

    @patch("requests.post")
    def test_register_404_is_non_fatal(self, mock_post):
        """When mallcop-pro register returns 404, config is still updated."""
        webhook_resp = MagicMock()
        webhook_resp.status_code = 200
        webhook_resp.raise_for_status = MagicMock()

        register_resp = MagicMock()
        register_resp.status_code = 404
        # raise_for_status would raise on 404, but we check status_code first
        register_resp.raise_for_status = MagicMock(
            side_effect=Exception("should not be called")
        )

        mock_post.side_effect = [webhook_resp, register_resp]

        config = self._make_config()
        result = _setup_pro_online(config)

        assert result is not None
        assert result["pro_online"] is True
        assert config["delivery"]["pro_online"] is True

    @patch("requests.post")
    def test_webhook_failure_returns_none(self, mock_post):
        """When Telegram setWebhook fails, return None."""
        webhook_resp = MagicMock()
        webhook_resp.status_code = 500
        webhook_resp.raise_for_status = MagicMock(
            side_effect=Exception("Internal Server Error")
        )

        mock_post.return_value = webhook_resp

        config = self._make_config()
        result = _setup_pro_online(config)

        assert result is None
        # Config should NOT be mutated
        assert "pro_online" not in config["delivery"]


class TestInitProOnlineFlag:
    """Integration tests for the --pro-online flag via Click runner."""

    def test_pro_online_without_pro_exits_1(self):
        """--pro-online without --pro raises SystemExit(1)."""
        from click.testing import CliRunner
        from mallcop.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["init", "--pro-online"])
        assert result.exit_code == 1
        assert "requires --pro" in (result.output + (result.stderr if hasattr(result, 'stderr') else ''))
