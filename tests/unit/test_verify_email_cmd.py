"""Tests for mallcop verify-email CLI command."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from mallcop.cli import cli


def _make_config(has_pro: bool = True):
    """Return a mock config with or without pro section."""
    config = MagicMock()
    if has_pro:
        config.pro.account_id = "acc_123"
        config.pro.service_token = "tok_abc"
        config.pro.account_url = "https://api.mallcop.dev"
    else:
        config.pro = None
    return config


class TestVerifyEmailCommand:
    """Tests for the verify-email subcommand."""

    def test_success_flow(self, tmp_path):
        """Valid OTP exits 0 with success message."""
        config = _make_config()
        runner = CliRunner()

        with patch("mallcop.cli.load_config", return_value=config), \
             patch("mallcop.pro.ProClient") as MockClient:
            client = MockClient.return_value
            client.verify_email_request.return_value = None
            client.verify_email_confirm.return_value = None

            result = runner.invoke(cli, ["verify-email", "--dir", str(tmp_path)], input="123456\n")

        assert result.exit_code == 0
        assert "Email verified. Escalation alerts are now active." in result.output
        client.verify_email_request.assert_called_once_with("acc_123", "tok_abc")
        client.verify_email_confirm.assert_called_once_with("acc_123", "123456", "tok_abc")

    def test_no_pro_config(self, tmp_path):
        """Missing pro config exits 1 with helpful message."""
        config = _make_config(has_pro=False)
        runner = CliRunner()

        with patch("mallcop.cli.load_config", return_value=config):
            result = runner.invoke(cli, ["verify-email", "--dir", str(tmp_path)])

        assert result.exit_code == 1
        assert "requires a Pro account" in result.output

    def test_invalid_otp(self, tmp_path):
        """Wrong OTP exits 1 with retry message."""
        config = _make_config()
        runner = CliRunner()

        with patch("mallcop.cli.load_config", return_value=config), \
             patch("mallcop.pro.ProClient") as MockClient:
            client = MockClient.return_value
            client.verify_email_request.return_value = None
            client.verify_email_confirm.side_effect = RuntimeError("invalid otp")

            result = runner.invoke(cli, ["verify-email", "--dir", str(tmp_path)], input="000000\n")

        assert result.exit_code == 1
        assert "Invalid or expired code" in result.output

    def test_request_failure(self, tmp_path):
        """Server error on request exits 1."""
        config = _make_config()
        runner = CliRunner()

        with patch("mallcop.cli.load_config", return_value=config), \
             patch("mallcop.pro.ProClient") as MockClient:
            client = MockClient.return_value
            client.verify_email_request.side_effect = RuntimeError("server error")

            result = runner.invoke(cli, ["verify-email", "--dir", str(tmp_path)])

        assert result.exit_code == 1
        assert "Failed to request verification" in result.output

    def test_appears_in_help(self):
        """verify-email appears in mallcop --help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert "verify-email" in result.output
