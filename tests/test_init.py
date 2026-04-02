"""Tests for mallcop init — campfire auto-creation and Telegram setup."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from click.testing import CliRunner

from mallcop.cli import cli


def _parse_init_output(output: str) -> dict:
    """Extract the status=ok JSON line from init command output.

    Init may emit a warning line before the final result (e.g. campfire
    creation failed). Find the line with status=ok.
    """
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("{"):
            parsed = json.loads(line)
            if parsed.get("status") == "ok":
                return parsed
    raise ValueError(f"No status=ok JSON line found in output: {output!r}")


class TestInitCampfire:
    def test_init_always_creates_campfire(self, tmp_path: Path) -> None:
        """init always calls cf create and stores the returned ID in config and output."""
        runner = CliRunner()

        fake_proc = MagicMock()
        fake_proc.stdout = "camp-abc123\n"
        fake_proc.returncode = 0

        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("subprocess.run", return_value=fake_proc) as mock_run:
                result = runner.invoke(cli, ["init"])

        assert result.exit_code == 0, result.output
        data = _parse_init_output(result.output)
        assert data["status"] == "ok"
        assert data["delivery"]["campfire_id"] == "camp-abc123"

        # Verify it was persisted to mallcop.yaml
        config_path = Path(data["config_path"])
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        assert cfg["delivery"]["campfire_id"] == "camp-abc123"

        # Verify cf was called with correct args
        call_args = mock_run.call_args
        cmd = call_args[0][0]
        assert cmd[0] == "cf"
        assert cmd[1] == "create"
        assert "--description" in cmd

    def test_init_campfire_graceful_failure(self, tmp_path: Path) -> None:
        """When cf raises an exception, init still succeeds (no campfire_id written)."""
        runner = CliRunner()

        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("subprocess.run", side_effect=FileNotFoundError("cf not found")):
                result = runner.invoke(cli, ["init"])

        assert result.exit_code == 0, result.output
        data = _parse_init_output(result.output)
        assert data["status"] == "ok"
        delivery = data.get("delivery", {})
        assert "campfire_id" not in delivery
        assert any("campfire" in w for w in data.get("warnings", []))

        config_path = Path(data["config_path"])
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        assert cfg.get("delivery", {}).get("campfire_id", "") == ""


class TestInitTelegram:
    def test_init_telegram_stores_token_and_chat_id(self, tmp_path: Path) -> None:
        """--telegram-bot-token stores the token value directly in config."""
        runner = CliRunner()
        raw_token = "bot12345:ABCDEF"
        raw_chat_id = "-100123456"

        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(
                cli,
                [
                    "init",
                    "--telegram-bot-token", raw_token,
                    "--telegram-chat-id", raw_chat_id,
                ],
            )

        assert result.exit_code == 0, result.output
        data = _parse_init_output(result.output)
        assert data["status"] == "ok"
        assert data["delivery"]["telegram_configured"] is True

        config_path = Path(data["config_path"])
        with open(config_path) as f:
            cfg = yaml.safe_load(f)

        assert cfg["delivery"]["telegram_bot_token"] == raw_token
        assert cfg["delivery"]["telegram_chat_id"] == raw_chat_id

    def test_init_telegram_token_only_no_chat_id(self, tmp_path: Path) -> None:
        """Token without chat ID: token stored, no chat_id entry."""
        runner = CliRunner()

        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(
                cli,
                ["init", "--telegram-bot-token", "bot99:TOKEN"],
            )

        assert result.exit_code == 0, result.output
        config_path = Path(_parse_init_output(result.output)["config_path"])
        with open(config_path) as f:
            cfg = yaml.safe_load(f)

        assert cfg["delivery"]["telegram_bot_token"] == "bot99:TOKEN"
        assert cfg["delivery"].get("telegram_chat_id", "") == ""

    def test_init_telegram_accepts_env_var(self, tmp_path: Path) -> None:
        """MALLCOP_TELEGRAM_BOT_TOKEN env var is accepted in lieu of --telegram-bot-token."""
        runner = CliRunner()

        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(
                cli,
                ["init"],
                env={"MALLCOP_TELEGRAM_BOT_TOKEN": "botENV:TOKEN"},
            )

        assert result.exit_code == 0, result.output
        data = _parse_init_output(result.output)
        assert data["delivery"]["telegram_configured"] is True


class TestInitCampfireTransport:
    def _fake_setup_github(self, config_data: dict, repo: str) -> dict:
        """Inject github section into config_data as _setup_github would."""
        config_data["github"] = {"repo": repo}
        return {"repo": repo}

    def test_github_transport_used_when_github_config_present(self, tmp_path: Path) -> None:
        """When config has github.repo (set by _setup_github), cf create uses --transport github."""
        runner = CliRunner()

        fake_proc = MagicMock()
        fake_proc.stdout = "camp-gh123\n"
        fake_proc.returncode = 0

        def inject_github(config_data: dict) -> dict:
            config_data["github"] = {"repo": "owner/repo"}
            return {"repo": "owner/repo"}

        def fake_setup_pro(config_data: dict) -> dict:
            config_data["pro"] = {
                "service_token": "mallcop-sk-test",
                "inference_url": "https://mallcop.app/api/inference",
                "account_url": "https://mallcop.app/api/account",
            }
            return {"inference_url": "https://mallcop.app/api/inference"}

        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("subprocess.run", return_value=fake_proc) as mock_run, \
                 patch("mallcop.cli._setup_github", side_effect=inject_github), \
                 patch("mallcop.cli._setup_pro", side_effect=fake_setup_pro):
                result = runner.invoke(cli, ["init", "--pro"])

        assert result.exit_code == 0, result.output
        data = _parse_init_output(result.output)
        assert data["status"] == "ok"
        assert data["delivery"]["campfire_id"] == "camp-gh123"

        # Verify cf was called with github transport flags
        call_args = mock_run.call_args
        cmd = call_args[0][0]
        assert "--transport" in cmd
        assert "github" in cmd
        assert "--github-repo" in cmd
        assert "owner/repo" in cmd
        assert "--github-token-env" in cmd
        assert "GITHUB_TOKEN" in cmd

        # Verify campfire_id is stored in config
        import yaml as _yaml
        config_path = Path(data["config_path"])
        with open(config_path) as f:
            cfg = _yaml.safe_load(f)
        assert cfg["delivery"]["campfire_id"] == "camp-gh123"

    def test_no_transport_flags_without_github_config(self, tmp_path: Path) -> None:
        """When config has no github section, cf create is called WITHOUT --transport flags."""
        runner = CliRunner()

        fake_proc = MagicMock()
        fake_proc.stdout = "camp-fs456\n"
        fake_proc.returncode = 0

        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("subprocess.run", return_value=fake_proc) as mock_run:
                result = runner.invoke(cli, ["init"])

        assert result.exit_code == 0, result.output
        data = _parse_init_output(result.output)
        assert data["status"] == "ok"
        assert data["delivery"]["campfire_id"] == "camp-fs456"

        # Verify cf was NOT called with transport flags
        call_args = mock_run.call_args
        cmd = call_args[0][0]
        assert "--transport" not in cmd
        assert "--github-repo" not in cmd
        assert "--github-token-env" not in cmd

        # Verify campfire_id is stored in config
        import yaml as _yaml
        config_path = Path(data["config_path"])
        with open(config_path) as f:
            cfg = _yaml.safe_load(f)
        assert cfg["delivery"]["campfire_id"] == "camp-fs456"
